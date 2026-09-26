//! Byte-range locks for the local backend. The registry is process-wide so
//! different shares of the same inode cannot grant conflicting locks. Other
//! backends must supply their own authority for cross-machine locking.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::backend::{RangeLock, RangeLockAction};
use crate::error::{SmbError, SmbResult};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct FileKey {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug)]
struct HeldLock {
    owner: u64,
    start: u64,
    end: u64,
    exclusive: bool,
}

#[derive(Clone, Debug)]
struct OpenRecord {
    owner: u64,
    desired: u32,
    share: u32,
}

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
static REGISTRY: OnceLock<Mutex<HashMap<FileKey, Vec<HeldLock>>>> = OnceLock::new();
static OPENS: OnceLock<Mutex<HashMap<FileKey, Vec<OpenRecord>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<FileKey, Vec<HeldLock>>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn open_registry() -> &'static Mutex<HashMap<FileKey, Vec<OpenRecord>>> {
    OPENS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn overlaps(start: u64, end: u64, held: &HeldLock) -> bool {
    start < held.end && held.start < end
}

/// A unique SMB CREATE handle owns its locks until CLOSE or disconnect drops
/// the handle. In-flight reads retain the owner while their blocking I/O runs.
pub(super) struct LockOwner {
    id: u64,
    key: FileKey,
}

impl LockOwner {
    pub(super) fn new(
        key: FileKey,
        read: bool,
        write: bool,
        delete: bool,
        share: u32,
    ) -> SmbResult<Self> {
        let desired = u32::from(read) | (u32::from(write) << 1) | (u32::from(delete) << 2);
        let id = NEXT_OWNER.fetch_add(1, Ordering::Relaxed);
        let mut opens = open_registry()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let records = opens.entry(key).or_default();
        if records
            .iter()
            .any(|record| desired & !record.share != 0 || record.desired & !share != 0)
        {
            return Err(SmbError::Sharing);
        }
        records.push(OpenRecord {
            owner: id,
            desired,
            share,
        });
        Ok(Self { id, key })
    }

    pub(super) fn apply(&self, operations: &[RangeLock]) -> SmbResult<()> {
        let mut table = registry()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut proposed = table.get(&self.key).cloned().unwrap_or_default();
        for operation in operations {
            let end = operation
                .offset
                .checked_add(operation.length)
                .ok_or(SmbError::NameInvalid)?;
            if operation.length == 0 {
                return Err(SmbError::NameInvalid);
            }
            match operation.action {
                RangeLockAction::Unlock => {
                    let Some(index) = proposed.iter().position(|held| {
                        held.owner == self.id && held.start == operation.offset && held.end == end
                    }) else {
                        return Err(SmbError::LockConflict);
                    };
                    proposed.remove(index);
                }
                RangeLockAction::Shared | RangeLockAction::Exclusive => {
                    let exclusive = operation.action == RangeLockAction::Exclusive;
                    if proposed.iter().any(|held| {
                        held.owner != self.id
                            && overlaps(operation.offset, end, held)
                            && (exclusive || held.exclusive)
                    }) {
                        return Err(SmbError::LockConflict);
                    }
                    proposed.push(HeldLock {
                        owner: self.id,
                        start: operation.offset,
                        end,
                        exclusive,
                    });
                }
            }
        }
        if proposed.is_empty() {
            table.remove(&self.key);
        } else {
            table.insert(self.key, proposed);
        }
        Ok(())
    }

    /// Keep the registry locked through I/O so a competing lock cannot be
    /// granted between the conflict check and the actual read or write.
    pub(super) fn with_access<T>(
        &self,
        offset: u64,
        length: u64,
        write: bool,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> SmbResult<T> {
        let end = offset.checked_add(length).ok_or(SmbError::NameInvalid)?;
        let table = registry()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if table.get(&self.key).is_some_and(|held| {
            held.iter().any(|held| {
                held.owner != self.id && overlaps(offset, end, held) && (write || held.exclusive)
            })
        }) {
            return Err(SmbError::LockConflict);
        }
        operation().map_err(SmbError::Io)
    }
}

impl Drop for LockOwner {
    fn drop(&mut self) {
        let mut table = registry()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(held) = table.get_mut(&self.key) {
            held.retain(|lock| lock.owner != self.id);
            if held.is_empty() {
                table.remove(&self.key);
            }
        }
        drop(table);
        let mut opens = open_registry()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(records) = opens.get_mut(&self.key) {
            records.retain(|record| record.owner != self.id);
            if records.is_empty() {
                opens.remove(&self.key);
            }
        }
    }
}

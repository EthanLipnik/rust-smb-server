//! Local byte-range locks and SMB share modes. Each inode has its own
//! read/write guard: nonconflicting I/O can run concurrently, while granting
//! a lock waits for in-flight I/O to finish its conflict check and operation.
//! Other backends need their own authority for cross-machine coordination.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

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

#[derive(Default)]
struct FileState {
    locks: Vec<HeldLock>,
    opens: Vec<OpenRecord>,
}

type SharedState = Arc<RwLock<FileState>>;
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
static REGISTRY: OnceLock<Mutex<HashMap<FileKey, Weak<RwLock<FileState>>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<FileKey, Weak<RwLock<FileState>>>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn state_for(key: FileKey) -> SharedState {
    let mut registry = registry()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let Some(state) = registry.get(&key).and_then(Weak::upgrade) {
        return state;
    }
    let state = Arc::new(RwLock::new(FileState::default()));
    registry.insert(key, Arc::downgrade(&state));
    state
}

fn overlaps(start: u64, end: u64, held: &HeldLock) -> bool {
    start < held.end && held.start < end
}

/// A unique SMB CREATE handle owns its locks and share mode until CLOSE or
/// disconnect drops the handle. Blocking I/O holds a clone of this owner.
pub(super) struct LockOwner {
    id: u64,
    key: FileKey,
    state: SharedState,
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
        let state = state_for(key);
        {
            let mut guard = state.write().unwrap_or_else(|poison| poison.into_inner());
            if guard
                .opens
                .iter()
                .any(|record| desired & !record.share != 0 || record.desired & !share != 0)
            {
                return Err(SmbError::Sharing);
            }
            guard.opens.push(OpenRecord {
                owner: id,
                desired,
                share,
            });
        }
        Ok(Self { id, key, state })
    }

    pub(super) fn apply(&self, operations: &[RangeLock]) -> SmbResult<()> {
        let mut guard = self
            .state
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut proposed = guard.locks.clone();
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
                        return Err(SmbError::LockNotGranted);
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
                        return Err(SmbError::LockNotGranted);
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
        guard.locks = proposed;
        Ok(())
    }

    pub(super) fn with_access<T>(
        &self,
        offset: u64,
        length: u64,
        write: bool,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> SmbResult<T> {
        let end = offset.checked_add(length).ok_or(SmbError::NameInvalid)?;
        let guard = self
            .state
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        if guard.locks.iter().any(|held| {
            held.owner != self.id && overlaps(offset, end, held) && (write || held.exclusive)
        }) {
            return Err(SmbError::LockConflict);
        }
        operation().map_err(SmbError::Io)
    }
}

impl Drop for LockOwner {
    fn drop(&mut self) {
        {
            let mut guard = self
                .state
                .write()
                .unwrap_or_else(|poison| poison.into_inner());
            guard.locks.retain(|lock| lock.owner != self.id);
            guard.opens.retain(|record| record.owner != self.id);
        }
        let mut registry = registry()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if Arc::strong_count(&self.state) == 1 {
            registry.remove(&self.key);
        }
    }
}

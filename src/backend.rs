//! `ShareBackend` and `Handle` traits — the storage abstraction.
//!
//! Implementors of these traits plug into `Share::new(name, backend)`. The
//! protocol layer never exposes raw FS types to backends; everything goes
//! through validated `SmbPath`s and the small structs below.

use async_trait::async_trait;
use std::time::SystemTime;

use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

// ---------------------------------------------------------------------------
// OpenOptions
// ---------------------------------------------------------------------------

/// Translated SMB CREATE intent — the small set of cases v1 cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenIntent {
    /// `FILE_OPEN` — open existing only; fail if missing.
    Open,
    /// `FILE_CREATE` — create new only; fail if exists.
    Create,
    /// `FILE_OPEN_IF` — open existing or create new.
    OpenOrCreate,
    /// `FILE_OVERWRITE_IF` — open existing (truncating) or create new.
    OverwriteOrCreate,
    /// `FILE_OVERWRITE` — open existing and truncate; fail if missing.
    Truncate,
}

/// Options passed to `ShareBackend::open`. v1 keeps this tight on purpose;
/// extra knobs become methods later if a backend genuinely needs them.
#[derive(Debug, Clone, Copy)]
pub struct OpenOptions {
    /// Read access requested.
    pub read: bool,
    /// Write access requested.
    pub write: bool,
    /// Delete access requested.
    pub delete: bool,
    /// FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE bitmask.
    pub share_access: u32,
    /// CREATE disposition.
    pub intent: OpenIntent,
    /// `FILE_DIRECTORY_FILE` was set on CREATE — open or create a directory.
    pub directory: bool,
    /// `FILE_NON_DIRECTORY_FILE` was set on CREATE — fail if the target is a directory.
    pub non_directory: bool,
    /// `FILE_DELETE_ON_CLOSE` was set on CREATE.
    pub delete_on_close: bool,
}

/// One byte-range operation in an SMB LOCK request. Backends apply all
/// operations in a request atomically or leave the previous state intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeLock {
    pub offset: u64,
    pub length: u64,
    pub action: RangeLockAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeLockAction {
    Shared,
    Exclusive,
    Unlock,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            read: true,
            write: false,
            delete: false,
            share_access: 0x7,
            intent: OpenIntent::Open,
            directory: false,
            non_directory: false,
            delete_on_close: false,
        }
    }
}

// ---------------------------------------------------------------------------
// FileInfo / DirEntry / FileTimes
// ---------------------------------------------------------------------------

/// Filesystem-style metadata for a single file or directory.
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// Display name (last component). For QUERY_INFO at the share root this
    /// is the share name.
    pub name: String,
    /// File size in bytes.
    pub end_of_file: u64,
    /// Allocation size — typically `end_of_file` rounded up to a cluster size.
    /// v1 backends may safely return the same value as `end_of_file`.
    pub allocation_size: u64,
    /// FILETIME (100ns ticks since 1601).
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    /// True if this is a directory.
    pub is_directory: bool,
    /// Optional 64-bit unique file id (for `FileInternalInformation`). v1 may
    /// return `0` if unavailable; the dispatcher will substitute the FileId.
    pub file_index: u64,
}

impl FileInfo {
    /// SMB2 file attributes (MS-FSCC §2.6) for this file. v1 returns
    /// `FILE_ATTRIBUTE_DIRECTORY` for dirs, `FILE_ATTRIBUTE_NORMAL` (0x80) for
    /// regular files. (`FILE_ATTRIBUTE_NORMAL` MUST be the only attribute set
    /// when used.)
    pub fn attributes(&self) -> u32 {
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
        if self.is_directory {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        }
    }
}

/// One entry of a directory listing.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub info: FileInfo,
}

/// One named alternate data stream on a file. The name excludes `:$DATA`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamInfo {
    pub name: String,
    pub size: u64,
    pub allocation_size: u64,
}

/// Filesystem capacity presented to clients as 4 KiB allocation units.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub label: String,
}

/// FILE_NOTIFY_INFORMATION event relative to the watched directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEvent {
    /// SMB FILE_ACTION_ADDED (1), REMOVED (2), MODIFIED (3),
    /// RENAMED_OLD_NAME (4), or RENAMED_NEW_NAME (5).
    pub action: u32,
    pub file_name: String,
}

/// Optional FILETIME values for `set_times`. `None` means "leave unchanged".
#[derive(Debug, Clone, Copy, Default)]
pub struct FileTimes {
    pub creation_time: Option<u64>,
    pub last_access_time: Option<u64>,
    pub last_write_time: Option<u64>,
    pub change_time: Option<u64>,
}

impl FileTimes {
    /// Convenience: convert `SystemTime` into a `FileTimes` setting all four
    /// fields to the same instant.
    pub fn all(t: SystemTime) -> Self {
        let ft = crate::utils::system_time_to_filetime(t);
        Self {
            creation_time: Some(ft),
            last_access_time: Some(ft),
            last_write_time: Some(ft),
            change_time: Some(ft),
        }
    }
}

// ---------------------------------------------------------------------------
// BackendCapabilities
// ---------------------------------------------------------------------------

/// Static, advertised capabilities of a backend.
///
/// Kept small intentionally — extending requires discussing with the maintainer.
#[derive(Debug, Clone, Copy, Default)]
pub struct BackendCapabilities {
    /// If true, all write-class operations are denied at the protocol layer
    /// before reaching the backend (matches `LocalFsBackend::read_only()`).
    pub is_read_only: bool,
    /// True iff the backend treats names case-sensitively.
    pub case_sensitive: bool,
    /// Named `:$DATA` streams can be opened, listed, and removed.
    pub supports_named_streams: bool,
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Pluggable storage backend mounted as a share.
///
/// Implementors must be `Send + Sync + 'static` so the server can spawn
/// per-request handlers freely.
#[async_trait]
pub trait ShareBackend: Send + Sync + 'static {
    /// Open or create a file or directory. Returns a fresh handle.
    async fn open(&self, path: &SmbPath, opts: OpenOptions) -> SmbResult<Box<dyn Handle>>;

    /// Unlink (delete) a file. Directories: must be empty. v1 does not
    /// recursively delete.
    async fn unlink(&self, path: &SmbPath) -> SmbResult<()>;

    /// Rename atomically. When replacement is false, reject an existing target.
    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()>;

    /// Open a named alternate data stream belonging to `path`.
    async fn open_stream(
        &self,
        _path: &SmbPath,
        _name: &str,
        _opts: OpenOptions,
    ) -> SmbResult<Box<dyn Handle>> {
        Err(SmbError::NotSupported)
    }

    /// Enumerate named streams. An empty list means only the default stream exists.
    async fn list_streams(&self, _path: &SmbPath) -> SmbResult<Vec<StreamInfo>> {
        Err(SmbError::NotSupported)
    }

    /// Remove a named stream without removing its owning file.
    async fn unlink_stream(&self, _path: &SmbPath, _name: &str) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }

    /// Wait for changes under a directory. `file_name` values in the result
    /// are relative to `path` and use backslash separators.
    async fn watch_changes(
        &self,
        _path: &SmbPath,
        _watch_tree: bool,
        _completion_filter: u32,
    ) -> SmbResult<Vec<ChangeEvent>> {
        Err(SmbError::NotSupported)
    }

    /// Backends with a real storage pool override the generic test volume.
    async fn volume_info(&self) -> SmbResult<VolumeInfo> {
        Ok(VolumeInfo {
            total_bytes: 1u64 << 52,
            available_bytes: 1u64 << 51,
            label: "smb-server".to_owned(),
        })
    }

    /// Static capabilities. The dispatcher consults these at TREE_CONNECT and
    /// uses `is_read_only` to clamp authz.
    fn capabilities(&self) -> BackendCapabilities;
}

/// A live open file or directory handle.
///
/// One handle per `CREATE`. The handle is dropped when CLOSE arrives or the
/// session goes away.
#[async_trait]
pub trait Handle: Send + Sync {
    /// Set or clear delete-pending on this open. Implementations coordinate
    /// all opens of the same file and delete after the final close. A backend
    /// without that authority must reject the request.
    async fn set_delete_on_close(&self, _delete: bool) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }
    /// Unsupported backends fail closed so the server never acknowledges
    /// byte-range protection it cannot enforce.
    async fn lock_ranges(&self, _operations: &[RangeLock]) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }
    /// Read up to `len` bytes at `offset`. May return fewer.
    async fn read(&self, offset: u64, len: u32) -> SmbResult<bytes::Bytes>;

    /// Write `data` at `offset`. Returns bytes written.
    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32>;

    /// Write owned `data` at `offset`. Backends that need ownership across a
    /// blocking boundary can override this to avoid an extra copy.
    async fn write_owned(&self, offset: u64, data: Vec<u8>) -> SmbResult<u32> {
        self.write(offset, &data).await
    }

    /// Flush buffered writes. May be a no-op on backends that always flush.
    async fn flush(&self) -> SmbResult<()>;

    /// Stat: current file info.
    async fn stat(&self) -> SmbResult<FileInfo>;

    /// Set timestamps. `None` fields leave the corresponding field alone.
    async fn set_times(&self, times: FileTimes) -> SmbResult<()>;

    /// Truncate (or extend) to `len` bytes. For directories: the protocol
    /// layer rejects this before reaching the backend.
    async fn truncate(&self, len: u64) -> SmbResult<()>;

    /// List directory entries matching the optional pattern. v1 ignores
    /// `pattern` if the backend doesn't implement matching — the dispatcher
    /// post-filters as needed for QUERY_DIRECTORY.
    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>>;

    /// Close the handle. Boxed self lets implementors consume internal state.
    async fn close(self: Box<Self>) -> SmbResult<()>;
}

/// No-op backend used for the synthetic IPC$ share. Every method returns
/// [`SmbError::NotSupported`]. Exists so we can hand a `ShareBackend`
/// implementor to the IPC$ tree without any real storage attached.
pub(crate) struct NotSupportedBackend;

#[async_trait]
impl ShareBackend for NotSupportedBackend {
    async fn open(&self, _path: &SmbPath, _opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
        Err(SmbError::NotSupported)
    }
    async fn unlink(&self, _path: &SmbPath) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }
    async fn rename(
        &self,
        _from: &SmbPath,
        _to: &SmbPath,
        _replace_if_exists: bool,
    ) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            is_read_only: true,
            case_sensitive: false,
            supports_named_streams: false,
        }
    }
}

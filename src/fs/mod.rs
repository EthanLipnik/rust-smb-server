//! Local-filesystem [`ShareBackend`] for `smb-server`, sandboxed via `cap-std`.

mod local;
mod locks;

pub use local::LocalFsBackend;

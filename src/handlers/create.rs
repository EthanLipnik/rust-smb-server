//! CREATE handler — open or create a file/directory and allocate a FileId.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{CreateContext, CreateRequest, CreateResponse};
use tracing::{debug, warn};

use crate::backend::{OpenIntent, OpenOptions};
use crate::builder::Access;
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session_tree;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::server::ServerState;
use crate::utils::utf16le_to_units;

// MS-SMB2 §2.2.13 access mask flags
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAX_ALLOWED: u32 = 0x0200_0000;

// CreateOptions
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

// CreateDisposition
const FILE_SUPERSEDE: u32 = 0x0000_0000;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_OPEN_IF: u32 = 0x0000_0003;
const FILE_OVERWRITE: u32 = 0x0000_0004;
const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

// CreateAction in response (MS-SMB2 §2.2.14)
const FILE_OPENED: u32 = 0x0000_0001;
const FILE_CREATED: u32 = 0x0000_0002;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match CreateRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    if req.share_access & !0x7 != 0 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let tree = tree_arc.read().await;
    let granted = tree.granted_access;
    let backend = tree.share.backend.clone();
    drop(tree);

    let contexts = match CreateContext::parse_chain(&req.create_contexts) {
        Ok(contexts) => contexts,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let mut response_contexts = Vec::new();
    for context in contexts {
        if context.name == b"AAPL" {
            if context.data.len() != 24
                || u32::from_le_bytes(context.data[0..4].try_into().unwrap()) != 1
            {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            }
            let requested = u64::from_le_bytes(context.data[8..16].try_into().unwrap());
            let supported = requested & 0x7;
            let mut data = Vec::new();
            data.extend_from_slice(&1u32.to_le_bytes()); // SERVER_QUERY
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&supported.to_le_bytes());
            if supported & 1 != 0 {
                data.extend_from_slice(&0u64.to_le_bytes()); // no enhanced directory attributes
            }
            if supported & 2 != 0 {
                let case_sensitive = if backend.capabilities().case_sensitive {
                    2u64
                } else {
                    0
                };
                data.extend_from_slice(&case_sensitive.to_le_bytes());
            }
            if supported & 4 != 0 {
                let model: Vec<u8> = "Mirage".encode_utf16().flat_map(u16::to_le_bytes).collect();
                data.extend_from_slice(&0u32.to_le_bytes());
                data.extend_from_slice(&(model.len() as u32).to_le_bytes());
                data.extend_from_slice(&model);
            }
            response_contexts.push(CreateContext {
                name: b"AAPL".to_vec(),
                data,
            });
        }
    }

    // Decode path.
    let units = match utf16le_to_units(&req.name) {
        Some(u) => u,
        None => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };
    let (path, stream_name) = match SmbPath::from_utf16_with_stream(&units) {
        Ok(p) => p,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };

    // Translate disposition.
    let intent = match req.create_disposition {
        FILE_SUPERSEDE | FILE_OVERWRITE_IF => OpenIntent::OverwriteOrCreate,
        FILE_OPEN => OpenIntent::Open,
        FILE_CREATE => OpenIntent::Create,
        FILE_OPEN_IF => OpenIntent::OpenOrCreate,
        FILE_OVERWRITE => OpenIntent::Truncate,
        _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    // Translate desired access into read/write hints.
    let want_read = req.desired_access
        & (FILE_READ_DATA | FILE_READ_ATTRIBUTES | GENERIC_READ | GENERIC_ALL | MAX_ALLOWED)
        != 0;
    let want_write = req.desired_access
        & (FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_ATTRIBUTES
            | GENERIC_WRITE
            | GENERIC_ALL
            | MAX_ALLOWED)
        != 0;
    let want_delete = req.desired_access & (DELETE | GENERIC_ALL | MAX_ALLOWED) != 0;

    // Reject writes on a read-only tree.
    if (want_write || want_delete) && !granted.allows_write() {
        warn!(path = %path, "write open on read-only tree");
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    // Disposition that creates: requires write permission.
    if !granted.allows_write()
        && matches!(
            intent,
            OpenIntent::Create
                | OpenIntent::OpenOrCreate
                | OpenIntent::OverwriteOrCreate
                | OpenIntent::Truncate
        )
    {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }

    let directory = req.create_options & FILE_DIRECTORY_FILE != 0;
    let non_directory = req.create_options & FILE_NON_DIRECTORY_FILE != 0;
    if directory && non_directory {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if stream_name.is_some() && directory {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let delete_on_close = req.create_options & FILE_DELETE_ON_CLOSE != 0;
    if delete_on_close && !want_delete {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }

    let opts = OpenOptions {
        read: want_read || (!want_write && !want_delete),
        write: want_write,
        delete: want_delete,
        share_access: req.share_access,
        intent,
        directory,
        non_directory,
        delete_on_close,
    };

    let open_result = match &stream_name {
        Some(name) => backend.open_stream(&path, name, opts).await,
        None => backend.open(&path, opts).await,
    };
    let handle = match open_result {
        Ok(h) => h,
        Err(e) => {
            debug!(error = %e, path = %path, "backend open failed");
            return HandlerResponse::err(e.to_nt_status());
        }
    };
    if delete_on_close {
        if let Err(e) = handle.set_delete_on_close(true).await {
            let _ = handle.close().await;
            return HandlerResponse::err(e.to_nt_status());
        }
    }

    // Stat for the response.
    let info = match handle.stat().await {
        Ok(i) => i,
        Err(e) => {
            let _ = handle.close().await;
            return HandlerResponse::err(e.to_nt_status());
        }
    };

    // Allocate FileId, register Open.
    let tree = tree_arc.write().await;
    let file_id = tree.alloc_file_id();
    let open = Open::new(
        file_id,
        handle,
        if want_write || want_delete {
            granted
        } else {
            Access::Read
        },
        path,
        stream_name,
        want_delete,
        info.is_directory,
        delete_on_close,
    );
    let open_arc = Arc::new(tokio::sync::RwLock::new(open));
    tree.opens.write().await.insert(file_id, open_arc);
    drop(tree);

    let create_action = match intent {
        OpenIntent::Create => FILE_CREATED,
        OpenIntent::OpenOrCreate | OpenIntent::OverwriteOrCreate => FILE_OPENED,
        OpenIntent::Open | OpenIntent::Truncate => FILE_OPENED,
    };
    let mut context_bytes = Vec::new();
    CreateContext::encode_chain(&response_contexts, &mut context_bytes).expect("encode contexts");
    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: 0,
        flags: 0,
        create_action,
        creation_time: info.creation_time,
        last_access_time: info.last_access_time,
        last_write_time: info.last_write_time,
        change_time: info.change_time,
        allocation_size: info.allocation_size,
        end_of_file: info.end_of_file,
        file_attributes: info.attributes(),
        reserved2: 0,
        file_id,
        create_contexts_offset: if context_bytes.is_empty() { 0 } else { 152 },
        create_contexts_length: context_bytes.len() as u32,
        create_contexts: context_bytes,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

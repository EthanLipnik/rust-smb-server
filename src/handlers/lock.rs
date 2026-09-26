//! LOCK handler. Unsupported backends reject locks instead of acknowledging
//! protection they cannot provide.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{LockElement, LockRequest, LockResponse};

use crate::backend::{RangeLock, RangeLockAction};
use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::ntstatus;
use crate::server::ServerState;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match LockRequest::parse(body) {
        Ok(req) if req.structure_size == 48 && !req.locks.is_empty() => req,
        _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let mut operations = Vec::with_capacity(req.locks.len());
    for element in &req.locks {
        if element.length == 0
            || element.offset.checked_add(element.length).is_none()
            || element.reserved != 0
        {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        let action = match element.flags {
            flags
                if flags
                    == (LockElement::FLAG_SHARED_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY) =>
            {
                RangeLockAction::Shared
            }
            flags
                if flags
                    == (LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY) =>
            {
                RangeLockAction::Exclusive
            }
            LockElement::FLAG_UNLOCK => RangeLockAction::Unlock,
            // A blocking lock needs an asynchronous waiter; acknowledging or
            // silently converting it to a try-lock would violate the request.
            flags
                if flags == LockElement::FLAG_SHARED_LOCK
                    || flags == LockElement::FLAG_EXCLUSIVE_LOCK =>
            {
                return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
            }
            _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
        };
        operations.push(RangeLock {
            offset: element.offset,
            length: element.length,
            action,
        });
    }

    let tree = match lookup_session_tree(conn, hdr).await {
        Ok(tree) => tree,
        Err(status) => return HandlerResponse::err(status),
    };
    let open = match lookup_open(&tree, req.file_id).await {
        Some(open) => open,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    let open = open.read().await;
    let Some(handle) = open.handle.as_ref() else {
        return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
    };
    if let Err(error) = handle.lock_ranges(&operations).await {
        return HandlerResponse::err(error.to_nt_status());
    }
    let mut buf = Vec::new();
    LockResponse::default().write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

//! CHANGE_NOTIFY waits for a backend event while the connection reader stays live.

use std::sync::Arc;
use std::time::Duration;

use crate::proto::header::Smb2Header;
use crate::proto::messages::change_notify::encode_change_events;
use crate::proto::messages::{ChangeNotifyRequest, ChangeNotifyResponse};

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
    let req = match ChangeNotifyRequest::parse(body) {
        Ok(req) if req.structure_size == 32 && req.reserved == 0 => req,
        _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let tree = match lookup_session_tree(conn, hdr).await {
        Ok(tree) => tree,
        Err(status) => return HandlerResponse::err(status),
    };
    let open = match lookup_open(&tree, req.file_id).await {
        Some(open) => open,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    let path = {
        let open = open.read().await;
        if !open.is_directory {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        open.last_path.clone()
    };
    let backend = tree.read().await.share.backend.clone();
    let watch_tree = req.flags & ChangeNotifyRequest::FLAG_WATCH_TREE != 0;
    let events = match tokio::time::timeout(
        Duration::from_secs(25),
        backend.watch_changes(&path, watch_tree, req.completion_filter),
    )
    .await
    {
        Ok(Ok(events)) => events,
        Ok(Err(error)) => return HandlerResponse::err(error.to_nt_status()),
        Err(_) => Vec::new(),
    };
    if events
        .iter()
        .any(|event| !(1..=5).contains(&event.action) || event.file_name.is_empty())
    {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let buffer = encode_change_events(&events);
    if buffer.len() > req.output_buffer_length as usize {
        return HandlerResponse::err(ntstatus::STATUS_NOTIFY_ENUM_DIR);
    }
    let response = ChangeNotifyResponse {
        structure_size: 9,
        output_buffer_offset: if buffer.is_empty() { 0 } else { 72 },
        output_buffer_length: buffer.len() as u32,
        buffer,
    };
    let mut out = Vec::new();
    response.write_to(&mut out).expect("encode");
    HandlerResponse::ok(out)
}

//! Per-connection frame reader: pulls bytes off the socket, frames them,
//! hands each frame to the dispatcher.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use crate::proto::framing::{FRAME_HEADER_LEN, decode_frame_header};
use tokio::io::{AsyncReadExt, ReadHalf};
use tokio::net::TcpStream;
use tracing::{debug, error};

use crate::conn::state::Connection;
use crate::proto::header::{Command, Smb2Header};
use crate::server::ServerState;

/// Read one frame's payload (without the 4-byte length prefix).
///
/// Returns `Ok(None)` on a clean EOF, `Ok(Some(bytes))` on a complete frame,
/// `Err` on partial/garbled data.
pub async fn read_one_frame(reader: &mut ReadHalf<TcpStream>) -> io::Result<Option<Vec<u8>>> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    match reader.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = match decode_frame_header(&hdr) {
        Ok(n) => n,
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
        }
    };
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

/// Continuously read frames; for each, await `dispatch_one`'s response and
/// route it to the writer.
///
/// CHANGE_NOTIFY waits run separately so the connection can receive CANCEL
/// and ordinary file operations while a directory watch is pending.
pub async fn reader_task(
    mut reader: ReadHalf<TcpStream>,
    server: Arc<ServerState>,
    conn: Arc<Connection>,
    tx: tokio::sync::mpsc::Sender<crate::conn::writer::FramePayload>,
) -> io::Result<()> {
    let mut notifications: HashMap<u64, tokio::task::JoinHandle<()>> = HashMap::new();
    let result = loop {
        let frame = match read_one_frame(&mut reader).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                debug!("client closed connection");
                break Ok(());
            }
            Err(e) => {
                error!(error = %e, "frame read error");
                break Err(e);
            }
        };
        // Check shutdown after every frame.
        if server
            .shutting_down
            .load(std::sync::atomic::Ordering::Acquire)
        {
            debug!("server shutting down; dropping connection");
            break Ok(());
        }
        notifications.retain(|_, task| !task.is_finished());
        let header = Smb2Header::parse(&frame).ok().map(|(header, _)| header);
        if let Some(header) = &header {
            if header.command == Command::ChangeNotify && header.next_command == 0 {
                let server = server.clone();
                let conn = conn.clone();
                let tx = tx.clone();
                let message_id = header.message_id;
                let task = tokio::spawn(async move {
                    if let Some(bytes) =
                        crate::dispatch::dispatch_frame(&server, &conn, &frame).await
                    {
                        let _ = tx.send(bytes).await;
                    }
                });
                if let Some(old) = notifications.insert(message_id, task) {
                    old.abort();
                }
                continue;
            }
        }
        // The dispatcher is async but we await it inline — order-preserving and
        // preserves preauthentication ordering for ordinary commands.
        let response = crate::dispatch::dispatch_frame(&server, &conn, &frame).await;
        if let Some(header) = &header {
            if header.command == Command::Cancel && response.is_none() {
                if let Some(task) = notifications.remove(&header.message_id) {
                    task.abort();
                }
            }
        }
        if let Some(bytes) = response
            && tx.send(bytes).await.is_err()
        {
            debug!("writer channel closed; reader exiting");
            break Ok(());
        }
    };
    for task in notifications.into_values() {
        task.abort();
    }
    result
}

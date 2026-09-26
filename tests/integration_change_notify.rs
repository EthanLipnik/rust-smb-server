//! A pending directory watch must leave the SMB connection usable and cancellable.

mod common;

use async_trait::async_trait;
use common::{
    anonymous_session_setup, build_header, negotiate, parse_response_header, read_frame,
    tree_connect, write_frame,
};
use smb_server::wire::header::Command;
use smb_server::wire::messages::{
    CancelRequest, ChangeNotifyRequest, CreateRequest, CreateResponse, EchoRequest,
};
use smb_server::{
    BackendCapabilities, ChangeEvent, Handle, LocalFsBackend, OpenOptions, Share, ShareBackend,
    SmbPath, SmbResult, SmbServer,
};
use tempfile::tempdir;
use tokio::net::TcpStream;

struct WaitingBackend(LocalFsBackend);

#[async_trait]
impl ShareBackend for WaitingBackend {
    async fn open(&self, path: &SmbPath, options: OpenOptions) -> SmbResult<Box<dyn Handle>> {
        self.0.open(path, options).await
    }
    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.0.unlink(path).await
    }
    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
        self.0.rename(from, to, replace).await
    }
    async fn watch_changes(
        &self,
        _path: &SmbPath,
        _watch_tree: bool,
        _filter: u32,
    ) -> SmbResult<Vec<ChangeEvent>> {
        std::future::pending().await
    }
    fn capabilities(&self) -> BackendCapabilities {
        self.0.capabilities()
    }
}

#[tokio::test]
async fn pending_notify_does_not_block_echo_and_cancel() {
    let td = tempdir().unwrap();
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "password")
        .share(
            Share::new(
                "share",
                WaitingBackend(LocalFsBackend::new(td.path()).unwrap()),
            )
            .public(),
        )
        .netbios_name("TESTSERVER")
        .build()
        .unwrap();
    server.bind().await.unwrap();
    let address = server.local_addr().await.unwrap();
    let task = tokio::spawn(async move { server.serve().await });
    let mut socket = TcpStream::connect(address).await.unwrap();
    negotiate(&mut socket).await;
    let session = anonymous_session_setup(&mut socket).await;
    let tree = tree_connect(&mut socket, "\\\\127.0.0.1\\share", session, 3).await;

    let request = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 7,
        create_disposition: 1,
        create_options: 1,
        name_offset: 120,
        name_length: 0,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: vec![],
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    request.write_to(&mut body).unwrap();
    write_frame(
        &mut socket,
        &build_header(Command::Create, 4, session, tree),
        &body,
    )
    .await;
    let response = read_frame(&mut socket).await;
    let (header, body) = parse_response_header(&response);
    assert_eq!(header.channel_sequence_status, 0);
    let opened = CreateResponse::parse(body).unwrap();

    let watch = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: opened.file_id,
        completion_filter: 0x17f,
        reserved: 0,
    };
    let mut body = Vec::new();
    watch.write_to(&mut body).unwrap();
    write_frame(
        &mut socket,
        &build_header(Command::ChangeNotify, 5, session, tree),
        &body,
    )
    .await;

    let mut body = Vec::new();
    EchoRequest::default().write_to(&mut body).unwrap();
    write_frame(
        &mut socket,
        &build_header(Command::Echo, 6, session, tree),
        &body,
    )
    .await;
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), read_frame(&mut socket))
        .await
        .unwrap();
    let (header, _) = parse_response_header(&response);
    assert_eq!(header.command, Command::Echo);
    assert_eq!(header.channel_sequence_status, 0);

    let mut body = Vec::new();
    CancelRequest::default().write_to(&mut body).unwrap();
    write_frame(
        &mut socket,
        &build_header(Command::Cancel, 5, session, tree),
        &body,
    )
    .await;
    let mut body = Vec::new();
    EchoRequest::default().write_to(&mut body).unwrap();
    write_frame(
        &mut socket,
        &build_header(Command::Echo, 7, session, tree),
        &body,
    )
    .await;
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), read_frame(&mut socket))
        .await
        .unwrap();
    let (header, _) = parse_response_header(&response);
    assert_eq!(header.command, Command::Echo);
    task.abort();
}

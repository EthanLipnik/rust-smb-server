//! Wire-level Apple CREATE context and named-stream fail-closed behavior.

mod common;

use common::{
    anonymous_session_setup, build_header, negotiate, parse_response_header, read_frame,
    tree_connect, utf16le, write_frame,
};
use smb_server::wire::header::Command;
use smb_server::wire::messages::{CreateContext, CreateRequest, CreateResponse};
use smb_server::{LocalFsBackend, Share, SmbServer};
use tempfile::tempdir;
use tokio::net::TcpStream;

fn create(name: &str, context: Option<CreateContext>) -> Vec<u8> {
    let name = utf16le(name);
    let mut contexts = Vec::new();
    if let Some(context) = context {
        CreateContext::encode_chain(&[context], &mut contexts).unwrap();
    }
    let context_offset = if contexts.is_empty() {
        0
    } else {
        (64 + (56 + name.len() + 7 & !7)) as u32
    };
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
        create_options: 0,
        name_offset: 120,
        name_length: name.len() as u16,
        create_contexts_offset: context_offset,
        create_contexts_length: contexts.len() as u32,
        name,
        create_contexts: contexts,
    };
    let mut body = Vec::new();
    request.write_to(&mut body).unwrap();
    if context_offset != 0 {
        let pad = context_offset as usize - 64 - 56 - request.name.len();
        body.splice(
            56 + request.name.len()..56 + request.name.len(),
            vec![0; pad],
        );
    }
    body
}

#[tokio::test]
async fn aapl_context_round_trip_and_unsupported_stream_is_not_name_invalid() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("file"), b"data").unwrap();
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "password")
        .share(Share::new("share", LocalFsBackend::new(td.path()).unwrap()).public())
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

    let mut aapl = vec![0u8; 24];
    aapl[0..4].copy_from_slice(&1u32.to_le_bytes());
    aapl[8..16].copy_from_slice(&7u64.to_le_bytes());
    let context = CreateContext {
        name: b"AAPL".to_vec(),
        data: aapl,
    };
    write_frame(
        &mut socket,
        &build_header(Command::Create, 4, session, tree),
        &create("file", Some(context)),
    )
    .await;
    let response = read_frame(&mut socket).await;
    let (header, body) = parse_response_header(&response);
    assert_eq!(header.channel_sequence_status, 0);
    let opened = CreateResponse::parse(body).unwrap();
    assert_eq!(opened.create_contexts_offset, 152);
    let contexts = CreateContext::parse_chain(&opened.create_contexts).unwrap();
    assert_eq!(contexts[0].name, b"AAPL");
    assert_eq!(
        u64::from_le_bytes(contexts[0].data[8..16].try_into().unwrap()),
        7
    );

    write_frame(
        &mut socket,
        &build_header(Command::Create, 5, session, tree),
        &create("file:AFP_Resource:$DATA", None),
    )
    .await;
    let response = read_frame(&mut socket).await;
    let (header, _) = parse_response_header(&response);
    assert_eq!(
        header.channel_sequence_status,
        smb_server::ntstatus::STATUS_NOT_SUPPORTED
    );

    // The local backend has no delete-pending authority; CREATE must fail
    // before acknowledging FILE_DELETE_ON_CLOSE.
    let mut body = create("file", None);
    body[24..28].copy_from_slice(&(0x0012_0089u32 | 0x0001_0000).to_le_bytes());
    body[40..44].copy_from_slice(&0x0000_1000u32.to_le_bytes());
    write_frame(
        &mut socket,
        &build_header(Command::Create, 6, session, tree),
        &body,
    )
    .await;
    let response = read_frame(&mut socket).await;
    let (header, _) = parse_response_header(&response);
    assert_eq!(
        header.channel_sequence_status,
        smb_server::ntstatus::STATUS_NOT_SUPPORTED
    );
    assert_eq!(std::fs::read(td.path().join("file")).unwrap(), b"data");
    task.abort();
}

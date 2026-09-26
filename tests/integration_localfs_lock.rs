mod common;

use common::{
    STATUS_SUCCESS, anonymous_session_setup, build_header, negotiate, parse_response_header,
    read_frame, tree_connect, utf16le, write_frame,
};
use smb_server::LocalFsBackend;
use smb_server::wire::header::Command;
use smb_server::wire::messages::{
    CloseRequest, CreateRequest, CreateResponse, FileId, LockElement, LockRequest, ReadRequest,
    ReadResponse, WriteRequest,
};
use smb_server::{Share, SmbServer};
use tempfile::tempdir;
use tokio::net::TcpStream;

async fn open_file(
    stream: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    share_access: u32,
) -> Result<FileId, u32> {
    open_with_disposition(stream, session_id, tree_id, message_id, share_access, 1).await
}

async fn open_with_disposition(
    stream: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    share_access: u32,
    create_disposition: u32,
) -> Result<FileId, u32> {
    let name = utf16le("shared.bin");
    let request = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0xC000_0000,
        file_attributes: 0,
        share_access,
        create_disposition,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    request.write_to(&mut body).unwrap();
    write_frame(
        stream,
        &build_header(Command::Create, message_id, session_id, tree_id),
        &body,
    )
    .await;
    let response = read_frame(stream).await;
    let (header, body) = parse_response_header(&response);
    if header.channel_sequence_status != STATUS_SUCCESS {
        return Err(header.channel_sequence_status);
    }
    Ok(CreateResponse::parse(body).unwrap().file_id)
}

async fn lock_file(
    stream: &mut TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    file_id: FileId,
) -> u32 {
    let request = LockRequest {
        structure_size: 48,
        lock_count: 1,
        lock_sequence: 0,
        file_id,
        locks: vec![LockElement {
            offset: 0,
            length: 128,
            flags: LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
            reserved: 0,
        }],
    };
    let mut body = Vec::new();
    request.write_to(&mut body).unwrap();
    write_frame(
        stream,
        &build_header(Command::Lock, message_id, session_id, tree_id),
        &body,
    )
    .await;
    let response = read_frame(stream).await;
    parse_response_header(&response).0.channel_sequence_status
}

#[tokio::test]
async fn exclusive_ranges_conflict_and_close_releases_them() {
    let root = tempdir().unwrap();
    std::fs::write(root.path().join("shared.bin"), [0; 256]).unwrap();
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "password")
        .share(Share::new("share", LocalFsBackend::new(root.path()).unwrap()).public())
        .build()
        .unwrap();
    server.bind().await.unwrap();
    let address = server.local_addr().await.unwrap();
    let task = tokio::spawn(async move { server.serve().await });
    let mut stream = TcpStream::connect(address).await.unwrap();
    negotiate(&mut stream).await;
    let session_id = anonymous_session_setup(&mut stream).await;
    let tree_id = tree_connect(&mut stream, "\\\\127.0.0.1\\share", session_id, 3).await;
    let first = open_file(&mut stream, session_id, tree_id, 4, 7)
        .await
        .unwrap();
    let second = open_file(&mut stream, session_id, tree_id, 5, 7)
        .await
        .unwrap();

    assert_eq!(
        lock_file(&mut stream, session_id, tree_id, 6, first).await,
        STATUS_SUCCESS
    );
    assert_eq!(
        lock_file(&mut stream, session_id, tree_id, 7, second).await,
        0xC000_0055,
        "SMB must never acknowledge a conflicting byte-range lock"
    );

    let read = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 16,
        offset: 0,
        file_id: second,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    read.write_to(&mut body).unwrap();
    write_frame(
        &mut stream,
        &build_header(Command::Read, 8, session_id, tree_id),
        &body,
    )
    .await;
    assert_eq!(
        parse_response_header(&read_frame(&mut stream).await)
            .0
            .channel_sequence_status,
        0xC000_0054,
        "a conflicting lock must also block reads"
    );

    let write = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: 1,
        offset: 0,
        file_id: second,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: vec![7],
    };
    let mut body = Vec::new();
    write.write_to(&mut body).unwrap();
    write_frame(
        &mut stream,
        &build_header(Command::Write, 9, session_id, tree_id),
        &body,
    )
    .await;
    assert_eq!(
        parse_response_header(&read_frame(&mut stream).await)
            .0
            .channel_sequence_status,
        0xC000_0054,
        "a conflicting lock must also block writes"
    );

    let mut body = Vec::new();
    CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: first,
    }
    .write_to(&mut body)
    .unwrap();
    write_frame(
        &mut stream,
        &build_header(Command::Close, 10, session_id, tree_id),
        &body,
    )
    .await;
    assert_eq!(
        parse_response_header(&read_frame(&mut stream).await)
            .0
            .channel_sequence_status,
        STATUS_SUCCESS
    );
    assert_eq!(
        lock_file(&mut stream, session_id, tree_id, 11, second).await,
        STATUS_SUCCESS
    );
    task.abort();
}

#[tokio::test]
async fn exclusive_share_access_rejects_a_second_open() {
    let root = tempdir().unwrap();
    std::fs::write(root.path().join("shared.bin"), [0; 256]).unwrap();
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "password")
        .share(Share::new("share", LocalFsBackend::new(root.path()).unwrap()).public())
        .build()
        .unwrap();
    server.bind().await.unwrap();
    let address = server.local_addr().await.unwrap();
    let task = tokio::spawn(async move { server.serve().await });
    let mut stream = TcpStream::connect(address).await.unwrap();
    negotiate(&mut stream).await;
    let session_id = anonymous_session_setup(&mut stream).await;
    let tree_id = tree_connect(&mut stream, "\\\\127.0.0.1\\share", session_id, 3).await;
    let first = open_file(&mut stream, session_id, tree_id, 4, 0)
        .await
        .unwrap();
    assert_eq!(
        open_with_disposition(&mut stream, session_id, tree_id, 5, 7, 5).await,
        Err(0xC000_0043),
        "SMB CREATE must honor FILE_SHARE_* denial"
    );
    assert_eq!(
        std::fs::metadata(root.path().join("shared.bin"))
            .unwrap()
            .len(),
        256,
        "a rejected overwrite must leave the original bytes intact"
    );

    let mut body = Vec::new();
    CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: first,
    }
    .write_to(&mut body)
    .unwrap();
    write_frame(
        &mut stream,
        &build_header(Command::Close, 6, session_id, tree_id),
        &body,
    )
    .await;
    assert_eq!(
        parse_response_header(&read_frame(&mut stream).await)
            .0
            .channel_sequence_status,
        STATUS_SUCCESS
    );
    assert!(
        open_file(&mut stream, session_id, tree_id, 7, 7)
            .await
            .is_ok()
    );
    task.abort();
}

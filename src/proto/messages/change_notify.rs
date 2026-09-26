//! CHANGE_NOTIFY Request/Response (MS-SMB2 §2.2.35 / §2.2.36).
//!
//! V1 returns `STATUS_NOT_SUPPORTED`, but we still parse/encode the wire
//! form so the dispatcher can recognize it.

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::ProtoResult;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotifyRequest {
    pub structure_size: u16,
    pub flags: u16,
    pub output_buffer_length: u32,
    pub file_id: FileId,
    pub completion_filter: u32,
    pub reserved: u32,
}

impl ChangeNotifyRequest {
    /// Flag: SMB2_WATCH_TREE.
    pub const FLAG_WATCH_TREE: u16 = 0x0001;

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        Ok(Self::read(&mut Cursor::new(buf))?)
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotifyResponse {
    pub structure_size: u16,
    pub output_buffer_offset: u16,
    pub output_buffer_length: u32,
    #[br(count = output_buffer_length as usize)]
    pub buffer: Vec<u8>,
}

impl ChangeNotifyResponse {
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        Ok(Self::read(&mut Cursor::new(buf))?)
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

/// Encode FILE_NOTIFY_INFORMATION records with four-byte next-entry alignment.
pub fn encode_change_events(events: &[crate::backend::ChangeEvent]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let name: Vec<u8> = event
            .file_name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let size = 12 + name.len();
        let aligned = (size + 3) & !3;
        let next = if index + 1 == events.len() {
            0
        } else {
            aligned as u32
        };
        out.extend_from_slice(&next.to_le_bytes());
        out.extend_from_slice(&event.action.to_le_bytes());
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(&name);
        if next != 0 {
            out.resize(out.len() + aligned - size, 0);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = ChangeNotifyRequest {
            structure_size: 32,
            flags: ChangeNotifyRequest::FLAG_WATCH_TREE,
            output_buffer_length: 0x1000,
            file_id: FileId::new(1, 2),
            completion_filter: 0xFF,
            reserved: 0,
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(ChangeNotifyRequest::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_round_trips() {
        let r = ChangeNotifyResponse {
            structure_size: 9,
            output_buffer_offset: 0x48,
            output_buffer_length: 0,
            buffer: vec![],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(ChangeNotifyResponse::parse(&buf).unwrap(), r);
    }

    #[test]
    fn event_chain_uses_relative_unicode_names_and_aligned_offsets() {
        let events = [
            crate::backend::ChangeEvent {
                action: 1,
                file_name: "新.txt".into(),
            },
            crate::backend::ChangeEvent {
                action: 3,
                file_name: "other".into(),
            },
        ];
        let bytes = encode_change_events(&events);
        let next = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        assert_eq!(next % 4, 0);
        assert_eq!(
            u32::from_le_bytes(bytes[next..next + 4].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(bytes[next + 4..next + 8].try_into().unwrap()),
            3
        );
    }
}

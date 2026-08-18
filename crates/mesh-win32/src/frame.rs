#![allow(clippy::missing_errors_doc)]

use std::io::{self, Read, Write};

use crate::{NativeError, NativeErrorCode, NativeOperation};

pub const REQUEST_FRAME_LIMIT: usize = 1024 * 1024;
pub const RESPONSE_FRAME_LIMIT: usize = 8 * 1024 * 1024;
pub const FRAME_HEADER_LENGTH: usize = 4;

/// Validate a little-endian frame header before allocating its payload.
pub fn decode_frame_length(
    header: [u8; FRAME_HEADER_LENGTH],
    limit: usize,
) -> Result<usize, NativeError> {
    let encoded = u32::from_le_bytes(header);
    let length = usize::try_from(encoded).map_err(|_| {
        NativeError::new(NativeErrorCode::FrameTooLarge, NativeOperation::ReadFrame)
    })?;
    if length == 0 {
        return Err(NativeError::new(
            NativeErrorCode::FrameInvalid,
            NativeOperation::ReadFrame,
        ));
    }
    if length > limit {
        return Err(NativeError::new(
            NativeErrorCode::FrameTooLarge,
            NativeOperation::ReadFrame,
        ));
    }
    Ok(length)
}

/// Encode one bounded frame. The payload is copied exactly once.
pub fn encode_frame(payload: &[u8], limit: usize) -> Result<Vec<u8>, NativeError> {
    if payload.is_empty() {
        return Err(NativeError::new(
            NativeErrorCode::FrameInvalid,
            NativeOperation::WriteFrame,
        ));
    }
    if payload.len() > limit || payload.len() > u32::MAX as usize {
        return Err(NativeError::new(
            NativeErrorCode::FrameTooLarge,
            NativeOperation::WriteFrame,
        ));
    }
    let encoded_length = u32::try_from(payload.len()).map_err(|_| {
        NativeError::new(NativeErrorCode::FrameTooLarge, NativeOperation::WriteFrame)
    })?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LENGTH + payload.len());
    frame.extend_from_slice(&encoded_length.to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Read one complete frame from a blocking stream.
pub fn read_frame(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, NativeError> {
    let mut header = [0_u8; FRAME_HEADER_LENGTH];
    read_exact(reader, &mut header, NativeOperation::ReadFrame)?;
    let length = decode_frame_length(header, limit)?;
    let mut payload = vec![0_u8; length];
    read_exact(reader, &mut payload, NativeOperation::ReadFrame)?;
    Ok(payload)
}

/// Write one complete frame to a blocking stream.
pub fn write_frame(
    writer: &mut impl Write,
    payload: &[u8],
    limit: usize,
) -> Result<(), NativeError> {
    let frame = encode_frame(payload, limit)?;
    writer
        .write_all(&frame)
        .map_err(|error| io_native_error(&error, NativeOperation::WriteFrame))
}

pub fn decode_utf8(payload: Vec<u8>, operation: NativeOperation) -> Result<String, NativeError> {
    String::from_utf8(payload)
        .map_err(|_| NativeError::new(NativeErrorCode::FrameInvalid, operation))
}

fn read_exact(
    reader: &mut impl Read,
    buffer: &mut [u8],
    operation: NativeOperation,
) -> Result<(), NativeError> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            NativeError::new(NativeErrorCode::ConnectionClosed, operation)
        } else {
            io_native_error(&error, operation)
        }
    })
}

fn io_native_error(error: &io::Error, operation: NativeOperation) -> NativeError {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .map_or_else(
            || NativeError::new(NativeErrorCode::OsFailure, operation),
            |code| NativeError::with_os_code(NativeErrorCode::OsFailure, operation, code),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct ChunkedReader {
        bytes: Cursor<Vec<u8>>,
        chunk: usize,
    }

    impl Read for ChunkedReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let available = output.len().min(self.chunk);
            self.bytes.read(&mut output[..available])
        }
    }

    #[test]
    fn accepts_split_and_coalesced_frames() {
        let first = encode_frame(b"one", REQUEST_FRAME_LIMIT).expect("first");
        let second = encode_frame(b"two", REQUEST_FRAME_LIMIT).expect("second");
        let bytes = [first, second].concat();
        for chunk in 1..=bytes.len() {
            let mut reader = ChunkedReader {
                bytes: Cursor::new(bytes.clone()),
                chunk,
            };
            assert_eq!(
                read_frame(&mut reader, REQUEST_FRAME_LIMIT).expect("one"),
                b"one"
            );
            assert_eq!(
                read_frame(&mut reader, REQUEST_FRAME_LIMIT).expect("two"),
                b"two"
            );
        }
    }

    #[test]
    fn rejects_zero_and_oversized_lengths_before_payload_read() {
        assert_eq!(
            decode_frame_length(0_u32.to_le_bytes(), REQUEST_FRAME_LIMIT)
                .expect_err("zero")
                .code(),
            NativeErrorCode::FrameInvalid
        );
        assert_eq!(
            decode_frame_length(u32::MAX.to_le_bytes(), REQUEST_FRAME_LIMIT)
                .expect_err("oversized")
                .code(),
            NativeErrorCode::FrameTooLarge
        );
    }

    #[test]
    fn enforces_exact_request_boundary_and_utf8() {
        let exact = vec![b'x'; REQUEST_FRAME_LIMIT];
        assert!(encode_frame(&exact, REQUEST_FRAME_LIMIT).is_ok());
        assert_eq!(
            encode_frame(&vec![b'x'; REQUEST_FRAME_LIMIT + 1], REQUEST_FRAME_LIMIT)
                .expect_err("too large")
                .code(),
            NativeErrorCode::FrameTooLarge
        );
        assert_eq!(
            decode_utf8(vec![0xff], NativeOperation::ReadFrame)
                .expect_err("invalid utf8")
                .code(),
            NativeErrorCode::FrameInvalid
        );
    }

    #[test]
    fn consumes_shared_frame_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../protocol/v1/frame-vectors.json"))
                .expect("shared frame vectors");
        let vectors = vectors.as_array().expect("vector array");

        let zero = &vectors[0];
        assert_eq!(zero["name"], "zero-length");
        assert_eq!(
            decode_frame_length(hex_prefix(&zero["prefix_hex"]), REQUEST_FRAME_LIMIT)
                .expect_err("zero-length vector")
                .code(),
            NativeErrorCode::FrameInvalid
        );

        let invalid_utf8 = &vectors[1];
        let payload = data_encoding::HEXLOWER
            .decode(
                invalid_utf8["payload_hex"]
                    .as_str()
                    .expect("payload hex")
                    .as_bytes(),
            )
            .expect("decode payload");
        assert_eq!(
            decode_frame_length(hex_prefix(&invalid_utf8["prefix_hex"]), REQUEST_FRAME_LIMIT)
                .expect("declared invalid UTF-8 length"),
            payload.len()
        );
        assert_eq!(
            decode_utf8(payload, NativeOperation::ReadFrame)
                .expect_err("invalid UTF-8 vector")
                .code(),
            NativeErrorCode::FrameInvalid
        );

        assert_eq!(
            decode_frame_length(
                u32::try_from(vectors[2]["declared_length"].as_u64().expect("limit"))
                    .expect("u32 limit")
                    .to_le_bytes(),
                REQUEST_FRAME_LIMIT,
            )
            .expect("request limit vector"),
            REQUEST_FRAME_LIMIT
        );
        assert_eq!(
            decode_frame_length(
                u32::try_from(
                    vectors[3]["declared_length"]
                        .as_u64()
                        .expect("limit plus one"),
                )
                .expect("u32 limit plus one")
                .to_le_bytes(),
                REQUEST_FRAME_LIMIT,
            )
            .expect_err("request limit plus one vector")
            .code(),
            NativeErrorCode::FrameTooLarge
        );
        assert_eq!(
            decode_frame_length(hex_prefix(&vectors[4]["prefix_hex"]), REQUEST_FRAME_LIMIT)
                .expect_err("u32 maximum vector")
                .code(),
            NativeErrorCode::FrameTooLarge
        );
    }

    fn hex_prefix(value: &serde_json::Value) -> [u8; FRAME_HEADER_LENGTH] {
        data_encoding::HEXLOWER
            .decode(value.as_str().expect("prefix hex").as_bytes())
            .expect("decode prefix")
            .try_into()
            .expect("four byte prefix")
    }
}

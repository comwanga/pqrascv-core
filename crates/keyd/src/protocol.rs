//! keyd wire protocol: length-prefixed CBOR messages over Unix domain socket.
//!
//! Frame format: [u32 little-endian length][CBOR payload]
//! Request:  CBOR struct { request_type: u8, label: String, payload: Vec<u8> }
//! Response: CBOR struct { status: u8, payload: Vec<u8> }

use serde::{Deserialize, Serialize};

#[cfg(test)]
#[repr(u8)]
#[allow(dead_code)] // documents the protocol request bytes; tests construct a subset
pub enum RequestType {
    GenerateKeypair = 1,
    ExportPublicKey = 2,
    Sign = 3,
    Rotate = 4,
    Delete = 5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub request_type: u8,
    pub label: String,
    pub payload: Vec<u8>,
}

#[repr(u8)]
pub enum StatusCode {
    Ok = 0,
    NotFound = 1,
    AlreadyExists = 2,
    SigningError = 3,
    InternalError = 4,
    /// Authorization denied by policy (default-deny or missing per-key grant).
    ///
    /// Additive: existing clients that only test `status == 0` for success are
    /// unaffected; a denied request simply reports a non-zero status as before.
    Denied = 5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub status: u8,
    pub payload: Vec<u8>,
}

#[cfg(test)]
pub fn encode_request(req: &Request) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut body = Vec::new();
    ciborium::into_writer(req, &mut body)?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn encode_response(resp: &Response) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut body = Vec::new();
    ciborium::into_writer(resp, &mut body)?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_encode_decode_roundtrip() {
        let req = Request {
            request_type: RequestType::Sign as u8,
            label: "my-key".to_string(),
            payload: b"data-to-sign".to_vec(),
        };
        let frame = encode_request(&req).unwrap();
        let len = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
        let decoded: Request = ciborium::from_reader(&frame[4..4 + len]).unwrap();
        assert_eq!(decoded.label, req.label);
        assert_eq!(decoded.payload, req.payload);
    }

    #[test]
    fn response_ok_has_status_zero() {
        let resp = Response {
            status: StatusCode::Ok as u8,
            payload: vec![0x42],
        };
        let frame = encode_response(&resp).unwrap();
        let len = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
        let decoded: Response = ciborium::from_reader(&frame[4..4 + len]).unwrap();
        assert_eq!(decoded.status, 0);
    }
}

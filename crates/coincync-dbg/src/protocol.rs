//! Debug Adapter Protocol wire framing.
//!
//! DAP messages are JSON bodies prefixed with an HTTP-style `Content-Length`
//! header, the same framing LSP uses:
//!
//! ```text
//! Content-Length: 119\r\n
//! \r\n
//! {"seq":1,"type":"request","command":"initialize", ...}
//! ```
//!
//! We keep messages as `serde_json::Value` rather than typed structs — the
//! adapter only touches a handful of fields, and `Value` keeps the surface tiny
//! and the dependency set to just serde_json.

use serde_json::Value;
use std::io::{BufRead, Write};

/// Read one DAP message. Returns `Ok(None)` on clean EOF (peer disconnected).
pub fn read_message<R: BufRead>(reader: &mut R) -> std::io::Result<Option<Value>> {
    let mut content_length: Option<usize> = None;

    // Headers, terminated by a blank line.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None); // EOF before any header → clean shutdown.
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // end of headers
        }
        if let Some(value) = trimmed.strip_prefix("Content-Length:") {
            content_length = value.trim().parse().ok();
        }
        // Other headers (e.g. Content-Type) are ignored per spec.
    }

    let len = match content_length {
        Some(len) => len,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DAP message missing Content-Length header",
            ))
        }
    };

    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(value))
}

/// Write one DAP message with its `Content-Length` header, then flush.
pub fn write_message<W: Write>(writer: &mut W, msg: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(msg)?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(&body)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    #[test]
    fn roundtrip_frames_a_message() {
        let msg = json!({"seq": 7, "type": "request", "command": "initialize"});
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).unwrap();
        // Header present and length correct.
        let text = String::from_utf8(buf.clone()).unwrap();
        assert!(text.starts_with("Content-Length: "));
        let mut cur = Cursor::new(buf);
        let back = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn clean_eof_is_none() {
        let mut cur = Cursor::new(Vec::new());
        assert!(read_message(&mut cur).unwrap().is_none());
    }
}

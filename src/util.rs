//! Shared primitives: error type, bounds-checked byte reader/writer, varints.
//!
//! Everything that parses untrusted network input goes through `Reader`, which never
//! panics: short input yields `Error::Eof`.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Eof,
    Invalid(&'static str),
    Limit(&'static str),
    Auth(String),
    Io(String),
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Eof => write!(f, "unexpected end of data"),
            Error::Invalid(m) => write!(f, "invalid data: {m}"),
            Error::Limit(m) => write!(f, "limit exceeded: {m}"),
            Error::Auth(m) => write!(f, "authentication failed: {m}"),
            Error::Io(m) => write!(f, "i/o error: {m}"),
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Wrap any `Debug` error (WASI error codes, etc.) as `Error::Io`.
pub fn io_err<E: fmt::Debug>(e: E) -> Error {
    Error::Io(format!("{e:?}"))
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Eof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16_be(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u24_le(&mut self) -> Result<u32> {
        let b = self.take(3)?;
        Ok(u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16))
    }

    pub fn u32_be(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i32_be(&mut self) -> Result<i32> {
        Ok(self.u32_be()? as i32)
    }

    pub fn i32_le(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i64_be(&mut self) -> Result<i64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(i64::from_be_bytes(a))
    }

    /// LEB128 unsigned varint (Bedrock `varuint32`, Java `VarInt` bit pattern).
    pub fn var_u32(&mut self) -> Result<u32> {
        let mut v: u32 = 0;
        for i in 0..5 {
            let b = self.u8()?;
            v |= u32::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(Error::Invalid("varint too long"))
    }

    /// Varint-length-prefixed UTF-8 string with an explicit byte limit.
    pub fn string_var(&mut self, max_bytes: usize) -> Result<String> {
        let len = self.var_u32()? as usize;
        if len > max_bytes {
            return Err(Error::Limit("string too long"));
        }
        let b = self.take(len)?;
        String::from_utf8(b.to_vec()).map_err(|_| Error::Invalid("string is not utf-8"))
    }
}

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }

    pub fn u16_be(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u16_le(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u24_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes()[..3]);
    }

    pub fn u32_be(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn i32_be(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn i64_be(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn f32_le(&mut self, v: f32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    pub fn var_u32(&mut self, mut v: u32) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            self.buf.push(b);
            if v == 0 {
                break;
            }
        }
    }

    pub fn string_var(&mut self, s: &str) {
        self.var_u32(s.len() as u32);
        self.bytes(s.as_bytes());
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Cryptographically secure random bytes from `wasi:random/random`.
pub fn random_bytes(n: usize) -> Vec<u8> {
    wasi::random::random::get_random_bytes(n as u64)
}

pub fn random_i64() -> i64 {
    let b = random_bytes(8);
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    i64::from_le_bytes(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u32, 1, 127, 128, 300, 2_097_151, u32::MAX] {
            let mut w = Writer::new();
            w.var_u32(v);
            let bytes = w.finish();
            assert_eq!(Reader::new(&bytes).var_u32().unwrap(), v);
        }
    }

    #[test]
    fn reader_never_panics_on_short_input() {
        assert!(Reader::new(&[]).u16_be().is_err());
        assert!(Reader::new(&[0x80]).var_u32().is_err());
        assert!(Reader::new(&[0xff; 6]).var_u32().is_err());
    }
}

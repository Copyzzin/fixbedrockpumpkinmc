//! Bedrock batch codec: `[encrypt]( [algorithm byte] compress( (varuint len, packet)* ) )`.
//!
//! Before `NetworkSettings` is exchanged a batch is just the concatenated packets; afterwards each
//! batch carries a one-byte algorithm id (0 = raw deflate, 0xFF = stored). We only advertise zlib.

use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::decompress_to_vec_with_limit;

use super::crypto::Cipher;
use crate::util::{Error, Reader, Result, Writer};

const MAX_PACKETS_PER_BATCH: usize = 512;

pub struct BatchCodec {
    compression: Option<usize>,
    pub cipher: Option<Cipher>,
    max_decompressed: usize,
}

impl BatchCodec {
    pub fn new(max_decompressed: usize) -> Self {
        Self { compression: None, cipher: None, max_decompressed }
    }

    /// Enable compression with the threshold announced in `NetworkSettings`.
    pub fn enable_compression(&mut self, threshold: usize) {
        self.compression = Some(threshold);
    }

    /// Split an incoming batch (bytes after 0xFE) into packets (`header + body` each).
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let decrypted;
        let mut data = data;
        if let Some(c) = self.cipher.as_mut() {
            decrypted = c.decrypt(data)?;
            data = &decrypted;
        }
        let inflated;
        if self.compression.is_some() {
            let (&algo, rest) = data.split_first().ok_or(Error::Eof)?;
            match algo {
                0x00 => {
                    inflated = decompress_to_vec_with_limit(rest, self.max_decompressed)
                        .map_err(|_| Error::Invalid("deflate stream"))?;
                    data = &inflated;
                }
                0xff => {
                    if rest.len() > self.max_decompressed {
                        return Err(Error::Limit("batch size"));
                    }
                    data = rest;
                }
                _ => return Err(Error::Invalid("unsupported compression algorithm")),
            }
        } else if data.len() > self.max_decompressed {
            return Err(Error::Limit("batch size"));
        }

        let mut r = Reader::new(data);
        let mut packets = Vec::new();
        while r.remaining() > 0 {
            if packets.len() >= MAX_PACKETS_PER_BATCH {
                return Err(Error::Limit("packets per batch"));
            }
            let len = r.var_u32()? as usize;
            packets.push(r.take(len)?.to_vec());
        }
        Ok(packets)
    }

    /// Frame packets (`header + body` each) into one batch payload (without the 0xFE marker).
    pub fn encode(&mut self, packets: &[Vec<u8>]) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        for p in packets {
            w.var_u32(p.len() as u32);
            w.bytes(p);
        }
        let mut body = w.finish();

        if let Some(threshold) = self.compression {
            let mut out = Vec::with_capacity(body.len() + 1);
            if body.len() >= threshold {
                out.push(0x00);
                out.extend_from_slice(&compress_to_vec(&body, 6));
            } else {
                out.push(0xff);
                out.append(&mut body);
            }
            body = out;
        }
        if let Some(c) = self.cipher.as_mut() {
            body = c.encrypt(&body);
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_compressed_roundtrip() {
        let packets = vec![vec![1u8, 2, 3], vec![9u8; 2000], vec![]];
        let mut sender = BatchCodec::new(1 << 20);
        let mut receiver = BatchCodec::new(1 << 20);

        let b = sender.encode(&packets).unwrap();
        assert_eq!(receiver.decode(&b).unwrap(), packets);

        sender.enable_compression(256);
        receiver.enable_compression(256);
        let b = sender.encode(&packets).unwrap();
        assert_eq!(b[0], 0x00); // large batch -> deflate
        assert_eq!(receiver.decode(&b).unwrap(), packets);

        let small = vec![vec![7u8; 10]];
        let b = sender.encode(&small).unwrap();
        assert_eq!(b[0], 0xff); // below threshold -> stored
        assert_eq!(receiver.decode(&b).unwrap(), small);
    }

    #[test]
    fn decompression_bomb_is_rejected() {
        let mut sender = BatchCodec::new(1 << 24);
        sender.enable_compression(0);
        let b = sender.encode(&[vec![0u8; 1 << 20]]).unwrap();
        let mut receiver = BatchCodec::new(64 * 1024);
        receiver.enable_compression(0);
        assert!(receiver.decode(&b).is_err());
    }
}

//! Bedrock network encryption.
//!
//! Handshake: the server generates an ephemeral P-384 key, sends a `ServerToClientHandshake`
//! containing an ES384 JWT (header `x5u` = server public key, payload `salt`), and both sides derive
//! `key = SHA-256(salt || ECDH shared secret)`.
//! Transport: AES-256-CTR (IV = key[0..12] || 00 00 00 02), one continuous keystream per direction,
//! and every packet carries an 8-byte checksum `SHA-256(counter_le64 || plaintext || key)[..8]`.
//!
//! CONFIDENCE: the construction above follows the publicly documented Bedrock scheme, but it has not
//! been exercised against a real client from this environment. Test with a vanilla client before use.

use aes::Aes256;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ctr::cipher::{KeyIvInit, StreamCipher};
use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey};
use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
use p384::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::util::{Error, Result, random_bytes};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub struct Cipher {
    key: [u8; 32],
    enc: Aes256Ctr,
    dec: Aes256Ctr,
    send_counter: u64,
    recv_counter: u64,
}

impl Cipher {
    fn new(key: [u8; 32]) -> Result<Self> {
        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(&key[..12]);
        iv[15] = 2;
        let make = || Aes256Ctr::new_from_slices(&key, &iv).map_err(|_| Error::Invalid("cipher key length"));
        Ok(Self { enc: make()?, dec: make()?, key, send_counter: 0, recv_counter: 0 })
    }

    fn checksum(&self, counter: u64, payload: &[u8]) -> [u8; 8] {
        let mut h = Sha256::new();
        h.update(counter.to_le_bytes());
        h.update(payload);
        h.update(self.key);
        let d = h.finalize();
        let mut out = [0u8; 8];
        out.copy_from_slice(&d[..8]);
        out
    }

    pub fn encrypt(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(payload.len() + 8);
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&self.checksum(self.send_counter, payload));
        self.send_counter += 1;
        self.enc.apply_keystream(&mut buf);
        buf
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 8 {
            return Err(Error::Invalid("encrypted packet too short"));
        }
        let mut buf = data.to_vec();
        self.dec.apply_keystream(&mut buf);
        let split = buf.len() - 8;
        let expected = self.checksum(self.recv_counter, &buf[..split]);
        // Constant-time comparison of the 8 checksum bytes.
        let diff = expected.iter().zip(&buf[split..]).fold(0u8, |a, (x, y)| a | (x ^ y));
        if diff != 0 {
            return Err(Error::Auth("packet checksum mismatch".into()));
        }
        self.recv_counter += 1;
        buf.truncate(split);
        Ok(buf)
    }
}

fn generate_secret() -> Result<SecretKey> {
    for _ in 0..8 {
        if let Ok(k) = SecretKey::from_slice(&random_bytes(48)) {
            return Ok(k);
        }
    }
    Err(Error::Invalid("could not generate an ephemeral key"))
}

/// Start the encryption handshake for a client whose (already verified) public key is `client_key_b64`
/// (base64 DER SPKI). Returns the handshake JWT to send and the cipher to enable *after* sending it.
pub fn start_handshake(client_key_b64: &str) -> Result<(String, Cipher)> {
    let der = STANDARD
        .decode(client_key_b64.trim())
        .map_err(|_| Error::Invalid("client key base64"))?;
    let client_pub =
        PublicKey::from_public_key_der(&der).map_err(|_| Error::Invalid("client public key"))?;

    let secret = generate_secret()?;
    let server_der = secret
        .public_key()
        .to_public_key_der()
        .map_err(|_| Error::Invalid("server public key encoding"))?;
    let server_b64 = STANDARD.encode(server_der.as_bytes());

    let salt = random_bytes(16);
    let shared = p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), client_pub.as_affine());
    let mut h = Sha256::new();
    h.update(&salt);
    h.update(shared.raw_secret_bytes());
    let key: [u8; 32] = h.finalize().into();

    let header = format!(r#"{{"alg":"ES384","x5u":"{server_b64}"}}"#);
    let payload = format!(r#"{{"salt":"{}"}}"#, STANDARD.encode(&salt));
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signer = SigningKey::from(secret.clone());
    let sig: Signature = signer.sign(signing_input.as_bytes());
    let jwt = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));

    Ok((jwt, Cipher::new(key)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_roundtrip_and_tamper_detection() {
        let key = [7u8; 32];
        let mut a = Cipher::new(key).unwrap();
        let mut b = Cipher::new(key).unwrap();
        let ct = a.encrypt(b"hello bedrock");
        assert_eq!(b.decrypt(&ct).unwrap(), b"hello bedrock");

        let mut ct2 = a.encrypt(b"second packet");
        ct2[0] ^= 1;
        assert!(b.decrypt(&ct2).is_err());
    }
}

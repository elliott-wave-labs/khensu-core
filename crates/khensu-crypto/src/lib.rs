// SPDX-License-Identifier: Apache-2.0
//! Primitives for khensu.nu (PROTOCOL.md section 1).
//!
//! Every hash, KDF and signature is domain-separated with [`label`].

pub mod kem;
pub mod sig;
pub mod sym;

pub use kem::{KemCiphertext, KemKeyPair, KemPublicKey};
pub use sig::{SigKeyPair, SigPublicKey, Signature};

/// Errors from primitive operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("random number generator failed")]
    Rng,
    #[error("invalid length")]
    Length,
    #[error("invalid public key")]
    PublicKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("signing failed")]
    Signing,
    #[error("decryption failed")]
    Decrypt,
}

pub type Result<T> = core::result::Result<T, Error>;

/// `Label(x) = "khensu v1 " || x`.
pub fn label(x: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + x.len());
    out.extend_from_slice(b"khensu v1 ");
    out.extend_from_slice(x.as_bytes());
    out
}

/// Fills a fixed-size array from the operating system RNG.
pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|_| Error::Rng)?;
    Ok(out)
}

/// QUIC-style variable-length integer (RFC 9000 section 16), as used by MLS vectors.
pub fn write_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0x3f => out.push(v as u8),
        0x40..=0x3fff => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => {
            assert!(v < 1 << 62, "varint out of range");
            out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes())
        }
    }
}

/// Writes `opaque x<V>`.
pub fn write_vec(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Cursor over a byte slice for decoding the structures in PROTOCOL.md.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Error::Length);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub fn varint(&mut self) -> Result<u64> {
        let first = self.u8()?;
        let len = 1usize << (first >> 6);
        let mut v = (first & 0x3f) as u64;
        for _ in 1..len {
            v = (v << 8) | self.u8()? as u64;
        }
        // Reject non-minimal encodings, as MLS does.
        let minimal = match len {
            1 => true,
            2 => v >= 0x40,
            4 => v >= 0x4000,
            _ => v >= 0x4000_0000,
        };
        if !minimal {
            return Err(Error::Length);
        }
        Ok(v)
    }

    pub fn vec(&mut self) -> Result<&'a [u8]> {
        let n = self.varint()?;
        let n = usize::try_from(n).map_err(|_| Error::Length)?;
        self.take(n)
    }

    pub fn finish(self) -> Result<()> {
        if self.buf.is_empty() { Ok(()) } else { Err(Error::Length) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_and_minimality() {
        for v in [0u64, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1] {
            let mut out = Vec::new();
            write_varint(&mut out, v);
            let mut r = Reader::new(&out);
            assert_eq!(r.varint().unwrap(), v);
            assert!(r.finish().is_ok());
        }
        assert_eq!(Reader::new(&[0x40, 0x01]).varint(), Err(Error::Length));
    }
}

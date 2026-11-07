//! Authenticator data. Port of `AppleAuthData.sol`: the narrow canonical CBOR
//! profile of macOS 27 and iOS 27 App Attest. Unknown extensions are rejected.

use crate::crypto::Crypto;
use crate::error::{require, Result};

fn head(b: &[u8], mut p: usize, major: u8) -> Result<(usize, usize)> {
    require!(p < b.len(), "CBOR truncated");
    let h = b[p];
    p += 1;
    require!(h >> 5 == major, "CBOR type");
    let mut n = (h & 31) as usize;
    require!(n < 26, "CBOR length profile");
    if n == 24 {
        require!(p < b.len(), "CBOR truncated");
        n = b[p] as usize;
        p += 1;
        require!(n >= 24, "CBOR nonminimal");
    } else if n == 25 {
        require!(p + 2 <= b.len(), "CBOR truncated");
        n = ((b[p] as usize) << 8) | b[p + 1] as usize;
        p += 2;
        require!(n > 255, "CBOR nonminimal");
    }
    Ok((n, p))
}

fn item(b: &[u8], p: usize, major: u8) -> Result<(&[u8], usize)> {
    let (size, start) = head(b, p, major)?;
    require!(start + size <= b.len(), "CBOR bounds");
    Ok((&b[start..start + size], start + size))
}

/// What a successful check reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub counter: u32,
    /// The credential ID, which is the SHA-256 of the key. Zero for an assertion.
    pub kid: [u8; 32],
    pub cdhash: [u8; 32],
    /// The RP ID hash: the first 32 bytes of the authenticator data.
    pub rp: [u8; 32],
}

/// Check authenticator data. For an enrollment `x` and `y` are the leaf key and the
/// credential data must carry it; for an assertion they are ignored.
pub fn check(
    c: &impl Crypto,
    auth: &[u8],
    aaguid: &[u8; 16],
    enrollment: bool,
    x: &[u8; 32],
    y: &[u8; 32],
    category: u32,
) -> Result<Checked> {
    require!(auth.len() >= 37 && auth.len() <= 1024, "auth size");
    let mut rp = [0u8; 32];
    rp.copy_from_slice(&auth[..32]);
    let flags = auth[32];
    require!(flags & 0x3e == 0 && flags & 0x80 != 0, "auth flags");
    let counter = u32::from_be_bytes(auth[33..37].try_into().unwrap());
    let mut p = 37;
    let mut kid = [0u8; 32];
    if enrollment {
        require!(flags & 0x40 != 0 && counter == 0 && auth.len() >= 164, "enrollment flags/counter");
        kid.copy_from_slice(&auth[55..87]);
        require!(auth[37..53] == aaguid[..] && auth[53] == 0 && auth[54] == 0x20, "AAGUID/credential length");
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(x);
        point.extend_from_slice(y);
        require!(kid == c.sha256(&point), "credential key");
        let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        cose.extend_from_slice(x);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(y);
        p = 87 + cose.len();
        require!(auth.len() >= p, "COSE truncated");
        require!(auth[87..p] == cose[..], "COSE key");
    }
    let (count, start) = head(auth, p, 5)?;
    p = start;
    let mut seen = 0u8;
    let mut cdhash = [0u8; 32];
    for _ in 0..count {
        let (key, next) = item(auth, p, 3)?;
        p = next;
        let flag;
        if key == b"apple_bundle_version_01" {
            flag = 8;
            let (_, next) = item(auth, p, 3)?;
            p = next;
        } else {
            let (value, next) = item(auth, p, 2)?;
            p = next;
            if key == b"apple_cd_hash_hash_01" {
                flag = 1;
                require!(value.len() == 32, "CDHash length");
                cdhash.copy_from_slice(value);
            } else if key == b"apple_cd_hash_type_01" {
                flag = 2;
                require!(value.len() == 1 && value[0] == 0x02, "CDHash type");
            } else if key == b"apple_validation_category_01" {
                flag = 4;
                require!(value == category.to_le_bytes(), "validation category");
            } else {
                return Err(crate::error::Error("unknown extension"));
            }
        }
        require!(seen & flag == 0, "duplicate extension");
        seen |= flag;
    }
    require!(seen & 7 == 7, "missing extension");
    require!(p == auth.len(), "auth trailing data");
    Ok(Checked { counter, kid, cdhash, rp })
}

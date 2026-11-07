//! Apple App Attestation CA certificates. Port of `AppleIntermediate.sol` and
//! `AppleEndorsements.endorseIntermediate`.

use crate::crypto::Crypto;
use crate::der;
use crate::error::{require, Result};
use crate::ext;

/// Not-after of Apple's App Attestation root: 2045-03-15 UTC.
pub const ROOT_NOT_AFTER: u64 = 2_373_148_800;

/// The P-384 key of `trust/apple-app-attestation-root.pem`, x then y.
pub const APPLE_ROOT_KEY: [u8; 96] = hex96(
    "4531e198b5b4ec04da1502045704ed4f877272d76135b26116cfc88b615d0a000719ba69858dfe77caa3b839e020ddd6\
     56141404702831e43f70b88fd6c394b608ea2bd6ae61e9f598c12f46af52937266e57f14eb61fec530f7144f53812e35",
);

const fn hex96(s: &str) -> [u8; 96] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("hex"),
        }
    }
    let b = s.as_bytes();
    let mut out = [0u8; 96];
    let mut i = 0;
    let mut j = 0;
    while i < b.len() {
        if b[i] == b' ' || b[i] == b'\\' || b[i] == b'\n' {
            i += 1;
            continue;
        }
        out[j] = nib(b[i]) << 4 | nib(b[i + 1]);
        j += 1;
        i += 2;
    }
    assert!(j == 96);
    out
}

/// Order of the P-384 group, big endian.
const N384: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
];

/// Reject zero and values at or above the group order.
pub fn scalar(raw: &[u8; 48]) -> Result<()> {
    require!(raw.iter().any(|&b| b != 0), "zero scalar");
    require!(raw < &N384, "scalar range");
    Ok(())
}

/// What the registry keeps for an endorsed intermediate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intermediate {
    pub subject: [u8; 32],
    /// x then y, 48 bytes each.
    pub key: [u8; 96],
    pub not_before: u64,
    pub not_after: u64,
}

impl Intermediate {
    /// `sha256(abi.encode(subject, key))` with the key as four 256-bit words: the
    /// high 16 bytes and low 32 bytes of x, then of y. The Solidity registry uses
    /// this value as the intermediate's identifier.
    pub fn id(&self, c: &impl Crypto) -> [u8; 32] {
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(&self.subject);
        for coord in [&self.key[..48], &self.key[48..]] {
            buf.extend_from_slice(&[0u8; 16]);
            buf.extend_from_slice(coord);
        }
        c.sha256(&buf)
    }
}

#[derive(Debug)]
pub struct Parsed {
    pub digest: [u8; 48],
    pub intermediate: Intermediate,
    pub sig: [u8; 96],
}

pub fn parse(c: &impl Crypto, cert: &[u8], now: u64) -> Result<Parsed> {
    require!(cert.len() <= 4096, "certificate size");
    let outer = der::expect(cert, 0, cert.len(), 0x30)?;
    require!(outer.end == cert.len(), "certificate trailing");
    let tbs = der::expect(cert, outer.body, outer.end, 0x30)?;
    let digest = c.sha384(der::encoded(cert, &tbs));
    let alg = der::expect(cert, tbs.end, outer.end, 0x30)?;
    require!(der::encoded(cert, &alg) == [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03], "signature algorithm");
    let bits = der::expect(cert, alg.end, outer.end, 3)?;
    require!(bits.end == outer.end && bits.end > bits.body && cert[bits.body] == 0, "certificate signature bits");
    let seq = der::expect(cert, bits.body + 1, bits.end, 0x30)?;
    require!(seq.end == bits.end, "signature trailing");
    let r = der::expect(cert, seq.body, seq.end, 2)?;
    let s = der::expect(cert, r.end, seq.end, 2)?;
    require!(s.end == seq.end, "signature fields");
    let rb = der::integer::<48>(cert, &r)?;
    let sb = der::integer::<48>(cert, &s)?;
    scalar(&rb)?;
    scalar(&sb)?;
    let n = der::expect(cert, tbs.body, tbs.end, 0xa0)?;
    require!(der::encoded(cert, &n) == [0xa0, 0x03, 0x02, 0x01, 0x02], "certificate version");
    let n = der::expect(cert, n.end, tbs.end, 2)?;
    der::integer::<20>(cert, &n)?;
    let n = der::expect(cert, n.end, tbs.end, 0x30)?;
    require!(der::encoded(cert, &n) == der::encoded(cert, &alg), "inner signature algorithm");
    let n = der::expect(cert, n.end, tbs.end, 0x30)?; // issuer: not an authority input
    let n = der::expect(cert, n.end, tbs.end, 0x30)?; // validity
    let before = der::expect(cert, n.body, n.end, 0x17)?;
    let after = der::expect(cert, before.end, n.end, 0x17)?;
    require!(after.end == n.end, "validity trailing");
    let not_after = der::utc(cert, &after)?;
    let not_before = der::utc(cert, &before)?;
    require!(now >= not_before && now <= not_after, "certificate validity");
    let n = der::expect(cert, n.end, tbs.end, 0x30)?;
    let subject = c.sha256(der::encoded(cert, &n));
    let n = der::expect(cert, n.end, tbs.end, 0x30)?;
    let pkalg = der::expect(cert, n.body, n.end, 0x30)?;
    require!(
        der::encoded(cert, &pkalg)
            == [0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
        "P384 SPKI"
    );
    let pk = der::expect(cert, pkalg.end, n.end, 3)?;
    require!(
        pk.end == n.end && pk.end - pk.body == 98 && cert[pk.body] == 0 && cert[pk.body + 1] == 0x04,
        "public key encoding"
    );
    let mut key = [0u8; 96];
    key.copy_from_slice(&cert[pk.body + 2..pk.end]);
    let n = der::expect(cert, n.end, tbs.end, 0xa3)?;
    require!(n.end == tbs.end, "TBS trailing");
    let seq = der::expect(cert, n.body, n.end, 0x30)?;
    require!(seq.end == n.end, "extensions trailing");
    extensions(cert, &seq)?;
    let mut sig = [0u8; 96];
    sig[..48].copy_from_slice(&rb);
    sig[48..].copy_from_slice(&sb);
    Ok(Parsed { digest, intermediate: Intermediate { subject, key, not_before, not_after }, sig })
}

fn extensions(cert: &[u8], seq: &der::Node) -> Result<()> {
    let mut required = 0u8;
    ext::walk(cert, seq, |e| {
        match e.oid {
            [0x55, 0x1d, 0x13] => {
                require!(e.critical && e.value == [0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00], "CA constraints");
                required |= 1;
            }
            [0x55, 0x1d, 0x0f] => {
                require!(e.critical && e.value == [0x03, 0x02, 0x01, 0x06], "CA usage");
                required |= 2;
            }
            _ => require!(!e.critical, "unsupported critical extension"),
        }
        Ok(())
    })?;
    require!(required == 3, "missing certificate extension");
    Ok(())
}

/// Check an Apple intermediate against `root_key` and return it. The caller keeps
/// it under `Intermediate::id` and rejects an id that it already holds
/// ("already endorsed").
pub fn endorse(c: &impl Crypto, root_key: &[u8; 96], der_cert: &[u8], now: u64) -> Result<Intermediate> {
    let p = parse(c, der_cert, now)?;
    require!(c.p384_verify_prehash(root_key, &p.digest, &p.sig), "root certificate signature");
    Ok(p.intermediate)
}

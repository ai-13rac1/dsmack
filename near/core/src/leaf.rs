//! Apple App Attest leaf certificates. Port of `AppleLeaf.sol`.

use crate::crypto::Crypto;
use crate::der;
use crate::error::{require, Result};
use crate::ext;
use crate::intermediate::scalar;

/// Key ACL extension content that Apple signs for a Mac key (leaf OID 1.2.840.113635.100.8.6).
pub const MAC_ACL: &[u8] = &[
    0x30, 0x46, 0xa3, 0x44, 0x04, 0x42, 0x30, 0x40, 0x0c, 0x02, 0x31, 0x31, 0x30, 0x3a, 0x30, 0x09,
    0x0c, 0x02, 0x6f, 0x6b, 0xa1, 0x03, 0x01, 0x01, 0xff, 0x30, 0x09, 0x0c, 0x02, 0x6f, 0x61, 0xa1,
    0x03, 0x01, 0x01, 0xff, 0x30, 0x0b, 0x0c, 0x04, 0x6f, 0x64, 0x65, 0x6c, 0xa1, 0x03, 0x01, 0x01,
    0xff, 0x30, 0x15, 0x0c, 0x04, 0x6f, 0x73, 0x67, 0x6e, 0xa0, 0x06, 0x0c, 0x04, 0x72, 0x73, 0x65,
    0x63, 0x30, 0x05, 0xa6, 0x03, 0x02, 0x01, 0x01,
];

/// Key ACL extension content that Apple signs for an iOS key.
pub const IOS_ACL: &[u8] = &[
    0x30, 0x49, 0xa3, 0x47, 0x04, 0x45, 0x30, 0x43, 0x0c, 0x02, 0x31, 0x31, 0x30, 0x3d, 0x30, 0x0a,
    0x0c, 0x03, 0x6f, 0x6b, 0x64, 0xa1, 0x03, 0x01, 0x01, 0xff, 0x30, 0x09, 0x0c, 0x02, 0x6f, 0x61,
    0xa1, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0b, 0x0c, 0x04, 0x6f, 0x73, 0x67, 0x6e, 0xa1, 0x03, 0x01,
    0x01, 0xff, 0x30, 0x0b, 0x0c, 0x04, 0x6f, 0x64, 0x65, 0x6c, 0xa1, 0x03, 0x01, 0x01, 0xff, 0x30,
    0x0a, 0x0c, 0x03, 0x6f, 0x63, 0x6b, 0xa1, 0x03, 0x01, 0x01, 0xff,
];

#[derive(Debug)]
pub struct Parsed {
    pub tbs_hash: [u8; 32],
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub expires: u64,
    /// r then s of the intermediate's P-384 signature.
    pub sig: [u8; 96],
}

/// Parse `cert`. `issuer_hash` is the intermediate's subject hash, `nonce` the
/// expected nonce extension value and `acl` the expected key ACL.
pub fn parse(
    c: &impl Crypto,
    cert: &[u8],
    issuer_hash: &[u8; 32],
    nonce: &[u8; 32],
    acl: &[u8],
    now: u64,
) -> Result<Parsed> {
    require!(cert.len() <= 4096, "certificate size");
    let outer = der::expect(cert, 0, cert.len(), 0x30)?;
    require!(outer.end == cert.len(), "certificate trailing");
    let tbs = der::expect(cert, outer.body, outer.end, 0x30)?;
    let tbs_hash = c.sha256(der::encoded(cert, &tbs));
    let alg = der::expect(cert, tbs.end, outer.end, 0x30)?;
    require!(der::encoded(cert, &alg) == [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02], "signature algorithm");
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
    let n = der::expect(cert, n.end, tbs.end, 0x30)?;
    require!(&c.sha256(der::encoded(cert, &n)) == issuer_hash, "issuer name");
    let n = der::expect(cert, n.end, tbs.end, 0x30)?;
    let before = der::expect(cert, n.body, n.end, 0x17)?;
    let after = der::expect(cert, before.end, n.end, 0x17)?;
    require!(after.end == n.end, "validity trailing");
    let expires = der::utc(cert, &after)?;
    require!(now >= der::utc(cert, &before)? && now <= expires, "certificate validity");
    let n = der::expect(cert, n.end, tbs.end, 0x30)?; // signed subject, not an authority input
    let n = der::expect(cert, n.end, tbs.end, 0x30)?;
    let pkalg = der::expect(cert, n.body, n.end, 0x30)?;
    require!(
        der::encoded(cert, &pkalg)
            == [0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        "P256 SPKI"
    );
    let pk = der::expect(cert, pkalg.end, n.end, 3)?;
    require!(
        pk.end == n.end && pk.end - pk.body == 66 && cert[pk.body] == 0 && cert[pk.body + 1] == 0x04,
        "public key encoding"
    );
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&cert[pk.body + 2..pk.body + 34]);
    y.copy_from_slice(&cert[pk.body + 34..pk.end]);
    let n = der::expect(cert, n.end, tbs.end, 0xa3)?;
    require!(n.end == tbs.end, "TBS trailing");
    let seq = der::expect(cert, n.body, n.end, 0x30)?;
    require!(seq.end == n.end, "extensions trailing");
    extensions(cert, &seq, nonce, acl)?;
    let mut sig = [0u8; 96];
    sig[..48].copy_from_slice(&rb);
    sig[48..].copy_from_slice(&sb);
    Ok(Parsed { tbs_hash, x, y, expires, sig })
}

fn extensions(cert: &[u8], seq: &der::Node, nonce: &[u8; 32], acl: &[u8]) -> Result<()> {
    let mut required = 0u8;
    ext::walk(cert, seq, |e| {
        match e.oid {
            [0x55, 0x1d, 0x13] => {
                require!(e.critical && e.value == [0x30, 0x00], "leaf constraints");
                required |= 1;
            }
            [0x55, 0x1d, 0x0f] => {
                require!(e.critical && e.value == [0x03, 0x02, 0x04, 0xf0], "leaf usage");
                required |= 2;
            }
            _ => {
                require!(!e.critical, "unsupported critical extension");
                match e.oid {
                    [0x55, 0x1d, 0x25] => {
                        require!(e.value == [0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x04, 0x18], "Apple EKU");
                        required |= 4;
                    }
                    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02] => {
                        let mut want = vec![0x30, 0x24, 0xa1, 0x22, 0x04, 0x20];
                        want.extend_from_slice(nonce);
                        require!(e.value == want.as_slice(), "certificate nonce");
                        required |= 8;
                    }
                    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x06] => {
                        require!(e.value == acl, "key ACL");
                        required |= 16;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    })?;
    require!(required == 31, "missing certificate extension");
    Ok(())
}

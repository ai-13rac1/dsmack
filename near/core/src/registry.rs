//! Approved builds. Port of the measurement code of `CDRegistry.sol`.
//!
//! A build is measured from a CodeDirectory blob, page 0 of the Mach-O and the DER
//! entitlements. Two copies of one program that differ only in signer fields
//! measure the same. The caller keeps the approved build ids and the CDHash maps.

use crate::crypto::Crypto;
use crate::der;
use crate::error::{require, Error, Result};

/// What distinguishes one build from another. Signer identity is not part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    pub rest: [u8; 32],
    pub masked_page0: [u8; 32],
    pub header: [u8; 32],
    pub entitlements: [u8; 32],
    pub code_limit: usize,
    pub linkedit_cmd: usize,
    pub code_sig_cmd: usize,
}

impl Build {
    /// `keccak256(abi.encode(build))`: seven 32-byte words.
    pub fn id(&self, c: &impl Crypto) -> [u8; 32] {
        let mut buf = Vec::with_capacity(7 * 32);
        for h in [&self.rest, &self.masked_page0, &self.header, &self.entitlements] {
            buf.extend_from_slice(h);
        }
        for n in [self.code_limit, self.linkedit_cmd, self.code_sig_cmd] {
            buf.extend_from_slice(&[0u8; 24]);
            buf.extend_from_slice(&(n as u64).to_be_bytes());
        }
        c.keccak256(&buf)
    }
}

/// Identity values that the entitlements seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Hash of the entitlement keys and non-identity values.
    pub shape: [u8; 32],
    /// SHA-256 of `application-identifier`: the App Attest RP ID hash.
    pub app: [u8; 32],
    /// SHA-256 of the team identifier, or zero when the entitlements have none.
    pub team: [u8; 32],
    /// SHA-256 of the part of `application-identifier` after the first dot.
    pub bundle: [u8; 32],
}

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error("slice bounds"))
}

fn slice(b: &[u8], start: usize, end: usize) -> Result<&[u8]> {
    require!(start <= end && end <= b.len(), "slice bounds");
    Ok(&b[start..end])
}

fn be32(b: &[u8], o: usize) -> Result<usize> {
    Ok(u32::from_be_bytes(slice(b, o, add(o, 4)?)?.try_into().unwrap()) as usize)
}

fn le32(b: &[u8], o: usize) -> Result<usize> {
    Ok(u32::from_le_bytes(slice(b, o, add(o, 4)?)?.try_into().unwrap()) as usize)
}

/// Page-0 offsets of the `__LINKEDIT` LC_SEGMENT_64 and the LC_CODE_SIGNATURE of a
/// thin arm64 Mach-O.
pub fn load_commands(page0: &[u8]) -> Result<(usize, usize)> {
    require!(le32(page0, 0)? == 0xfeed_facf && le32(page0, 4)? == 0x0100_000c, "thin arm64");
    let end = add(32, le32(page0, 20)?)?;
    require!(end <= page0.len(), "load commands");
    let (mut linkedit, mut code_sig) = (0usize, 0usize);
    let mut off = 32usize;
    for _ in 0..le32(page0, 16)? {
        let (cmd, sz) = (le32(page0, off)?, le32(page0, add(off, 4)?)?);
        require!(sz >= 8 && add(off, sz)? <= end, "load commands");
        let mut name = [0u8; 16];
        name[..10].copy_from_slice(b"__LINKEDIT");
        if cmd == 0x19 && slice(page0, add(off, 8)?, add(off, 24)?)? == name {
            require!(linkedit == 0 && sz == 72, "__LINKEDIT");
            linkedit = off;
        }
        if cmd == 0x1d {
            require!(code_sig == 0 && sz == 16, "LC_CODE_SIGNATURE");
            code_sig = off;
        }
        off = add(off, sz)?;
    }
    require!(linkedit != 0, "__LINKEDIT");
    require!(code_sig != 0, "LC_CODE_SIGNATURE");
    Ok((linkedit, code_sig))
}

/// Hash of page 0 with the three signer-dependent fields cleared: the `__LINKEDIT`
/// vmsize and filesize, and the LC_CODE_SIGNATURE datasize.
pub fn masked_hash(c: &impl Crypto, page0: &[u8], linkedit: usize, code_sig: usize) -> [u8; 32] {
    let mut p = page0.to_vec();
    p[linkedit + 32..linkedit + 40].fill(0);
    p[linkedit + 48..linkedit + 56].fill(0);
    p[code_sig + 12..code_sig + 16].fill(0);
    c.keccak256(&p)
}

/// Read the identity and the shape of DER entitlements. Identity values are sealed
/// by the CDHash but are not proof of execution: a consumer must also verify a live
/// Apple assertion for that CDHash and RP pair.
pub fn entitlement_identity(c: &impl Crypto, d: &[u8]) -> Result<Identity> {
    let outer = der::expect(d, 0, d.len(), 0x70)?;
    let version = der::expect(d, outer.body, outer.end, 0x02)?;
    require!(outer.end == d.len() && version.end == version.body + 1 && d[version.body] == 0x01, "entitlements");
    let dict = der::expect(d, version.end, outer.end, 0xb0)?;
    require!(dict.end == outer.end, "entitlements");
    let mut id = Identity { shape: [0; 32], app: [0; 32], team: [0; 32], bundle: [0; 32] };
    let chain = |shape: &[u8; 32], k: &[u8; 32]| {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(shape);
        b[32..].copy_from_slice(k);
        c.keccak256(&b)
    };
    let mut p = dict.body;
    while p < dict.end {
        let pair = der::expect(d, p, dict.end, 0x30)?;
        let key = der::expect(d, pair.body, pair.end, 0x0c)?;
        let value = der::node(d, key.end, pair.end)?;
        require!(value.end == pair.end, "entitlements");
        let name = der::contents(d, &key);
        let k = c.keccak256(name);
        if name == b"application-identifier" || name == b"com.apple.application-identifier" {
            require!(id.app == [0; 32] && value.tag == 0x0c, "application-identifier");
            let app_id = der::contents(d, &value);
            id.app = c.sha256(app_id);
            // The App ID prefix may differ from the team ID on legacy accounts. Bind the
            // bundle suffix without treating the prefix as a team.
            for i in 0..app_id.len() {
                if app_id[i] == b'.' && i > 0 && i + 1 < app_id.len() {
                    id.bundle = c.sha256(&app_id[i + 1..]);
                    break;
                }
            }
            id.shape = chain(&id.shape, &k);
        } else if name == b"com.apple.developer.team-identifier" {
            require!(id.team == [0; 32] && value.tag == 0x0c, "team-identifier");
            let team = der::contents(d, &value);
            require!(
                team.len() == 10 && team.iter().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit()),
                "team-identifier"
            );
            id.team = c.sha256(team);
            id.shape = chain(&id.shape, &k);
        } else if name == b"keychain-access-groups" {
            id.shape = chain(&id.shape, &k);
        } else {
            let pair_hash = c.keccak256(der::encoded(d, &pair));
            id.shape = chain(&id.shape, &pair_hash);
        }
        p = pair.end;
    }
    require!(id.app != [0; 32], "application-identifier");
    Ok(id)
}

fn header(c: &impl Crypto, cd: &[u8]) -> Result<[u8; 32]> {
    let tail = if be32(cd, 8)? >= 0x20500 { 0x60 } else { 0x58 };
    let mut b = Vec::new();
    b.extend_from_slice(slice(cd, 8, 16)?);
    b.extend_from_slice(slice(cd, 0x24, 0x30)?);
    b.extend_from_slice(slice(cd, 0x34, tail)?);
    Ok(c.keccak256(&b))
}

/// Measure a build and return it with the identity of its entitlements.
pub fn measure(c: &impl Crypto, cd: &[u8], page0: &[u8], ent: &[u8]) -> Result<(Build, Identity)> {
    require!(be32(cd, 0)? == 0xfade_0c02 && be32(cd, 4)? == cd.len(), "blob");
    let hash_params = slice(cd, 0x24, 0x28)?;
    require!(
        hash_params[0] == 0x20 && hash_params[1] == 0x02 && hash_params[3] == 0x0e && page0.len() == 16384,
        "sha256/16KiB"
    );
    let off = be32(cd, 0x10)?;
    let end = add(off, be32(cd, 0x1c)?.checked_mul(32).ok_or(Error("slice bounds"))?)?;
    require!(end <= cd.len() && c.sha256(page0)[..] == *slice(cd, off, add(off, 32)?)?, "page0 hash");
    let mut slot = Vec::with_capacity(ent.len() + 8);
    slot.extend_from_slice(&0xfade_7172u32.to_be_bytes());
    slot.extend_from_slice(&((ent.len() + 8) as u32).to_be_bytes());
    slot.extend_from_slice(ent);
    require!(
        be32(cd, 0x18)? >= 7 && off >= 7 * 32 && c.sha256(&slot)[..] == *slice(cd, off - 7 * 32, off - 6 * 32)?,
        "entitlements slot"
    );
    let identity = entitlement_identity(c, ent)?;
    let (linkedit_cmd, code_sig_cmd) = load_commands(page0)?;
    let build = Build {
        rest: c.keccak256(slice(cd, add(off, 32)?, end)?),
        masked_page0: masked_hash(c, page0, linkedit_cmd, code_sig_cmd),
        header: header(c, cd)?,
        entitlements: identity.shape,
        code_limit: be32(cd, 0x20)?,
        linkedit_cmd,
        code_sig_cmd,
    };
    Ok((build, identity))
}

/// The CDHash of a CodeDirectory blob.
pub fn cdhash(c: &impl Crypto, cd: &[u8]) -> [u8; 32] {
    c.sha256(cd)
}

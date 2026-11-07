//! Enrollment and assertion checks. Port of `AppleAttest.sol`.
//!
//! The functions hold no state. The caller keeps the endorsed intermediates and
//! the enrolled keys, and applies the results.

use crate::authdata;
use crate::crypto::Crypto;
use crate::error::{require, Result};
use crate::intermediate::{Intermediate, ROOT_NOT_AFTER};
use crate::leaf::{self, IOS_ACL, MAC_ACL};

/// The platform that a deployment accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub aaguid: [u8; 16],
    /// Apple validation category: 3 is Apple Development for a Mac.
    pub category: u32,
    pub ios: bool,
}

impl Platform {
    fn acl(&self) -> &'static [u8] {
        if self.ios {
            IOS_ACL
        } else {
            MAC_ACL
        }
    }
}

/// An enrolled key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub expires: u64,
    pub counter: u32,
}

impl Key {
    fn compressed(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = 2 + (self.y[31] & 1);
        out[1..].copy_from_slice(&self.x);
        out
    }
}

/// The policy that decides which builds are admitted.
pub trait Policy {
    /// Accept or reject the CDHash and the RP ID hash that the evidence carries.
    fn admit(&self, cdhash: &[u8; 32], rp: &[u8; 32]) -> Result<()>;
    fn is_enrolled(&self, kid: &[u8; 32]) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    pub kid: [u8; 32],
    pub key: Key,
    pub cdhash: [u8; 32],
    pub rp: [u8; 32],
}

/// Check an enrollment against the endorsed intermediate `ca`. `None` means that
/// the intermediate is not endorsed.
#[allow(clippy::too_many_arguments)]
pub fn enroll(
    c: &impl Crypto,
    platform: &Platform,
    policy: &impl Policy,
    ca: Option<&Intermediate>,
    cert: &[u8],
    auth: &[u8],
    client_data: &[u8],
    now: u64,
) -> Result<Enrolled> {
    require!(client_data.len() <= 2048 && now <= ROOT_NOT_AFTER, "anchor expiry/client data");
    let ca = match ca {
        Some(ca) if ca.not_after != 0 && now >= ca.not_before && now <= ca.not_after => ca,
        _ => return Err(crate::error::Error("intermediate validity")),
    };
    let mut nonce_input = auth.to_vec();
    nonce_input.extend_from_slice(&c.sha256(client_data));
    let nonce = c.sha256(&nonce_input);
    let leaf = leaf::parse(c, cert, &ca.subject, &nonce, platform.acl(), now)?;
    let checked = authdata::check(c, auth, &platform.aaguid, true, &leaf.x, &leaf.y, platform.category)?;
    policy.admit(&checked.cdhash, &checked.rp)?;
    require!(!policy.is_enrolled(&checked.kid), "already enrolled");
    require!(c.p384_verify_prehash(&ca.key, &leaf.tbs_hash, &leaf.sig), "Apple certificate signature");
    Ok(Enrolled {
        kid: checked.kid,
        key: Key { x: leaf.x, y: leaf.y, expires: ca.not_after, counter: 0 },
        cdhash: checked.cdhash,
        rp: checked.rp,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asserted {
    pub counter: u32,
    pub cdhash: [u8; 32],
    pub rp: [u8; 32],
}

/// Check an assertion by `key` over `context`. `None` means that the key is not
/// enrolled. The caller stores `counter` as the key's new counter.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    c: &impl Crypto,
    platform: &Platform,
    policy: &impl Policy,
    key: Option<&Key>,
    auth: &[u8],
    context: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    now: u64,
) -> Result<Asserted> {
    let key = match key {
        Some(k) if now <= k.expires && now <= ROOT_NOT_AFTER => k,
        _ => return Err(crate::error::Error("key validity")),
    };
    let checked = authdata::check(c, auth, &platform.aaguid, false, &[0; 32], &[0; 32], platform.category)?;
    policy.admit(&checked.cdhash, &checked.rp)?;
    require!(checked.counter > key.counter, "assertion replay");
    let mut nonce_input = auth.to_vec();
    nonce_input.extend_from_slice(context);
    let digest = c.sha256(&c.sha256(&nonce_input));
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r);
    sig[32..].copy_from_slice(s);
    require!(c.p256_verify(&sig, &digest, &key.compressed()), "assertion signature");
    Ok(Asserted { counter: checked.counter, cdhash: checked.cdhash, rp: checked.rp })
}

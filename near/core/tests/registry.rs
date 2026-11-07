//! Port of dsmack `contracts/test/CDRegistry.t.sol`.
//! Run with `DSMACK_DIR` set to a dsmack checkout.

mod common;
use common::{err, Native};
use dsmack_attest_core::registry::{self, cdhash};
use dsmack_attest_core::{Crypto, Result};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

fn dir() -> PathBuf {
    let d = std::env::var("DSMACK_DIR").expect("set DSMACK_DIR to a dsmack checkout");
    PathBuf::from(d).join("contracts/fixtures/resign")
}

fn rd(name: &str, ext: &str) -> Vec<u8> {
    let p = dir().join(format!("{name}{ext}"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn json_value(name: &str) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(dir().join(format!("{name}.json"))).unwrap()).unwrap()
}

fn hx(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn json(name: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let j = json_value(name);
    (hx(&j["cd"]), hx(&j["page0"]), hx(&j["ent"]))
}

fn sha(s: &str) -> [u8; 32] {
    Native.sha256(s.as_bytes())
}

const OURS: &str = "90a07dc69293aa64c279caed89cfebd3fde0ad92b510f752ed45ba829157fff6";

/// The state that the contract keeps for the registry.
#[derive(Default)]
struct Registry {
    build_id: [u8; 32],
    approved: HashSet<[u8; 32]>,
    rp_of: HashMap<[u8; 32], [u8; 32]>,
    build_of: HashMap<[u8; 32], [u8; 32]>,
    team: HashMap<[u8; 32], [u8; 32]>,
    bundle: HashMap<[u8; 32], [u8; 32]>,
}

impl Registry {
    fn with_build(cd: &[u8], page0: &[u8], ent: &[u8]) -> Registry {
        let mut r = Registry::default();
        r.set_build(cd, page0, ent).unwrap();
        r
    }
    fn mac() -> Registry {
        Registry::with_build(&rd("A-original", ".cd"), &rd("A-original", ".page0"), &rd("A-original", ".ent"))
    }
    fn json(name: &str) -> Registry {
        let (cd, p, e) = json(name);
        Registry::with_build(&cd, &p, &e)
    }
    fn set_build(&mut self, cd: &[u8], page0: &[u8], ent: &[u8]) -> Result<()> {
        let (b, _) = registry::measure(&Native, cd, page0, ent)?;
        self.build_id = b.id(&Native);
        self.approved.insert(self.build_id);
        Ok(())
    }
    fn register(&mut self, cd: &[u8], page0: &[u8], ent: &[u8]) -> Result<[u8; 32]> {
        let (b, id) = registry::measure(&Native, cd, page0, ent)?;
        let bid = b.id(&Native);
        if !self.approved.contains(&bid) {
            return Err(dsmack_attest_core::Error("not an approved build"));
        }
        let h = cdhash(&Native, cd);
        self.rp_of.insert(h, id.app);
        self.team.insert(h, id.team);
        self.bundle.insert(h, id.bundle);
        self.build_of.insert(h, bid);
        Ok(h)
    }
    fn rp(&self, h: &[u8; 32]) -> [u8; 32] {
        if self.build_of.get(h) == Some(&self.build_id) { self.rp_of[h] } else { [0; 32] }
    }
    fn team_id(&self, h: &[u8; 32]) -> [u8; 32] {
        if self.rp(h) != [0; 32] { self.team[h] } else { [0; 32] }
    }
    fn bundle_id(&self, h: &[u8; 32]) -> [u8; 32] {
        if self.rp(h) != [0; 32] { self.bundle[h] } else { [0; 32] }
    }
    fn admit(&mut self, cd: &[u8], page0: &[u8], ent: &[u8]) -> [u8; 32] {
        let h = self.register(cd, page0, ent).unwrap();
        assert_eq!(h, Native.sha256(cd));
        assert_ne!(self.rp(&h), [0; 32]);
        h
    }
    fn file(&mut self, name: &str) -> [u8; 32] {
        self.admit(&rd(name, ".cd"), &rd(name, ".page0"), &rd(name, ".ent"))
    }
}

fn ours() -> [u8; 32] {
    hex::decode(OURS).unwrap().try_into().unwrap()
}

#[test]
fn resign_fixtures() {
    let mut r = Registry::mac();
    assert_eq!(ours(), sha("DC9JH5DRMY.dev.dsmack.provider"));
    for n in ["A-original", "D-dev-timestamp", "G-strip-then-dev", "I-dev-resign-same"] {
        let h = r.file(n);
        assert_eq!(r.rp(&h), ours());
    }
    for n in ["B-adhoc", "C-adhoc-otherid", "H-strip-then-adhoc", "E-dev-noent"] {
        assert_eq!(err(r.register(&rd(n, ".cd"), &rd(n, ".page0"), &rd(n, ".ent"))), "entitlements slot");
    }
    let n = "M-modified";
    assert_eq!(err(r.register(&rd(n, ".cd"), &rd(n, ".page0"), &rd(n, ".ent"))), "not an approved build");
    let mut p = rd("A-original", ".page0");
    p[100] ^= 1;
    assert_eq!(err(r.register(&rd("A-original", ".cd"), &p, &rd("A-original", ".ent"))), "page0 hash");
}

#[test]
fn load_commands_match_fixtures() {
    for n in [
        "../cd-args-probe-macos", "../cd-args-developer-id", "../cd-args-release-development", "iphone-honest",
        "iphone-modified", "node-honest", "node-resigned", "node-modified", "node-synthetic-team",
        "node-synthetic-prefix-only",
    ] {
        let j = json_value(n);
        let (linkedit, code_sig) = registry::load_commands(&hx(&j["page0"])).unwrap();
        assert_eq!(linkedit as u64, j["linkeditCmd"].as_u64().unwrap(), "{n}");
        assert_eq!(code_sig as u64, j["codeSigCmd"].as_u64().unwrap(), "{n}");
    }
    assert_eq!(registry::load_commands(&rd("A-original", ".page0")).unwrap(), (2320, 3608));
}

#[test]
fn load_commands_reject_malformed() {
    let mut p = rd("A-original", ".page0");
    p[2320 + 8 + 2] = b'X';
    assert_eq!(err(registry::load_commands(&p)), "__LINKEDIT");
    let mut p = rd("A-original", ".page0");
    p[3592] = 0x1d;
    assert_eq!(err(registry::load_commands(&p)), "LC_CODE_SIGNATURE");
    let mut p = rd("A-original", ".page0");
    p[21] = 0x40;
    assert_eq!(err(registry::load_commands(&p)), "load commands");
    let mut p = rd("A-original", ".page0");
    p[20] = 0;
    assert_eq!(err(registry::load_commands(&p)), "load commands");
}

fn patched(at: usize, x: u8) -> Vec<u8> {
    let mut cd = rd("A-original", ".cd");
    cd[at] ^= x;
    cd
}

/// A CodeDirectory whose entitlements slot seals `ent`.
fn with_ent(ent: &[u8]) -> Vec<u8> {
    let mut cd = rd("A-original", ".cd");
    let mut slot = 0xfade_7172u32.to_be_bytes().to_vec();
    slot.extend_from_slice(&((ent.len() + 8) as u32).to_be_bytes());
    slot.extend_from_slice(ent);
    let h = Native.sha256(&slot);
    cd[351 - 224..351 - 224 + 32].copy_from_slice(&h);
    cd
}

#[test]
fn signer_fields_free_behavior_pinned() {
    let mut r = Registry::mac();
    let page0 = rd("A-original", ".page0");
    let ent = rd("A-original", ".ent");
    let h = r.admit(&patched(351 - 1, 1), &page0, &ent); // Info.plist slot
    assert_eq!(r.rp(&h), ours());
    let h = r.admit(&patched(351 - 64, 1), &page0, &ent); // requirements slot
    assert_eq!(r.rp(&h), ours());
    for (at, x) in [(0x0d, 0x01), (0x57, 0x10), (0x5b, 0x01)] {
        // flags, execSeg flags, runtime version
        assert_eq!(err(r.register(&patched(at, x), &page0, &ent)), "not an approved build");
    }
    let mut longer = ent.clone();
    longer.push(0);
    assert_eq!(err(r.register(&rd("A-original", ".cd"), &page0, &longer)), "entitlements slot");
    let mut e = rd("A-original", ".ent");
    e[134] = b'X'; // app-attest-opt-in value
    assert_eq!(err(r.register(&with_ent(&e), &page0, &e)), "not an approved build");
    let mut e = rd("A-original", ".ent");
    e[181..191].fill(b'Z'); // team-identifier value
    let h = r.admit(&with_ent(&e), &page0, &e);
    assert_eq!(r.rp(&h), ours());
    let mut e = rd("A-original", ".ent");
    e[47..57].fill(b'Z'); // application-identifier value
    let h = r.admit(&with_ent(&e), &page0, &e);
    assert_eq!(r.rp(&h), sha("ZZZZZZZZZZ.dev.dsmack.provider"));
}

#[test]
fn team_metadata_requires_sealed_entitlements() {
    let mut r = Registry::mac();
    let page0 = rd("A-original", ".page0");
    let mut ent = rd("A-original", ".ent");
    let original = r.file("A-original");
    assert_eq!(r.team_id(&original), sha("DC9JH5DRMY"));
    ent[181..191].fill(b'Z');
    assert_eq!(err(r.register(&rd("A-original", ".cd"), &page0, &ent)), "entitlements slot");
    let changed = r.register(&with_ent(&ent), &page0, &ent).unwrap();
    assert_ne!(changed, original);
    assert_eq!(r.team_id(&changed), sha("ZZZZZZZZZZ"));
    assert_eq!(r.team_id(&original), sha("DC9JH5DRMY"));
    ent[181] = b'!';
    assert_eq!(err(r.register(&with_ent(&ent), &page0, &ent)), "team-identifier");
    assert_eq!(r.team_id(&[0; 31].iter().copied().chain([123]).collect::<Vec<_>>().try_into().unwrap()), [0; 32]);
}

#[test]
fn bundle_identity_is_sealed_and_separate_from_prefix() {
    let mut r = Registry::mac();
    let original = r.file("A-original");
    assert_eq!(r.bundle_id(&original), sha("dev.dsmack.provider"));
    let page0 = rd("A-original", ".page0");
    let mut ent = rd("A-original", ".ent");
    ent[47..57].fill(b'Z');
    let h = r.register(&with_ent(&ent), &page0, &ent).unwrap();
    assert_eq!(r.bundle_id(&h), sha("dev.dsmack.provider"));
    ent[76] = b'x';
    let changed = r.register(&with_ent(&ent), &page0, &ent).unwrap();
    assert_eq!(r.bundle_id(&changed), sha("dev.dsmack.providex"));
    assert_eq!(r.bundle_id(&original), sha("dev.dsmack.provider"));
}

#[test]
fn new_build_makes_old_builds_stop_resolving() {
    let mut r = Registry::mac();
    let a = r.file("A-original");
    let (cd, page0, ent) = json("iphone-honest");
    r.set_build(&cd, &page0, &ent).unwrap();
    assert_eq!(r.rp(&a), [0; 32]);
    assert_eq!(r.team_id(&a), [0; 32]);
    assert_eq!(r.bundle_id(&a), [0; 32]);
    let h = r.admit(&cd, &page0, &ent);
    assert_eq!(r.rp(&h), ours());
    // A consumer that pins a build still resolves the superseded one.
    assert_eq!(r.rp_of[&a], ours());
    assert!(r.build_of[&a] != r.build_id && r.approved.contains(&r.build_of[&a]));
}

#[test]
fn iphone_build() {
    let mut r = Registry::json("iphone-honest");
    let (cd, page0, ent) = json("iphone-honest");
    let h = r.admit(&cd, &page0, &ent);
    assert_eq!(hex::encode(h), "5395bf39ecded47ab804eb78b7f878c246baa4860ca32cad1c63ed468783b591");
    assert_eq!(r.rp(&h), ours());
    let (cd, page0, ent) = json("iphone-modified");
    assert_eq!(err(r.register(&cd, &page0, &ent)), "not an approved build");
}

#[test]
fn synthetic_team_identity() {
    let mut r = Registry::json("node-honest");
    let (cd, page0, ent) = json("node-honest");
    let original = r.admit(&cd, &page0, &ent);
    let (cd, page0, ent) = json("node-synthetic-team");
    let changed = r.admit(&cd, &page0, &ent);
    assert_ne!(changed, original);
    assert_eq!(r.rp(&original), ours());
    assert_eq!(r.team_id(&original), sha("DC9JH5DRMY"));
    assert_eq!(r.rp(&changed), sha("TESTTEAM01.dev.dsmack.provider"));
    assert_eq!(r.team_id(&changed), sha("TESTTEAM01"));
}

#[test]
fn missing_team_is_not_inferred_from_app_prefix() {
    let mut r = Registry::json("node-synthetic-prefix-only");
    let (cd, page0, ent) = json("node-synthetic-prefix-only");
    let original = r.admit(&cd, &page0, &ent);
    let (cd, page0, ent) = json("node-synthetic-prefix-only-other");
    let changed = r.admit(&cd, &page0, &ent);
    assert_ne!(changed, original);
    assert_eq!(r.rp(&original), ours());
    assert_eq!(r.rp(&changed), sha("TESTTEAM01.dev.dsmack.provider"));
    assert_eq!(r.team_id(&original), [0; 32]);
    assert_eq!(r.team_id(&changed), [0; 32]);
    assert_eq!(err(r.register(&cd, &page0, &[])), "entitlements slot");
}

#[test]
fn node_builds() {
    let mut r = Registry::json("node-honest");
    let (cd, page0, ent) = json("node-honest");
    let a = r.admit(&cd, &page0, &ent);
    let (cd, page0, ent) = json("node-resigned");
    let b = r.admit(&cd, &page0, &ent);
    assert_ne!(a, b);
    assert_eq!(r.rp(&b), ours());
    let (cd, page0, ent) = json("node-modified");
    assert_eq!(err(r.register(&cd, &page0, &ent)), "not an approved build");
}

//! Tests of the authenticator data checks against Apple's fixtures.
//! near/test.sh sets `DSMACK_DIR`.

mod common;
use common::*;
use dsmack_attest_core::intermediate::{self, APPLE_ROOT_KEY};
use dsmack_attest_core::leaf::{self, IOS_ACL, MAC_ACL};
use dsmack_attest_core::authdata;

// (fixture, validation category, iOS, a time inside the leaf's validity)
const MAC_REAL: (&str, u32, bool, u64) = ("real-apple.json", 3, false, 1_789_567_200);
const MAC_FRESH: (&str, u32, bool, u64) = ("fresh-apple.json", 3, false, 1_789_588_800);
const IPHONE: (&str, u32, bool, u64) = ("iphone-apple.json", 5, true, 1_790_200_000);

/// The key of the leaf certificate, as the certificate parser reads it.
fn leaf_key(f: &Fixture, ios: bool, now: u64) -> ([u8; 32], [u8; 32]) {
    let ca = intermediate::endorse(&Native, &APPLE_ROOT_KEY, &read("apple-intermediate.der"), now).unwrap();
    let acl = if ios { IOS_ACL } else { MAC_ACL };
    let l = leaf::parse(&Native, &f.cert, &ca.subject, &f.nonce(), acl, now).unwrap();
    (l.x, l.y)
}

#[test]
fn enrollment_data_of_each_fixture_is_accepted() {
    for (name, category, ios, now) in [MAC_REAL, MAC_FRESH, IPHONE] {
        let f = Fixture::load(name);
        let (x, y) = leaf_key(&f, ios, now);
        let c = authdata::check(&Native, &f.auth, &f.aaguid, true, &x, &y, category).unwrap();
        assert_eq!((c.counter, c.kid, c.cdhash, c.rp), (0, f.kid, f.cdhash, f.app_hash), "{name}");
    }
}

#[test]
fn assertion_data_carries_the_build_and_a_counter() {
    let f = Fixture::load("fresh-apple.json");
    for name in ["assert", "modified", "restored"] {
        let (auth, ..) = f.assertion(name);
        let c = authdata::check(&Native, &auth, &f.aaguid, false, &[0; 32], &[0; 32], 3).unwrap();
        assert!(c.counter > 0, "{name}");
        assert_eq!(c.rp, f.app_hash, "{name}");
        // The modified build asserts a different CDHash.
        assert_eq!(c.cdhash == f.cdhash, name != "modified", "{name}");
    }
}

#[test]
fn enrollment_data_binds_the_credential_to_the_key() {
    let f = Fixture::load("real-apple.json");
    let (x, y) = leaf_key(&f, false, MAC_REAL.3);
    let check = |auth: &[u8], aaguid: &[u8; 16]| authdata::check(&Native, auth, aaguid, true, &x, &y, 3);
    check(&f.auth, &f.aaguid).unwrap();

    let mut a = f.auth.clone();
    a[55] ^= 1; // credential ID
    assert_eq!(err(check(&a, &f.aaguid)), "credential key");
    let mut a = f.auth.clone();
    a[87 + 10] ^= 1; // first byte of the COSE x coordinate
    assert_eq!(err(check(&a, &f.aaguid)), "COSE key");
    let mut other = f.aaguid;
    other[0] ^= 1;
    assert_eq!(err(check(&f.auth, &other)), "AAGUID/credential length");
    let mut a = f.auth.clone();
    a[36] = 1; // an enrollment starts at counter zero
    assert_eq!(err(check(&a, &f.aaguid)), "enrollment flags/counter");
}

#[test]
fn size_flags_and_category_are_checked() {
    let f = Fixture::load("real-apple.json");
    let (x, y) = leaf_key(&f, false, MAC_REAL.3);
    let check = |auth: &[u8], category| authdata::check(&Native, auth, &f.aaguid, true, &x, &y, category);
    assert_eq!(err(check(&f.auth[..36], 3)), "auth size");
    let mut a = f.auth.clone();
    a[32] &= !0x80; // user verification flag cleared
    assert_eq!(err(check(&a, 3)), "auth flags");
    assert_eq!(err(check(&f.auth, 4)), "validation category");
    let mut a = f.auth.clone();
    a.push(0);
    assert_eq!(err(check(&a, 3)), "auth trailing data");
}

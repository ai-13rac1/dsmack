//! Tests of the intermediate and leaf certificate parsers against Apple's fixtures.
//! near/test.sh sets `DSMACK_DIR`.

mod common;
use common::*;
use dsmack_attest_core::intermediate::{self, APPLE_ROOT_KEY};
use dsmack_attest_core::leaf::{self, IOS_ACL, MAC_ACL};
use dsmack_attest_core::Crypto;

const REAL_TIME: u64 = 1_789_567_200;

// Validity of the fixtures, from `openssl x509 -dates`, as Unix seconds.
const CA_NOT_BEFORE: u64 = 1_584_556_795;
const CA_NOT_AFTER: u64 = 1_899_590_400; // 2030-03-13 00:00:00 UTC
const LEAF_NOT_BEFORE: u64 = 1_789_492_238;
const LEAF_NOT_AFTER: u64 = 1_789_751_438;

fn apple_ca() -> intermediate::Intermediate {
    intermediate::endorse(&Native, &APPLE_ROOT_KEY, &read("apple-intermediate.der"), REAL_TIME).unwrap()
}

fn parse_leaf(f: &Fixture, ca: &intermediate::Intermediate, acl: &[u8], now: u64) -> dsmack_attest_core::Result<leaf::Parsed> {
    leaf::parse(&Native, &f.cert, &ca.subject, &f.nonce(), acl, now)
}

#[test]
fn the_root_endorses_the_apple_intermediate() {
    let ca = apple_ca();
    assert_eq!(
        hex::encode(ca.key),
        "ae5b37a0774d79b2358f40e7d1f22626f1c25fef17802deab3826a59874ff8d2ad1525789aa26604191248b63cb96706\
         9e98d363bd5e370fbfa08e329e8073a985e7746ea359a2f66f29db32af455e211658d567af9e267eb2614dc21a66ce99"
    );
    assert_eq!((ca.not_before, ca.not_after), (CA_NOT_BEFORE, CA_NOT_AFTER));
    // The identifier is the one that the Solidity AppleEndorsements uses.
    assert_eq!(hex::encode(ca.id(&Native)), "b4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90");
}

#[test]
fn only_the_apple_root_endorses() {
    let der = read("apple-intermediate.der");
    let mut changed = der.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(err(intermediate::endorse(&Native, &APPLE_ROOT_KEY, &changed, REAL_TIME)), "root certificate signature");
    assert_eq!(err(intermediate::endorse(&Native, &rotation_root(), &der, REAL_TIME)), "root certificate signature");
}

#[test]
fn rotation_intermediates_share_a_subject_and_differ_in_key() {
    let root = rotation_root();
    let ca2 = intermediate::endorse(&Native, &root, &read("rotation/ca2.der"), REAL_TIME).unwrap();
    let ca3 = intermediate::endorse(&Native, &root, &read("rotation/ca3.der"), REAL_TIME).unwrap();
    assert_eq!(ca2.subject, ca3.subject);
    assert_ne!(ca2.key, ca3.key);
    assert_ne!(ca2.id(&Native), ca3.id(&Native));
}

#[test]
fn intermediate_validity_is_inclusive() {
    let der = read("apple-intermediate.der");
    for (now, ok) in [(CA_NOT_BEFORE - 1, false), (CA_NOT_BEFORE, true), (CA_NOT_AFTER, true), (CA_NOT_AFTER + 1, false)] {
        let r = intermediate::parse(&Native, &der, now);
        assert_eq!(r.is_ok(), ok, "{now}");
        if !ok {
            assert_eq!(err(r), "certificate validity");
        }
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let f = Fixture::load("real-apple.json");
    let ca = apple_ca();
    let mut der = read("apple-intermediate.der");
    der.push(0);
    assert_eq!(err(intermediate::parse(&Native, &der, REAL_TIME)), "certificate trailing");
    let mut cert = f.cert.clone();
    cert.push(0);
    let r = leaf::parse(&Native, &cert, &ca.subject, &f.nonce(), MAC_ACL, REAL_TIME);
    assert_eq!(err(r), "certificate trailing");
}

#[test]
fn the_leaf_carries_the_attested_key() {
    let f = Fixture::load("real-apple.json");
    let l = parse_leaf(&f, &apple_ca(), MAC_ACL, REAL_TIME).unwrap();
    assert_eq!(l.expires, LEAF_NOT_AFTER);
    // The credential ID is the SHA-256 of the uncompressed point.
    let mut point = vec![4u8];
    point.extend_from_slice(&l.x);
    point.extend_from_slice(&l.y);
    assert_eq!(Native.sha256(&point), f.kid);
}

#[test]
fn the_intermediate_signs_the_leaf() {
    let f = Fixture::load("real-apple.json");
    let ca = apple_ca();
    let l = parse_leaf(&f, &ca, MAC_ACL, REAL_TIME).unwrap();
    assert!(Native.p384_verify_prehash(&ca.key, &l.tbs_hash, &l.sig));
    let mut cert = f.cert.clone();
    *cert.last_mut().unwrap() ^= 1;
    let changed = leaf::parse(&Native, &cert, &ca.subject, &f.nonce(), MAC_ACL, REAL_TIME).unwrap();
    assert!(!Native.p384_verify_prehash(&ca.key, &changed.tbs_hash, &changed.sig));
}

#[test]
fn the_leaf_binds_nonce_issuer_and_key_acl() {
    let f = Fixture::load("real-apple.json");
    let ca = apple_ca();
    let r = leaf::parse(&Native, &f.cert, &ca.subject, &[0; 32], MAC_ACL, REAL_TIME);
    assert_eq!(err(r), "certificate nonce");
    let r = leaf::parse(&Native, &f.cert, &[0; 32], &f.nonce(), MAC_ACL, REAL_TIME);
    assert_eq!(err(r), "issuer name");
    assert_eq!(err(parse_leaf(&f, &ca, IOS_ACL, REAL_TIME)), "key ACL");
    let phone = Fixture::load("iphone-apple.json");
    let r = parse_leaf(&phone, &ca, MAC_ACL, 1_790_200_000);
    assert_eq!(err(r), "key ACL");
    parse_leaf(&phone, &ca, IOS_ACL, 1_790_200_000).unwrap();
}

#[test]
fn leaf_validity_is_inclusive() {
    let f = Fixture::load("real-apple.json");
    let ca = apple_ca();
    for (now, ok) in [(LEAF_NOT_BEFORE - 1, false), (LEAF_NOT_BEFORE, true), (LEAF_NOT_AFTER, true), (LEAF_NOT_AFTER + 1, false)] {
        let r = parse_leaf(&f, &ca, MAC_ACL, now);
        assert_eq!(r.is_ok(), ok, "{now}");
        if !ok {
            assert_eq!(err(r), "certificate validity");
        }
    }
}

#[test]
fn scalars_stay_below_the_group_order() {
    let n = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973").unwrap();
    let mut s: [u8; 48] = n.try_into().unwrap();
    assert_eq!(err(intermediate::scalar(&s)), "scalar range");
    s[47] -= 1;
    intermediate::scalar(&s).unwrap();
    assert_eq!(err(intermediate::scalar(&[0; 48])), "zero scalar");
}

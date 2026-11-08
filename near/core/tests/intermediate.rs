//! Port of dsmack `app-attest/contracts/test/Intermediate.t.sol`.
//! Run with `DSMACK_DIR` set to a dsmack checkout.

mod common;
use common::*;
use dsmack_attest_core::attest::Platform;
use dsmack_attest_core::der;
use std::cell::RefCell;
use std::collections::HashMap;

const REAL_TIME: u64 = 1_789_567_200;
const FRESH_TIME: u64 = 1_789_588_800;
const SUBJECT: &str = "b4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90";

fn setup() -> (Fixture, Model, [u8; 32], Vec<u8>) {
    let f = Fixture::load("real-apple.json");
    let (m, id) = Model::mac(&f, 3, false, REAL_TIME).with_apple_intermediate();
    (f, m, id, read("apple-intermediate.der"))
}

/// Change the byte at `offset` from the first match of `needle` to `value`.
fn changed(mut b: Vec<u8>, needle: &[u8], offset: usize, value: u8) -> Vec<u8> {
    let i = b.windows(needle.len()).position(|w| w == needle).expect("mutation not found");
    b[i + offset] = value;
    b
}

fn rotation(f: &Fixture, now: u64) -> Model {
    Model {
        platform: Platform { aaguid: f.aaguid, category: 3, ios: false },
        admit: Admit::Open,
        root: rotation_root(),
        intermediates: HashMap::new(),
        keys: RefCell::new(HashMap::new()),
        now,
    }
}

#[test]
fn endorse_real() {
    let (_, mut m, id, ca) = setup();
    assert_eq!(hex::encode(id), SUBJECT);
    assert_eq!(err(m.endorse(&ca)), "already endorsed");
    let c = &m.intermediates[&id];
    assert_eq!(
        hex::encode(c.key),
        "ae5b37a0774d79b2358f40e7d1f22626f1c25fef17802deab3826a59874ff8d2ad1525789aa26604191248b63cb96706\
         9e98d363bd5e370fbfa08e329e8073a985e7746ea359a2f66f29db32af455e211658d567af9e267eb2614dc21a66ce99"
    );
    assert!(c.not_before <= m.now && c.not_after >= m.now);
}

#[test]
fn root_signature() {
    let (_, mut m, _, mut ca) = setup();
    m.intermediates.clear();
    *ca.last_mut().unwrap() ^= 1;
    assert_eq!(err(m.endorse(&ca)), "root certificate signature");
}

fn reject(ca: Vec<u8>, reason: &str) {
    let (_, mut m, _, _) = setup();
    m.intermediates.clear();
    assert_eq!(err(m.endorse(&ca)), reason);
}

#[test]
fn algorithm() {
    let (_, _, _, mut ca) = setup();
    let outer = der::expect(&ca, 0, ca.len(), 0x30).unwrap();
    let tbs = der::expect(&ca, outer.body, outer.end, 0x30).unwrap();
    let alg = der::expect(&ca, tbs.end, outer.end, 0x30).unwrap();
    ca[alg.end - 1] = 0x02;
    reject(ca, "signature algorithm");
}

#[test]
fn inner_algorithm() {
    let (_, _, _, ca) = setup();
    reject(changed(ca, &hex::decode("300a06082a8648ce3d040303").unwrap(), 11, 0x02), "inner signature algorithm");
}

#[test]
fn non_ca() {
    let (_, _, _, ca) = setup();
    reject(changed(ca, &hex::decode("30060101ff020100").unwrap(), 4, 0), "CA constraints");
}

#[test]
fn usage() {
    let (_, _, _, ca) = setup();
    reject(changed(ca, &hex::decode("03020106").unwrap(), 3, 4), "CA usage");
}

#[test]
fn constraints_critical() {
    let (_, _, _, ca) = setup();
    reject(changed(ca, &hex::decode("0603551d130101ff").unwrap(), 7, 0), "critical encoding");
}

#[test]
fn usage_critical() {
    let (_, _, _, ca) = setup();
    reject(changed(ca, &hex::decode("0603551d0f0101ff").unwrap(), 7, 0), "critical encoding");
}

#[test]
fn spki() {
    let (_, _, _, ca) = setup();
    reject(changed(ca, &hex::decode("06052b81040022").unwrap(), 6, 0x23), "P384 SPKI");
}

#[test]
fn point_encoding() {
    let (_, _, _, ca) = setup();
    reject(changed(ca, &hex::decode("03620004").unwrap(), 3, 2), "public key encoding");
}

#[test]
fn expired_and_future() {
    let (_, mut m, id, ca) = setup();
    let (before, after) = (m.intermediates[&id].not_before, m.intermediates[&id].not_after);
    m.intermediates.clear();
    m.now = after + 1;
    assert_eq!(err(m.endorse(&ca)), "certificate validity");
    m.now = before - 1;
    assert_eq!(err(m.endorse(&ca)), "certificate validity");
}

#[test]
fn trailing() {
    let (_, _, _, mut ca) = setup();
    ca.push(0);
    reject(ca, "certificate trailing");
}

#[test]
fn no_endorsement() {
    let (f, m, _, _) = setup();
    assert_eq!(err(m.enroll(&[0; 32], &f.cert, &f.auth, &f.client_data)), "intermediate validity");
}

#[test]
fn issuer_mismatch() {
    let (f, m, id, _) = setup();
    let cert = changed(f.cert.clone(), b"Apple App Attestation CA 1", 0, 0x42);
    assert_eq!(err(m.enroll(&id, &cert, &f.auth, &f.client_data)), "issuer name");
}

#[test]
fn expired_and_future_endorsement() {
    let (f, _, _, _) = setup();
    let mut r = rotation(&f, REAL_TIME);
    let id = r.endorse(&read("rotation/ca2.der")).unwrap();
    let (start, end) = (r.intermediates[&id].not_before, r.intermediates[&id].not_after);
    r.now = end + 1;
    assert_eq!(err(r.enroll(&id, &f.cert, &f.auth, &f.client_data)), "intermediate validity");
    r.now = start - 1;
    assert_eq!(err(r.enroll(&id, &f.cert, &f.auth, &f.client_data)), "intermediate validity");
}

#[test]
fn same_subject_wrong_key() {
    let (f, _, _, _) = setup();
    let mut r = rotation(&f, REAL_TIME);
    let a = r.endorse(&read("rotation/ca2.der")).unwrap();
    let b = r.endorse(&read("rotation/ca3.der")).unwrap();
    assert_ne!(a, b);
    assert_eq!(r.intermediates[&a].subject, r.intermediates[&b].subject);
    assert_eq!(err(r.enroll(&b, &read("rotation/leaf2.der"), &f.auth, &f.client_data)), "Apple certificate signature");
}

#[test]
fn rotation_keeps_earlier_endorsements() {
    let (f, _, _, _) = setup();
    let mut r = rotation(&f, REAL_TIME);
    let s2 = r.endorse(&read("rotation/ca2.der")).unwrap();
    assert_eq!(r.enroll(&s2, &read("rotation/leaf2.der"), &f.auth, &f.client_data).unwrap(), f.kid);
    let prior = r.intermediates[&s2].clone();
    assert_eq!(err(r.endorse(&read("rotation/ca2-reissued.der"))), "already endorsed");
    assert_eq!(r.intermediates[&s2], prior);
    let s3 = r.endorse(&read("rotation/ca3.der")).unwrap();
    assert_ne!(s2, s3);
    assert_eq!(r.intermediates[&s2], prior);
    assert_eq!(r.intermediates[&s2].subject, r.intermediates[&s3].subject);
    let current = r.intermediates[&s3].clone();
    r.now = FRESH_TIME;
    let fresh = Fixture::load("fresh-apple.json");
    assert_eq!(r.enroll(&s3, &read("rotation/leaf3.der"), &fresh.auth, &fresh.client_data).unwrap(), fresh.kid);
    assert_eq!(r.intermediates[&s2], prior);
    assert_eq!(r.intermediates[&s3], current);
}

#[test]
fn after_2030_enrollment_and_assertion() {
    let (f, _, _, _) = setup();
    let mut r = rotation(&f, 1_938_297_600);
    let id = r.endorse(&read("rotation/ca5.der")).unwrap();
    let fresh = Fixture::load("fresh-apple.json");
    assert_eq!(r.enroll(&id, &read("rotation/leaf5.der"), &fresh.auth, &fresh.client_data).unwrap(), fresh.kid);
    let (auth, ctx, rr, s) = fresh.assertion("assert");
    assert_eq!(r.verify(&fresh.kid, &auth, &ctx, &rr, &s).unwrap().cdhash, fresh.cdhash);
    r.now = 2_373_148_801;
    assert_eq!(err(r.verify(&fresh.kid, &auth, &[0; 32], &rr, &s)), "key validity");
}

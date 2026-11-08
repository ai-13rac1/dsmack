//! Port of dsmack `app-attest/contracts/test/MacAppAttestV1.t.sol`.
//! Run with `DSMACK_DIR` set to a dsmack checkout.

mod common;
use common::*;

const REAL_TIME: u64 = 1_789_567_200;
const FRESH_TIME: u64 = 1_789_588_800;
const IPHONE_TIME: u64 = 1_790_200_000;

fn real() -> (Fixture, Model, [u8; 32]) {
    let f = Fixture::load("real-apple.json");
    let (m, id) = Model::mac(&f, 3, false, REAL_TIME).with_apple_intermediate();
    (f, m, id)
}

fn fresh() -> (Fixture, Model, [u8; 32]) {
    let f = Fixture::load("fresh-apple.json");
    let (m, id) = Model::mac(&f, 3, false, FRESH_TIME).with_apple_intermediate();
    m.enroll(&id, &f.cert, &f.auth, &f.client_data).unwrap();
    (f, m, id)
}

fn iphone() -> (Fixture, Model, [u8; 32]) {
    let f = Fixture::load("iphone-apple.json");
    let (m, id) = Model::mac(&f, 5, true, IPHONE_TIME).with_apple_intermediate();
    (f, m, id)
}

#[test]
fn intermediate_id_matches_foundry() {
    let (_, _, id) = real();
    assert_eq!(hex::encode(id), "b4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90");
}

#[test]
fn real_apple_enrollment() {
    let (f, m, id) = real();
    assert_eq!(m.enroll(&id, &f.cert, &f.auth, &f.client_data).unwrap(), f.kid);
    assert_eq!(m.counter(&f.kid), 0);
}

#[test]
fn fresh_hardware_assertions_and_modified_code() {
    let (f, m, _) = fresh();
    let (auth, ctx, r, s) = f.assertion("assert");
    let a = m.verify(&f.kid, &auth, &ctx, &r, &s).unwrap();
    assert_eq!((a.counter, a.cdhash, a.rp), (1, f.cdhash, f.app_hash));
    assert_eq!(err(m.verify(&f.kid, &auth, &ctx, &r, &s)), "assertion replay");
    let (auth, ctx, r, s) = f.assertion("modified");
    assert_eq!(err(m.verify(&f.kid, &auth, &ctx, &r, &s)), "current CDHash");
    let (auth, ctx, r, s) = f.assertion("restored");
    assert_eq!(m.verify(&f.kid, &auth, &ctx, &r, &s).unwrap().counter, 3);
    assert_eq!(m.counter(&f.kid), 3);
}

#[test]
fn fresh_hardware_wrong_context_rejected() {
    let (f, m, _) = fresh();
    let (auth, mut ctx, r, s) = f.assertion("assert");
    ctx[31] ^= 1;
    assert_eq!(err(m.verify(&f.kid, &auth, &ctx, &r, &s)), "assertion signature");
    assert_eq!(m.counter(&f.kid), 0);
}

#[test]
fn fresh_hardware_cannot_reset_counter_by_reenrolling() {
    let (f, m, id) = fresh();
    assert_eq!(err(m.enroll(&id, &f.cert, &f.auth, &f.client_data)), "already enrolled");
}

#[test]
fn expired_certificate_rejected() {
    let (f, mut m, id) = real();
    m.now = 1_790_000_000;
    assert_eq!(err(m.enroll(&id, &f.cert, &f.auth, &f.client_data)), "certificate validity");
}

#[test]
fn wrong_nonce_rejected() {
    let (f, m, id) = real();
    assert_eq!(err(m.enroll(&id, &f.cert, &f.auth, &[0])), "certificate nonce");
}

#[test]
fn tampered_signature_rejected() {
    let (f, m, id) = real();
    let mut cert = f.cert.clone();
    *cert.last_mut().unwrap() ^= 1;
    assert_eq!(err(m.enroll(&id, &cert, &f.auth, &f.client_data)), "Apple certificate signature");
}

#[test]
fn trailing_certificate_rejected() {
    let (f, m, id) = real();
    let mut cert = f.cert.clone();
    cert.push(0);
    assert_eq!(err(m.enroll(&id, &cert, &f.auth, &f.client_data)), "certificate trailing");
}

#[test]
fn wrong_validation_category_rejected() {
    let f = Fixture::load("real-apple.json");
    let (m, id) = Model::mac(&f, 4, false, REAL_TIME).with_apple_intermediate();
    assert_eq!(err(m.enroll(&id, &f.cert, &f.auth, &f.client_data)), "validation category");
}

#[test]
fn iphone_enrollment_and_assertions() {
    let (f, m, id) = iphone();
    assert_eq!(m.enroll(&id, &f.cert, &f.auth, &f.client_data).unwrap(), f.kid);
    let (auth, ctx, r, s) = f.assertion("assert");
    let a = m.verify(&f.kid, &auth, &ctx, &r, &s).unwrap();
    assert_eq!((a.counter, a.cdhash, a.rp), (1, f.cdhash, f.app_hash));
    let (auth, ctx, r, s) = f.assertion("modified");
    assert_eq!(err(m.verify(&f.kid, &auth, &ctx, &r, &s)), "current CDHash");
    assert_eq!(m.counter(&f.kid), 1);
}

#[test]
fn iphone_tampered_cdhash_rejected() {
    let (f, m, id) = iphone();
    m.enroll(&id, &f.cert, &f.auth, &f.client_data).unwrap();
    let (mut auth, ctx, r, s) = f.assertion("assert");
    auth[70] ^= 1;
    assert_eq!(err(m.verify(&f.kid, &auth, &ctx, &r, &s)), "current CDHash");
}

#[test]
fn iphone_evidence_rejected_under_mac_acl() {
    let f = Fixture::load("iphone-apple.json");
    let (m, id) = Model::mac(&f, 5, false, IPHONE_TIME).with_apple_intermediate();
    assert_eq!(err(m.enroll(&id, &f.cert, &f.auth, &f.client_data)), "key ACL");
}

#[test]
fn mac_evidence_rejected_under_ios_acl() {
    let f = Fixture::load("real-apple.json");
    let (m, id) = Model::mac(&f, 3, true, REAL_TIME).with_apple_intermediate();
    assert_eq!(err(m.enroll(&id, &f.cert, &f.auth, &f.client_data)), "key ACL");
}

#[test]
fn signature_covers_the_assertion_data() {
    let (f, m, _) = fresh();
    let (mut auth, ctx, r, s) = f.assertion("assert");
    auth[36] ^= 0x10; // another counter that is still above the stored one
    assert_eq!(err(m.verify(&f.kid, &auth, &ctx, &r, &s)), "assertion signature");
}

// Validity of the real leaf, from `openssl x509 -dates`, as Unix seconds.
const LEAF_NOT_BEFORE: u64 = 1_789_492_238;
const LEAF_NOT_AFTER: u64 = 1_789_751_438;

#[test]
fn enrollment_validity_is_inclusive() {
    for (now, ok) in [
        (LEAF_NOT_BEFORE - 1, false),
        (LEAF_NOT_BEFORE, true),
        (LEAF_NOT_AFTER, true),
        (LEAF_NOT_AFTER + 1, false),
    ] {
        let (f, mut m, id) = real();
        m.now = now;
        let r = m.enroll(&id, &f.cert, &f.auth, &f.client_data);
        if ok {
            r.unwrap();
        } else {
            assert_eq!(err(r), "certificate validity");
        }
    }
}

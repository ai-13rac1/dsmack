//! Shared test code: RustCrypto primitives and the Apple fixtures of this repository.
#![allow(dead_code)]

use dsmack_attest_core::{Crypto, Result};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256, Sha384};

pub struct Native;

impl Crypto for Native {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }
    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        Sha384::digest(data).into()
    }
    fn p384_verify_prehash(&self, pub_xy: &[u8; 96], prehash: &[u8], sig: &[u8; 96]) -> bool {
        let mut sec1 = [0u8; 97];
        sec1[0] = 4;
        sec1[1..].copy_from_slice(pub_xy);
        let Ok(k) = p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else { return false };
        let Ok(s) = p384::ecdsa::Signature::from_slice(sig) else { return false };
        k.verify_prehash(prehash, &s).is_ok()
    }
    fn p256_verify(&self, sig: &[u8; 64], prehash: &[u8; 32], pub33: &[u8; 33]) -> bool {
        let Ok(k) = p256::ecdsa::VerifyingKey::from_sec1_bytes(pub33) else { return false };
        let Ok(s) = p256::ecdsa::Signature::from_slice(sig) else { return false };
        k.verify_prehash(prehash, &s).is_ok()
    }
}

/// The root key that dsmack's rotation test CAs are signed with.
pub fn rotation_root() -> [u8; 96] {
    let h = "283c1d7365ce4788f29f8ebf234edffead6fe997fbea5ffa2d58cc9dfa7b1c508b05526f55b9ebb2040f05b48fb6d0e1\
             9475c99061e41b88ba52efdb8c1690471a61d867ed799729d9c92cd01dbd225630d84ede32a78f9e64664cdac512ef8c";
    hex::decode(h).unwrap().try_into().unwrap()
}

/// The Apple fixtures. `DSMACK_DIR` is the root of this repository; near/test.sh sets it.
pub fn fixtures() -> std::path::PathBuf {
    let dir = std::env::var("DSMACK_DIR").expect("DSMACK_DIR is the root of the dsmack repository");
    std::path::Path::new(&dir).join("app-attest/contracts/fixtures")
}

pub fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn hx(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

pub fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().unwrap()
}

pub struct Fixture {
    pub json: serde_json::Value,
    pub cert: Vec<u8>,
    pub auth: Vec<u8>,
    pub client_data: Vec<u8>,
    pub kid: [u8; 32],
    pub app_hash: [u8; 32],
    pub cdhash: [u8; 32],
    pub aaguid: [u8; 16],
}

impl Fixture {
    pub fn load(name: &str) -> Fixture {
        let json: serde_json::Value = serde_json::from_slice(&read(name)).unwrap();
        Fixture {
            cert: hx(&json["cert"]),
            auth: hx(&json["auth"]),
            client_data: hx(&json["clientData"]),
            kid: arr(&hx(&json["kid"])),
            app_hash: arr(&hx(&json["appHash"])),
            cdhash: arr(&hx(&json["cdhash"])),
            aaguid: arr(&hx(&json["aaguid"])),
            json,
        }
    }

    /// The assertion `name`: authenticator data, context (the SHA-256 of the signed
    /// context bytes), r and s.
    pub fn assertion(&self, name: &str) -> (Vec<u8>, [u8; 32], [u8; 32], [u8; 32]) {
        let a = &self.json[name];
        let context = Native.sha256(&hx(&a["context"]));
        (hx(&a["auth"]), context, arr(&hx(&a["r"])), arr(&hx(&a["s"])))
    }

    /// The nonce that Apple puts in the leaf certificate: SHA-256 of the authenticator
    /// data and the SHA-256 of the client data.
    pub fn nonce(&self) -> [u8; 32] {
        let mut input = self.auth.clone();
        input.extend_from_slice(&Native.sha256(&self.client_data));
        Native.sha256(&input)
    }
}

pub fn err<T: std::fmt::Debug>(r: Result<T>) -> &'static str {
    r.expect_err("expected an error").0
}

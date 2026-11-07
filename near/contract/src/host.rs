//! The core crate's primitives, on NEAR host functions and WASM code.

use dsmack_attest_core::Crypto;
use near_sdk::env;
use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest, Sha384};

pub struct Host;

impl Crypto for Host {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        env::sha256_array(data)
    }

    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        Sha384::digest(data).into()
    }

    fn keccak256(&self, data: &[u8]) -> [u8; 32] {
        env::keccak256_array(data)
    }

    fn p384_verify_prehash(&self, pub_xy: &[u8; 96], prehash: &[u8], sig: &[u8; 96]) -> bool {
        let mut sec1 = [0u8; 97];
        sec1[0] = 4;
        sec1[1..].copy_from_slice(pub_xy);
        let Ok(key) = VerifyingKey::from_sec1_bytes(&sec1) else { return false };
        let Ok(sig) = Signature::from_slice(sig) else { return false };
        key.verify_prehash(prehash, &sig).is_ok()
    }

    fn p256_verify(&self, sig: &[u8; 64], prehash: &[u8; 32], pub33: &[u8; 33]) -> bool {
        env::p256_verify(sig, prehash, pub33)
    }
}

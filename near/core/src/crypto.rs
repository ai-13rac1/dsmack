/// The primitives that the checks need. The contract implements them with NEAR
/// host functions and WASM code; tests implement them with RustCrypto.
pub trait Crypto {
    fn sha256(&self, data: &[u8]) -> [u8; 32];
    fn sha384(&self, data: &[u8]) -> [u8; 48];
    fn keccak256(&self, data: &[u8]) -> [u8; 32];
    /// ECDSA P-384 over a prehash. `pub_xy` is x then y, 48 bytes each; `sig` is r then s.
    fn p384_verify_prehash(&self, pub_xy: &[u8; 96], prehash: &[u8], sig: &[u8; 96]) -> bool;
    /// ECDSA P-256 over a 32-byte prehash. `pub33` is a compressed point; `sig` is r then s.
    fn p256_verify(&self, sig: &[u8; 64], prehash: &[u8; 32], pub33: &[u8; 33]) -> bool;
}

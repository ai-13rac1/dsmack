//! Apple App Attest checks. A port of the dsmack Solidity verifier
//! (`app-attest/contracts/src`). Every check returns the same message as the
//! Solidity `require` that it replaces.

pub mod attest;
pub mod authdata;
pub mod crypto;
pub mod der;
pub mod error;
pub mod ext;
pub mod intermediate;
pub mod leaf;

pub use crypto::Crypto;
pub use error::{Error, Result};

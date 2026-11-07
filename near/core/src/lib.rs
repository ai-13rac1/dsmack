//! Apple App Attest checks. A port of the dsmack Solidity verifier
//! (`app-attest/contracts/src`). Every check returns the same message as the
//! Solidity `require` that it replaces.

pub mod der;
pub mod error;

pub use error::{Error, Result};

//! Example consumer. A contract that needs "this message comes from an approved Mac
//! program" calls `verify` on the dsmack-near contract and reads the result in a callback.
//! The assertion counter lives in dsmack-near under this contract's account, so the
//! context that the app asserts commits to this contract, the receiver and the action.

use near_sdk::json_types::Base64VecU8;
use near_sdk::{env, ext_contract, near, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError};

#[near(serializers = [json])]
pub struct Proof {
    pub kid: Base64VecU8,
    pub auth: Base64VecU8,
    pub r: Base64VecU8,
    pub s: Base64VecU8,
}

/// The result of `verify`.
#[near(serializers = [json])]
pub struct Verified {
    pub kid: Base64VecU8,
    pub cdhash: Base64VecU8,
    pub rp: Base64VecU8,
    pub counter: u32,
}

/// The context of an action: it commits to this contract, the receiver and the action.
#[cfg(not(feature = "fixture-context"))]
fn context(receiver: &AccountId, action: &[u8]) -> Vec<u8> {
    let data = near_sdk::borsh::to_vec(&(env::current_account_id(), receiver, action)).unwrap();
    env::sha256(&data)
}

/// Test builds only: the action is the context, so that the tests can use the fixed
/// contexts of Apple's fixtures.
#[cfg(feature = "fixture-context")]
fn context(_receiver: &AccountId, action: &[u8]) -> Vec<u8> {
    action.to_vec()
}

#[ext_contract(ext_dsmack)]
pub trait Dsmack {
    fn verify(&mut self, context: Base64VecU8, proof: Proof) -> Verified;
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Consumer {
    dsmack: AccountId,
    last_kid: Option<Base64VecU8>,
}

#[near]
impl Consumer {
    #[private]
    #[init]
    pub fn new(dsmack: AccountId) -> Self {
        Self { dsmack, last_kid: None }
    }

    /// The context that the app asserts for `action` by `receiver`: the SHA-256 of the
    /// borsh encoding of (this contract's account ID, `receiver`, `action`). The app
    /// passes it to `generateAssertion` as the `clientDataHash`.
    pub fn context_of(&self, receiver: AccountId, action: Base64VecU8) -> Base64VecU8 {
        Base64VecU8(context(&receiver, &action.0))
    }

    /// Ask dsmack-near to verify an assertion over `context_of(caller, action)`. The
    /// caller receives the result of the action. Another account that sends a copy of
    /// the proof gets a different context, so the check fails for it.
    ///
    /// The attached deposit pays the storage of a first assertion by a key. A failed
    /// check sends the deposit back to the caller; after a successful check dsmack-near
    /// returns the unused part to this contract.
    #[payable]
    pub fn check(&mut self, action: Base64VecU8, proof: Proof) -> Promise {
        let user = env::predecessor_account_id();
        let deposit = env::attached_deposit();
        ext_dsmack::ext(self.dsmack.clone())
            .with_attached_deposit(deposit)
            .with_static_gas(Gas::from_tgas(60))
            .verify(Base64VecU8(context(&user, &action.0)), proof)
            .then(Self::ext(env::current_account_id()).with_static_gas(Gas::from_tgas(10)).on_verified(user, deposit))
    }

    #[private]
    pub fn on_verified(
        &mut self,
        user: AccountId,
        deposit: NearToken,
        #[callback_result] result: Result<Verified, PromiseError>,
    ) -> bool {
        match result {
            Ok(v) => {
                self.last_kid = Some(v.kid);
                true
            }
            Err(_) => {
                Promise::new(user).transfer(deposit).detach();
                false
            }
        }
    }

    pub fn last_kid(&self) -> Option<Base64VecU8> {
        self.last_kid.clone()
    }
}

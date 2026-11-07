//! Example consumer. A contract that needs "this message comes from an approved Mac
//! program" calls `verify` on the dsmack-near contract and reads the key ID in a callback.
//! The assertion counter lives in dsmack-near under this contract's account.

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

    /// Ask dsmack-near to verify the assertion. The attached deposit pays the storage
    /// of a first assertion by a key. A failed check sends the deposit back to the
    /// caller; after a successful check dsmack-near returns the unused part to this contract.
    ///
    /// This example takes `context` from the caller so that the tests can use Apple's
    /// fixtures. An assertion is fresh once for each consumer account, so a real consumer
    /// derives `context` on chain from its own account ID and the action.
    #[payable]
    pub fn check(&mut self, context: Base64VecU8, proof: Proof) -> Promise {
        let user = env::predecessor_account_id();
        let deposit = env::attached_deposit();
        ext_dsmack::ext(self.dsmack.clone())
            .with_attached_deposit(deposit)
            .with_static_gas(Gas::from_tgas(60))
            .verify(context, proof)
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
                let _ = Promise::new(user).transfer(deposit);
                false
            }
        }
    }

    pub fn last_kid(&self) -> Option<Base64VecU8> {
        self.last_kid.clone()
    }
}

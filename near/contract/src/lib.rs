//! NEAR contract for Apple App Attest. Port of dsmack's `AppleEndorsements`,
//! `AppleAttestRegistryV1` and `CDRegistry` as one contract, so that the policy
//! check on every enrollment and assertion stays synchronous.
//!
//! Enrollment is global. Assertion counters and evidence belong to the calling
//! account, so one deployment serves many consumers and a caller cannot use up the
//! counter of another.

mod host;

use dsmack_attest_core::attest::{self, Key, Platform, Policy};
use dsmack_attest_core::intermediate::{self, Intermediate, APPLE_ROOT_KEY};
use dsmack_attest_core::{registry, Error};
use host::Host;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::Base64VecU8;
use near_sdk::store::{LookupMap, LookupSet};
use near_sdk::{env, near, AccountId, NearToken, PanicOnDefault, Promise};

type B32 = [u8; 32];

#[derive(BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
struct StoredIntermediate {
    subject: B32,
    key: [u8; 96],
    not_before: u64,
    not_after: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
struct StoredKey {
    x: B32,
    y: B32,
    expires: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone)]
#[borsh(crate = "near_sdk::borsh")]
struct StoredEvidence {
    context: B32,
    cdhash: B32,
    rp: B32,
    checked_at: u64,
    counter: u32,
}

#[derive(BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
struct StoredBuild {
    build: B32,
    rp: B32,
    team: B32,
    bundle: B32,
}

#[near(serializers = [json])]
pub struct Proof {
    pub kid: Base64VecU8,
    pub auth: Base64VecU8,
    pub r: Base64VecU8,
    pub s: Base64VecU8,
}

#[near(serializers = [json])]
pub struct KeyView {
    pub x: Base64VecU8,
    pub y: Base64VecU8,
    pub expires: u64,
}

#[near(serializers = [json])]
pub struct EvidenceView {
    pub context: Base64VecU8,
    pub cdhash: Base64VecU8,
    pub rp: Base64VecU8,
    pub checked_at: u64,
    pub counter: u32,
}

#[near(serializers = [json])]
pub struct IntermediateView {
    pub subject: Base64VecU8,
    pub key: Base64VecU8,
    pub not_before: u64,
    pub not_after: u64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Dsmack {
    owner: AccountId,
    aaguid: [u8; 16],
    category: u32,
    ios: bool,
    intermediates: LookupMap<B32, StoredIntermediate>,
    keys: LookupMap<B32, StoredKey>,
    evidence: LookupMap<(AccountId, B32), StoredEvidence>,
    build_id: B32,
    approved: LookupSet<B32>,
    builds: LookupMap<B32, StoredBuild>,
}

fn check<T>(r: Result<T, Error>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => env::panic_str(e.0),
    }
}

fn fixed<const N: usize>(b: &Base64VecU8, what: &str) -> [u8; N] {
    match <[u8; N]>::try_from(b.0.as_slice()) {
        Ok(a) => a,
        Err(_) => env::panic_str(&format!("{what} must be {N} bytes")),
    }
}

#[cfg(not(feature = "fixture-clock"))]
fn now() -> u64 {
    env::block_timestamp() / 1_000_000_000
}

#[cfg(feature = "fixture-clock")]
fn now() -> u64 {
    match env::storage_read(b"fixture-clock") {
        Some(b) => u64::from_le_bytes(b.try_into().unwrap()),
        None => env::block_timestamp() / 1_000_000_000,
    }
}

/// Charge the storage that a call added to the deposit that came with it and send
/// the rest back to the caller. The caller flushes the collections that it changed
/// first: the store collections cache writes, and `storage_usage` does not count them.
fn settle(storage_before: u64) {
    let used = env::storage_usage().saturating_sub(storage_before) as u128;
    let cost = env::storage_byte_cost().as_yoctonear().saturating_mul(used);
    let deposit = env::attached_deposit().as_yoctonear();
    if deposit < cost {
        env::panic_str(&format!("attach {cost} yoctoNEAR for storage"));
    }
    if deposit > cost {
        let _ = Promise::new(env::predecessor_account_id()).transfer(NearToken::from_yoctonear(deposit - cost));
    }
}

/// Registry policy: a CDHash is admitted when the current build resolves it to
/// the RP ID that the evidence carries.
struct Admission<'a>(&'a Dsmack);

impl Policy for Admission<'_> {
    fn admit(&self, cdhash: &B32, rp: &B32) -> Result<(), Error> {
        if *rp == [0; 32] || self.0.resolve_rp(cdhash) != *rp {
            return Err(Error("build not admitted"));
        }
        Ok(())
    }
    fn is_enrolled(&self, kid: &B32) -> bool {
        self.0.keys.contains_key(kid)
    }
}

impl Dsmack {
    fn platform(&self) -> Platform {
        Platform { aaguid: self.aaguid, category: self.category, ios: self.ios }
    }

    fn resolve_rp(&self, cdhash: &B32) -> B32 {
        match self.builds.get(cdhash) {
            Some(b) if b.build == self.build_id => b.rp,
            _ => [0; 32],
        }
    }
}

#[near]
impl Dsmack {
    /// `aaguid` is the 16-byte App Attest AAGUID, `category` the Apple validation
    /// category (3: Apple Development), and `ios` selects the iOS key ACL.
    ///
    /// Only the contract account can call `new`: deploy and initialize in one batch
    /// transaction so that nobody else can take the owner role first.
    #[private]
    #[init]
    pub fn new(owner: AccountId, aaguid: Base64VecU8, category: u32, ios: bool) -> Self {
        Self {
            owner,
            aaguid: fixed(&aaguid, "aaguid"),
            category,
            ios,
            intermediates: LookupMap::new(b"i"),
            keys: LookupMap::new(b"k"),
            evidence: LookupMap::new(b"e"),
            build_id: [0; 32],
            approved: LookupSet::new(b"a"),
            builds: LookupMap::new(b"b"),
        }
    }

    // Endorsements

    /// Endorse an Apple App Attestation CA that Apple's root key signed. Anyone may call.
    /// Returns the intermediate's identifier. Attach a deposit for the storage.
    #[payable]
    pub fn endorse_intermediate(&mut self, der: Base64VecU8) -> Base64VecU8 {
        let before = env::storage_usage();
        let ca = check(intermediate::endorse(&Host, &APPLE_ROOT_KEY, &der.0, now()));
        let id = ca.id(&Host);
        if self.intermediates.contains_key(&id) {
            env::panic_str("already endorsed");
        }
        self.intermediates.insert(
            id,
            StoredIntermediate { subject: ca.subject, key: ca.key, not_before: ca.not_before, not_after: ca.not_after },
        );
        self.intermediates.flush();
        settle(before);
        Base64VecU8(id.to_vec())
    }

    pub fn intermediate(&self, id: Base64VecU8) -> Option<IntermediateView> {
        self.intermediates.get(&fixed::<32>(&id, "id")).map(|i| IntermediateView {
            subject: Base64VecU8(i.subject.to_vec()),
            key: Base64VecU8(i.key.to_vec()),
            not_before: i.not_before,
            not_after: i.not_after,
        })
    }

    // Enrollment and assertions

    /// Enroll the key of an App Attest attestation. Returns the key ID. Attach a
    /// deposit for the storage.
    #[payable]
    pub fn enroll(&mut self, id: Base64VecU8, cert: Base64VecU8, auth: Base64VecU8, client_data: Base64VecU8) -> Base64VecU8 {
        let before = env::storage_usage();
        let id: B32 = fixed(&id, "id");
        let ca = self.intermediates.get(&id).map(|i| Intermediate {
            subject: i.subject,
            key: i.key,
            not_before: i.not_before,
            not_after: i.not_after,
        });
        let e = check(attest::enroll(
            &Host,
            &self.platform(),
            &Admission(self),
            ca.as_ref(),
            &cert.0,
            &auth.0,
            &client_data.0,
            now(),
        ));
        self.keys.insert(e.kid, StoredKey { x: e.key.x, y: e.key.y, expires: e.key.expires });
        self.keys.flush();
        settle(before);
        Base64VecU8(e.kid.to_vec())
    }

    /// Check an assertion by an enrolled key over `context` (the 32-byte
    /// `clientDataHash` that the app asserted). The counter and the evidence belong to
    /// the calling account. Returns the key ID. Attach a deposit for the first call of
    /// a key from an account.
    ///
    /// An assertion is fresh once for each calling account, so the caller must make
    /// `context` bind the action: derive it on chain from its own account ID and the
    /// action, and never take it from the user. A `context` that does not commit to the
    /// caller accepts an assertion that was made for another consumer.
    #[payable]
    pub fn verify(&mut self, context: Base64VecU8, proof: Proof) -> Base64VecU8 {
        let before = env::storage_usage();
        let kid: B32 = fixed(&proof.kid, "kid");
        let context: B32 = fixed(&context, "context");
        let caller = env::predecessor_account_id();
        let slot = (caller, kid);
        let counter = self.evidence.get(&slot).map_or(0, |e| e.counter);
        let key = self.keys.get(&kid).map(|k| Key { x: k.x, y: k.y, expires: k.expires, counter });
        let a = check(attest::verify(
            &Host,
            &self.platform(),
            &Admission(self),
            key.as_ref(),
            &proof.auth.0,
            &context,
            &fixed(&proof.r, "r"),
            &fixed(&proof.s, "s"),
            now(),
        ));
        self.evidence.insert(
            slot,
            StoredEvidence { context, cdhash: a.cdhash, rp: a.rp, checked_at: now(), counter: a.counter },
        );
        self.evidence.flush();
        settle(before);
        Base64VecU8(kid.to_vec())
    }

    pub fn key(&self, kid: Base64VecU8) -> Option<KeyView> {
        self.keys.get(&fixed::<32>(&kid, "kid")).map(|k| KeyView {
            x: Base64VecU8(k.x.to_vec()),
            y: Base64VecU8(k.y.to_vec()),
            expires: k.expires,
        })
    }

    /// The latest verified assertion of `kid` by `consumer`.
    pub fn evidence(&self, consumer: AccountId, kid: Base64VecU8) -> Option<EvidenceView> {
        self.evidence.get(&(consumer, fixed::<32>(&kid, "kid"))).map(|e| EvidenceView {
            context: Base64VecU8(e.context.to_vec()),
            cdhash: Base64VecU8(e.cdhash.to_vec()),
            rp: Base64VecU8(e.rp.to_vec()),
            checked_at: e.checked_at,
            counter: e.counter,
        })
    }

    // Registry

    /// Set the current approved build. Only the owner may call. CDHashes that were
    /// registered under the previous build stop resolving.
    #[payable]
    pub fn set_build(&mut self, cd: Base64VecU8, page0: Base64VecU8, ent: Base64VecU8) {
        if env::predecessor_account_id() != self.owner {
            env::panic_str("owner");
        }
        let before = env::storage_usage();
        let (build, _) = check(registry::measure(&Host, &cd.0, &page0.0, &ent.0));
        self.build_id = build.id(&Host);
        self.approved.insert(self.build_id);
        settle(before);
    }

    /// Admit a copy whose code, masked page 0, CodeDirectory header and entitlement
    /// shape match an approved build. Anyone may call. Returns the CDHash.
    #[payable]
    pub fn register_build(&mut self, cd: Base64VecU8, page0: Base64VecU8, ent: Base64VecU8) -> Base64VecU8 {
        let before = env::storage_usage();
        let (build, identity) = check(registry::measure(&Host, &cd.0, &page0.0, &ent.0));
        let id = build.id(&Host);
        if !self.approved.contains(&id) {
            env::panic_str("not an approved build");
        }
        let h = registry::cdhash(&Host, &cd.0);
        self.builds.insert(h, StoredBuild { build: id, rp: identity.app, team: identity.team, bundle: identity.bundle });
        self.builds.flush();
        settle(before);
        Base64VecU8(h.to_vec())
    }

    /// The RP ID hash of a CDHash under the current build; 32 zero bytes when it is not admitted.
    pub fn rp_id_hash(&self, cdhash: Base64VecU8) -> Base64VecU8 {
        Base64VecU8(self.resolve_rp(&fixed(&cdhash, "cdhash")).to_vec())
    }

    pub fn team_id_hash(&self, cdhash: Base64VecU8) -> Base64VecU8 {
        let h: B32 = fixed(&cdhash, "cdhash");
        let t = match self.builds.get(&h) {
            Some(b) if b.build == self.build_id => b.team,
            _ => [0; 32],
        };
        Base64VecU8(t.to_vec())
    }

    pub fn bundle_id_hash(&self, cdhash: Base64VecU8) -> Base64VecU8 {
        let h: B32 = fixed(&cdhash, "cdhash");
        let t = match self.builds.get(&h) {
            Some(b) if b.build == self.build_id => b.bundle,
            _ => [0; 32],
        };
        Base64VecU8(t.to_vec())
    }

    pub fn is_admitted(&self, cdhash: Base64VecU8) -> bool {
        self.resolve_rp(&fixed(&cdhash, "cdhash")) != [0; 32]
    }

    /// The identifier of the current approved build; 32 zero bytes before the first `set_build`.
    pub fn build_id(&self) -> Base64VecU8 {
        Base64VecU8(self.build_id.to_vec())
    }

    /// Whether `build` was ever approved by `set_build`.
    pub fn is_approved(&self, build: Base64VecU8) -> bool {
        self.approved.contains(&fixed::<32>(&build, "build"))
    }

    /// The build under which `cdhash` was registered, whether or not it is current;
    /// 32 zero bytes for a CDHash that was never registered. A consumer that pins a build
    /// compares this with the build that it pinned.
    pub fn build_of(&self, cdhash: Base64VecU8) -> Base64VecU8 {
        let h: B32 = fixed(&cdhash, "cdhash");
        Base64VecU8(self.builds.get(&h).map_or([0; 32], |b| b.build).to_vec())
    }

    /// The RP ID hash registered for `cdhash`, whether or not its build is current.
    pub fn rp_of(&self, cdhash: Base64VecU8) -> Base64VecU8 {
        let h: B32 = fixed(&cdhash, "cdhash");
        Base64VecU8(self.builds.get(&h).map_or([0; 32], |b| b.rp).to_vec())
    }
}

#[cfg(feature = "fixture-clock")]
#[near]
impl Dsmack {
    /// Test builds only: set the clock, in Unix seconds. Only the contract account can call it.
    pub fn set_clock(&mut self, secs: u64) {
        if env::predecessor_account_id() != env::current_account_id() {
            env::panic_str("contract account only");
        }
        env::storage_write(b"fixture-clock", &secs.to_le_bytes());
    }
}

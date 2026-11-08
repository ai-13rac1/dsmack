//! Sandbox tests of the contract on near-sandbox. The fixtures have expired, so the
//! tests use the `fixture-clock` build and set the clock to the Foundry timestamps.
//!
//! Environment: `DSMACK_DIR` (a dsmack checkout) and `WASM_DIR` (the `out/` of build.sh).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, Contract};
use serde_json::{json, Value};
use std::path::PathBuf;

const FRESH_TIME: u64 = 1_789_588_800;

fn dsmack(sub: &str) -> PathBuf {
    PathBuf::from(std::env::var("DSMACK_DIR").expect("DSMACK_DIR")).join(sub)
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn b64(v: &[u8]) -> String {
    B64.encode(v)
}

fn load(sub: &str) -> Value {
    serde_json::from_slice(&std::fs::read(dsmack(sub)).unwrap_or_else(|e| panic!("{sub}: {e}"))).unwrap()
}

fn sha256(v: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(v).to_vec()
}

struct Env {
    contract: Contract,
    owner: Account,
    sb: near_workspaces::Worker<near_workspaces::network::Sandbox>,
}

/// A call with a deposit for storage. Panics with the failure text when it fails
/// and `expect_err` is empty; otherwise checks that the failure contains it.
async fn call(from: &Account, c: &Contract, method: &str, args: Value, expect_err: &str) -> Option<Value> {
    call_deposit(from, c, method, args, NearToken::from_millinear(100), expect_err).await
}

async fn call_deposit(from: &Account, c: &Contract, method: &str, args: Value, deposit: NearToken, expect_err: &str) -> Option<Value> {
    let r = from
        .call(c.id(), method)
        .args_json(args)
        .deposit(deposit)
        .gas(Gas::from_tgas(1000))
        .transact()
        .await
        .unwrap();
    let tgas = r.total_gas_burnt.as_tgas();
    if expect_err.is_empty() {
        assert!(r.is_success(), "{method}: {:?}", r.failures());
        // The limit of a transaction is 1000 Tgas. A call that nears it cannot run on a busy chain.
        assert!(tgas < 300, "{method} burnt {tgas} Tgas");
        println!("{method:22} {tgas:7.1} Tgas");
        Some(r.json::<Value>().unwrap_or(Value::Null))
    } else {
        assert!(r.is_failure(), "{method}: expected failure '{expect_err}'");
        let text = format!("{:?}", r.failures());
        assert!(text.contains(expect_err), "{method}: expected '{expect_err}' in {text}");
        None
    }
}

async fn setup(platform_category: u32, ios: bool, aaguid: &[u8]) -> Env {
    setup_with("test/dsmack_near_fixture_clock.wasm", platform_category, ios, aaguid).await
}

async fn setup_with(wasm_name: &str, platform_category: u32, ios: bool, aaguid: &[u8]) -> Env {
    let sb = near_workspaces::sandbox().await.unwrap();
    let wasm = std::fs::read(PathBuf::from(std::env::var("WASM_DIR").expect("WASM_DIR")).join(wasm_name)).unwrap();
    let contract = sb.dev_deploy(&wasm).await.unwrap();
    let owner = sb.dev_create_account().await.unwrap();
    let r = contract
        .call("new")
        .args_json(json!({"owner": owner.id(), "aaguid": b64(aaguid), "category": platform_category, "ios": ios}))
        .transact()
        .await
        .unwrap();
    assert!(r.is_success(), "{:?}", r.failures());
    Env { contract, owner, sb }
}

async fn set_clock(e: &Env, secs: u64) {
    let r = e.contract.call("set_clock").args_json(json!({ "secs": secs })).transact().await.unwrap();
    assert!(r.is_success());
}

/// The `set_build` and `register_build` arguments of a cd-args file in dsmack.
fn build_args(sub: &str) -> Value {
    let j = load(sub);
    json!({"cd": b64(&hx(&j["cd"])), "page0": b64(&hx(&j["page0"])), "ent": b64(&hx(&j["ent"]))})
}

/// Register the build of a cd-args file and return its CDHash.
async fn register(e: &Env, sub: &str) -> String {
    let h = call(&e.owner, &e.contract, "register_build", build_args(sub), "").await.unwrap();
    let cdhash = h.as_str().unwrap().to_string();
    assert_eq!(cdhash, b64(&sha256(&hx(&load(sub)["cd"]))));
    cdhash
}

/// Approve and register the build of a cd-args file, and return its CDHash.
async fn approve_build(e: &Env, sub: &str) -> String {
    call(&e.owner, &e.contract, "set_build", build_args(sub), "").await;
    register(e, sub).await
}

/// Approve and register the build of dsmack's probe app, which Apple signs for the fixtures.
async fn approve_probe_build(e: &Env) {
    let probe = "contracts/fixtures/cd-args-probe-macos.json";
    call(&e.sb.dev_create_account().await.unwrap(), &e.contract, "set_build", build_args(probe), "Smart contract panicked: owner").await;
    approve_build(e, probe).await;
}

fn enroll_args(f: &Value, id: &str) -> Value {
    json!({"id": id, "cert": b64(&hx(&f["cert"])), "auth": b64(&hx(&f["auth"])), "client_data": b64(&hx(&f["clientData"]))})
}

/// A sandbox with the probe build approved and the key of `fresh-apple.json` enrolled.
async fn enrolled_mac() -> (Env, Value, Vec<u8>) {
    let f = load("app-attest/contracts/fixtures/fresh-apple.json");
    let kid = hx(&f["kid"]);
    let e = setup(3, false, &hx(&f["aaguid"])).await;
    set_clock(&e, FRESH_TIME).await;
    approve_probe_build(&e).await;
    let id = endorse_apple(&e).await;
    call(&e.owner, &e.contract, "enroll", enroll_args(&f, &id), "").await;
    (e, f, kid)
}

async fn evidence(e: &Env, consumer: &Account, kid: &[u8]) -> Value {
    e.contract.view("evidence").args_json(json!({"consumer": consumer.id(), "kid": b64(kid)})).await.unwrap().json().unwrap()
}

async fn endorse_apple(e: &Env) -> String {
    let der = std::fs::read(dsmack("app-attest/contracts/fixtures/apple-intermediate.der")).unwrap();
    call(&e.owner, &e.contract, "endorse_intermediate", json!({"der": b64(&der)}), "").await.unwrap().as_str().unwrap().to_string()
}

fn proof(f: &Value, name: &str, kid: &[u8]) -> (String, Value) {
    let a = &f[name];
    let ctx = sha256(&hx(&a["context"]));
    (b64(&ctx), json!({"kid": b64(kid), "auth": b64(&hx(&a["auth"])), "r": b64(&hx(&a["r"])), "s": b64(&hx(&a["s"]))}))
}

#[tokio::test]
async fn enrollment_and_assertions() {
    let f = load("app-attest/contracts/fixtures/fresh-apple.json");
    let kid = hx(&f["kid"]);
    let e = setup(3, false, &hx(&f["aaguid"])).await;
    set_clock(&e, FRESH_TIME).await;
    approve_probe_build(&e).await;
    let id = endorse_apple(&e).await;
    assert_eq!(hex::encode(B64.decode(&id).unwrap()), "b4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90");
    call(&e.owner, &e.contract, "endorse_intermediate", json!({"der": b64(&std::fs::read(dsmack("app-attest/contracts/fixtures/apple-intermediate.der")).unwrap())}), "already endorsed").await;

    let enroll = json!({"id": id, "cert": b64(&hx(&f["cert"])), "auth": b64(&hx(&f["auth"])), "client_data": b64(&hx(&f["clientData"]))});
    let got = call(&e.owner, &e.contract, "enroll", enroll.clone(), "").await.unwrap();
    assert_eq!(got.as_str().unwrap(), b64(&kid));
    call(&e.owner, &e.contract, "enroll", enroll, "already enrolled").await;
    let k: Value = e.contract.view("key").args_json(json!({"kid": b64(&kid)})).await.unwrap().json().unwrap();
    assert!(k["expires"].as_u64().unwrap() > FRESH_TIME);

    let a = e.sb.dev_create_account().await.unwrap();
    let b = e.sb.dev_create_account().await.unwrap();
    let (ctx, p) = proof(&f, "assert", &kid);
    call(&a, &e.contract, "verify", json!({"context": ctx, "proof": p}), "").await;
    call(&a, &e.contract, "verify", json!({"context": ctx, "proof": p}), "assertion replay").await;
    // Another consumer has its own counter.
    call(&b, &e.contract, "verify", json!({"context": ctx, "proof": p}), "").await;
    let (mctx, mp) = proof(&f, "modified", &kid);
    call(&a, &e.contract, "verify", json!({"context": mctx, "proof": mp}), "build not admitted").await;
    let (rctx, rp) = proof(&f, "restored", &kid);
    call(&a, &e.contract, "verify", json!({"context": rctx, "proof": rp}), "").await;
    let ev: Value = e.contract.view("evidence").args_json(json!({"consumer": a.id(), "kid": b64(&kid)})).await.unwrap().json().unwrap();
    assert_eq!(ev["counter"], 3);
    let evb: Value = e.contract.view("evidence").args_json(json!({"consumer": b.id(), "kid": b64(&kid)})).await.unwrap().json().unwrap();
    assert_eq!(evb["counter"], 1);
    let mut wrong = B64.decode(&ctx).unwrap();
    wrong[31] ^= 1;
    let c = e.sb.dev_create_account().await.unwrap();
    call(&c, &e.contract, "verify", json!({"context": b64(&wrong), "proof": p}), "assertion signature").await;
}

#[tokio::test]
async fn enrollment_needs_an_admitted_build() {
    let f = load("app-attest/contracts/fixtures/fresh-apple.json");
    let e = setup(3, false, &hx(&f["aaguid"])).await;
    set_clock(&e, FRESH_TIME).await;
    let id = endorse_apple(&e).await;
    let enroll = json!({"id": id, "cert": b64(&hx(&f["cert"])), "auth": b64(&hx(&f["auth"])), "client_data": b64(&hx(&f["clientData"]))});
    call(&e.owner, &e.contract, "enroll", enroll, "build not admitted").await;
}

async fn deploy_consumer(e: &Env, wasm_name: &str) -> Contract {
    let wasm = std::fs::read(PathBuf::from(std::env::var("WASM_DIR").unwrap()).join(wasm_name)).unwrap();
    let c = e.sb.dev_deploy(&wasm).await.unwrap();
    let r = c.call("new").args_json(json!({"dsmack": e.contract.id()})).transact().await.unwrap();
    assert!(r.is_success(), "{:?}", r.failures());
    c
}

async fn consumer_check(user: &Account, consumer: &Contract, args: &Value) -> bool {
    let r = user
        .call(consumer.id(), "check")
        .args_json(args.clone())
        .deposit(NearToken::from_millinear(100))
        .gas(Gas::from_tgas(300))
        .transact()
        .await
        .unwrap();
    println!("consumer check         {:7.1} Tgas", r.total_gas_burnt.as_tgas());
    r.json::<bool>().unwrap()
}

/// A consumer contract calls `verify` and reads the result in a callback. The test build
/// of the consumer takes the fixed context of the Apple fixture as the action.
#[tokio::test]
async fn consumer_contracts_call_verify() {
    let (e, f, kid) = enrolled_mac().await;
    let mut consumers = Vec::new();
    for _ in 0..2 {
        consumers.push(deploy_consumer(&e, "test/dsmack_consumer_fixture_context.wasm").await);
    }
    let user = e.sb.dev_create_account().await.unwrap();
    let (ctx, p) = proof(&f, "assert", &kid);
    let args = json!({"action": ctx, "proof": p});
    let mut results = Vec::new();
    for i in [0, 0, 1] {
        results.push(consumer_check(&user, &consumers[i], &args).await);
    }
    // The second call by the first consumer is a replay for that consumer, and the
    // promise failure reaches its callback. The second consumer has its own counter.
    assert_eq!(results, [true, false, true]);
    let last: Value = consumers[0].view("last_kid").await.unwrap().json().unwrap();
    assert_eq!(last.as_str().unwrap(), b64(&kid));
    let ev: Value = e.contract.view("evidence").args_json(json!({"consumer": consumers[0].id(), "kid": b64(&kid)})).await.unwrap().json().unwrap();
    assert_eq!(ev["counter"], 1);
}

/// Borsh encoding of a string or byte string: a little-endian u32 length, then the bytes.
fn borsh_bytes(v: &[u8]) -> Vec<u8> {
    let mut out = (v.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(v);
    out
}

/// The example consumer derives the context from its account, the caller and the action.
/// A proof sent by another account, or for another action, does not verify.
#[tokio::test]
async fn consumer_binds_the_context_to_the_receiver() {
    let (e, f, kid) = enrolled_mac().await;
    let consumer = deploy_consumer(&e, "dsmack_consumer.wasm").await;
    let user = e.sb.dev_create_account().await.unwrap();
    let action = b"pay task 7".to_vec();
    let mut data = borsh_bytes(consumer.id().as_bytes());
    data.extend(borsh_bytes(user.id().as_bytes()));
    data.extend(borsh_bytes(&action));
    let got: Value = consumer
        .view("context_of")
        .args_json(json!({"receiver": user.id(), "action": b64(&action)}))
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(got, b64(&sha256(&data)).as_str());

    // The fixture assertion was made over another context, so the derived context fails.
    let (ctx, p) = proof(&f, "assert", &kid);
    assert!(!consumer_check(&user, &consumer, &json!({"action": b64(&action), "proof": p})).await);
    assert!(!consumer_check(&user, &consumer, &json!({"action": ctx, "proof": p})).await);
    let ev: Value = e.contract.view("evidence").args_json(json!({"consumer": consumer.id(), "kid": b64(&kid)})).await.unwrap().json().unwrap();
    assert_eq!(ev, Value::Null);
}

/// A call without a deposit for its storage fails: the caller pays, not the contract.
#[tokio::test]
async fn storage_is_paid_by_the_caller() {
    let f = load("app-attest/contracts/fixtures/fresh-apple.json");
    let e = setup(3, false, &hx(&f["aaguid"])).await;
    set_clock(&e, FRESH_TIME).await;
    let der = std::fs::read(dsmack("app-attest/contracts/fixtures/apple-intermediate.der")).unwrap();
    let args = json!({"der": b64(&der)});
    for deposit in [0, 1] {
        let d = NearToken::from_yoctonear(deposit);
        call_deposit(&e.owner, &e.contract, "endorse_intermediate", args.clone(), d, "yoctoNEAR for storage").await;
    }
    call(&e.owner, &e.contract, "endorse_intermediate", args, "").await;
    // set_build stores the build ID in a LookupSet, which writes at once, so the call pays.
    let build = build_args("contracts/fixtures/cd-args-probe-macos.json");
    call_deposit(&e.owner, &e.contract, "set_build", build.clone(), NearToken::from_yoctonear(0), "yoctoNEAR for storage").await;
    call(&e.owner, &e.contract, "set_build", build, "").await;
}

/// The views follow the current build, and a view rejects a value of the wrong length.
#[tokio::test]
async fn views_follow_the_current_build() {
    let f = load("app-attest/contracts/fixtures/fresh-apple.json");
    let e = setup(3, false, &hx(&f["aaguid"])).await;
    set_clock(&e, FRESH_TIME).await;
    approve_probe_build(&e).await;
    let id = endorse_apple(&e).await;
    let probe = load("contracts/fixtures/cd-args-probe-macos.json");
    let cdhash = b64(&sha256(&hx(&probe["cd"])));
    let view = |method: &'static str, key: &'static str, v: String| {
        let c = e.contract.clone();
        async move { c.view(method).args_json(json!({ key: v })).await }
    };
    let text = |r: near_workspaces::result::ViewResultDetails| r.json::<Value>().unwrap();
    assert_eq!(text(view("rp_id_hash", "cdhash", cdhash.clone()).await.unwrap()), b64(&hx(&f["appHash"])));
    assert_eq!(text(view("team_id_hash", "cdhash", cdhash.clone()).await.unwrap()), b64(&sha256(b"DC9JH5DRMY")));
    assert_eq!(text(view("bundle_id_hash", "cdhash", cdhash.clone()).await.unwrap()), b64(&sha256(b"dev.dsmack.provider")));
    assert_eq!(text(view("is_admitted", "cdhash", cdhash.clone()).await.unwrap()), true);
    let ca = text(view("intermediate", "id", id).await.unwrap());
    assert_eq!(ca["not_after"], 1_899_590_400u64);

    // A new approved build: the registered CDHash stops resolving.
    let next = load("contracts/fixtures/resign/iphone-honest.json");
    let args = json!({"cd": b64(&hx(&next["cd"])), "page0": b64(&hx(&next["page0"])), "ent": b64(&hx(&next["ent"]))});
    call(&e.owner, &e.contract, "set_build", args, "").await;
    assert_eq!(text(view("rp_id_hash", "cdhash", cdhash.clone()).await.unwrap()), b64(&[0u8; 32]));
    assert_eq!(text(view("is_admitted", "cdhash", cdhash.clone()).await.unwrap()), false);
    // A consumer that pins a build still resolves the superseded one.
    let old_build = text(view("build_of", "cdhash", cdhash.clone()).await.unwrap());
    let current = text(e.contract.view("build_id").await.unwrap());
    assert_ne!(old_build, current);
    assert_ne!(old_build, b64(&[0u8; 32]));
    assert_eq!(text(view("is_approved", "build", old_build.as_str().unwrap().to_string()).await.unwrap()), true);
    assert_eq!(text(view("rp_of", "cdhash", cdhash).await.unwrap()), b64(&hx(&f["appHash"])));

    let short = view("key", "kid", b64(&[0u8; 31])).await.err().expect("a 31-byte kid is rejected");
    assert!(format!("{short:?}").contains("kid must be 32 bytes"), "{short:?}");
}

/// The production build has no `set_clock` and reads the block time.
#[tokio::test]
async fn production_build_reads_the_block_time() {
    let f = load("app-attest/contracts/fixtures/fresh-apple.json");
    let e = setup_with("dsmack_near.wasm", 3, false, &hx(&f["aaguid"])).await;
    let r = e.contract.call("set_clock").args_json(json!({"secs": FRESH_TIME})).transact().await.unwrap();
    assert!(format!("{:?}", r.failures()).contains("MethodNotFound"), "{:?}", r.failures());
    let id = endorse_apple(&e).await;
    approve_probe_build(&e).await;
    let enroll = json!({"id": id, "cert": b64(&hx(&f["cert"])), "auth": b64(&hx(&f["auth"])), "client_data": b64(&hx(&f["clientData"]))});
    call(&e.owner, &e.contract, "enroll", enroll, "certificate validity").await;
}

/// An iOS deployment: the iPhone fixture, category 5 and the iOS key ACL. Port of
/// `test_IPhoneEnrollAndAssertThroughRegistry` and `test_IPhoneUnregisteredBuildRejected`.
#[tokio::test]
async fn ios_deployment() {
    let f = load("app-attest/contracts/fixtures/iphone-apple.json");
    let kid = hx(&f["kid"]);
    let e = setup(5, true, &hx(&f["aaguid"])).await;
    set_clock(&e, 1_790_200_000).await;
    let build = "contracts/fixtures/resign/iphone-honest.json";
    call(&e.owner, &e.contract, "set_build", build_args(build), "").await;
    let id = endorse_apple(&e).await;
    call(&e.owner, &e.contract, "enroll", enroll_args(&f, &id), "build not admitted").await;
    register(&e, build).await;
    let got = call(&e.owner, &e.contract, "enroll", enroll_args(&f, &id), "").await.unwrap();
    assert_eq!(got.as_str().unwrap(), b64(&kid));
    let a = e.sb.dev_create_account().await.unwrap();
    let (ctx, p) = proof(&f, "assert", &kid);
    call(&a, &e.contract, "verify", json!({"context": ctx, "proof": p}), "").await;
    let (mctx, mp) = proof(&f, "modified", &kid);
    call(&a, &e.contract, "verify", json!({"context": mctx, "proof": mp}), "build not admitted").await;
}

/// Evidence is stored only by a successful, fresh assertion. Port of
/// `test_ReceiptEvidenceRequiresSuccessfulFreshAssertion`.
#[tokio::test]
async fn evidence_needs_a_fresh_assertion() {
    let (e, f, kid) = enrolled_mac().await;
    let a = e.sb.dev_create_account().await.unwrap();
    assert_eq!(evidence(&e, &a, &kid).await, Value::Null);

    let (ctx, p) = proof(&f, "assert", &kid);
    let got = call(&a, &e.contract, "verify", json!({"context": ctx, "proof": p}), "").await.unwrap();
    assert_eq!(got, json!({"kid": b64(&kid), "cdhash": b64(&hx(&f["cdhash"])), "rp": b64(&hx(&f["appHash"])), "counter": 1}));
    let ev = evidence(&e, &a, &kid).await;
    assert_eq!(ev["context"], ctx.as_str());
    assert_eq!(ev["cdhash"], b64(&hx(&f["cdhash"])).as_str());
    assert_eq!(ev["rp"], b64(&hx(&f["appHash"])).as_str());
    assert_eq!(ev["checked_at"], FRESH_TIME);
    assert_eq!(ev["counter"], 1);

    call(&a, &e.contract, "verify", json!({"context": ctx, "proof": p}), "assertion replay").await;
    let (mctx, mp) = proof(&f, "modified", &kid);
    call(&a, &e.contract, "verify", json!({"context": mctx, "proof": mp}), "build not admitted").await;
    assert_eq!(evidence(&e, &a, &kid).await, ev);
    let (rctx, rp) = proof(&f, "restored", &kid);
    let mut other = [0u8; 32];
    other[31] = 123;
    call(&a, &e.contract, "verify", json!({"context": b64(&other), "proof": rp}), "assertion signature").await;
    assert_eq!(evidence(&e, &a, &kid).await, ev);

    call(&a, &e.contract, "verify", json!({"context": rctx, "proof": rp}), "").await;
    let ev = evidence(&e, &a, &kid).await;
    assert_eq!(ev["context"], rctx.as_str());
    assert_eq!(ev["counter"], 3);
}

/// An enrolled key verifies after its leaf certificate expires. Port of
/// `test_EnrolledKeyOutlivesLeaf`.
#[tokio::test]
async fn enrolled_key_outlives_its_leaf() {
    let (e, f, kid) = enrolled_mac().await;
    set_clock(&e, 1_789_761_030 + 30 * 86_400).await;
    let a = e.sb.dev_create_account().await.unwrap();
    let (ctx, p) = proof(&f, "assert", &kid);
    let got = call(&a, &e.contract, "verify", json!({"context": ctx, "proof": p}), "").await.unwrap();
    assert_eq!(got["kid"], b64(&kid).as_str());
}

/// A new approved build stops the keys of the earlier build at once. Port of the main
/// verifier half of `test_SupersededBuildStopsKey`. The contract has no canary verifier.
#[tokio::test]
async fn new_build_stops_enrolled_keys() {
    let (e, f, kid) = enrolled_mac().await;
    call(&e.owner, &e.contract, "set_build", build_args("contracts/fixtures/cd-args-developer-id.json"), "").await;
    let a = e.sb.dev_create_account().await.unwrap();
    let (ctx, p) = proof(&f, "assert", &kid);
    call(&a, &e.contract, "verify", json!({"context": ctx, "proof": p}), "build not admitted").await;
}

async fn developer_id(category: u32) -> (Env, Value, String) {
    let f = load("contracts/fixtures/developer-id-apple.json");
    let e = setup(category, false, &hx(&f["aaguid"])).await;
    set_clock(&e, f["capturedAt"].as_u64().unwrap()).await;
    let cdhash = approve_build(&e, "contracts/fixtures/cd-args-developer-id.json").await;
    assert_eq!(cdhash, b64(&hx(&f["cdhash"])));
    let id = endorse_apple(&e).await;
    (e, f, id)
}

/// A Developer ID build enrolls under category 6, and a release Development build
/// registers under the same approved build. Port of
/// `test_DeveloperIDEnrollmentThroughRegistry` and
/// `test_ReleaseDevelopmentAndDeveloperIDShareCodeBaseline`.
#[tokio::test]
async fn developer_id_enrollment() {
    let (e, f, id) = developer_id(6).await;
    let got = call(&e.owner, &e.contract, "enroll", enroll_args(&f, &id), "").await.unwrap();
    assert_eq!(got.as_str().unwrap(), b64(&hx(&f["kid"])));
    let release = "contracts/fixtures/cd-args-release-development.json";
    assert_eq!(register(&e, release).await, b64(&hx(&load(release)["cdhash"])));
}

/// A Developer ID enrollment fails under the Apple Development category. Port of
/// `test_DeveloperIDNotAcceptedAsDevelopmentSigning`.
#[tokio::test]
async fn developer_id_is_not_development_signing() {
    let (e, f, id) = developer_id(3).await;
    call(&e.owner, &e.contract, "enroll", enroll_args(&f, &id), "validation category").await;
}

/// Two copies signed by different teams resolve to their own App ID hash, so the
/// CDHash of one team does not admit the App ID of the other. Port of
/// `test_SyntheticTeamLookup`.
#[tokio::test]
async fn registry_keeps_teams_apart() {
    let e = setup(3, false, b"appattest\0\0\0\0\0\0\0").await;
    let ours = approve_build(&e, "contracts/fixtures/resign/node-honest.json").await;
    let other = register(&e, "contracts/fixtures/resign/node-synthetic-team.json").await;
    assert_ne!(ours, other);
    for (cdhash, app) in [(ours, "DC9JH5DRMY.dev.dsmack.provider"), (other, "TESTTEAM01.dev.dsmack.provider")] {
        let rp: Value = e.contract.view("rp_id_hash").args_json(json!({ "cdhash": cdhash })).await.unwrap().json().unwrap();
        assert_eq!(rp, b64(&sha256(app.as_bytes())).as_str());
    }
}

/// The data of the one NEP-297 event that a successful call logs.
async fn event(from: &Account, c: &Contract, method: &str, args: Value) -> Value {
    let r = from.call(c.id(), method).args_json(args).deposit(NearToken::from_millinear(100)).gas(Gas::from_tgas(300)).transact().await.unwrap();
    assert!(r.is_success(), "{method}: {:?}", r.failures());
    let logs = r.logs();
    assert_eq!(logs.len(), 1, "{method}: {logs:?}");
    let e: Value = serde_json::from_str(logs[0].strip_prefix("EVENT_JSON:").unwrap()).unwrap();
    assert_eq!((&e["standard"], &e["version"]), (&json!("dsmack"), &json!("1.0.0")));
    json!({"event": e["event"], "data": e["data"][0]})
}

/// Endorsement, enrollment and assertion log the events of the Solidity contracts.
#[tokio::test]
async fn calls_log_the_solidity_events() {
    let f = load("app-attest/contracts/fixtures/fresh-apple.json");
    let kid = hx(&f["kid"]);
    let e = setup(3, false, &hx(&f["aaguid"])).await;
    set_clock(&e, FRESH_TIME).await;
    approve_probe_build(&e).await;
    let der = std::fs::read(dsmack("app-attest/contracts/fixtures/apple-intermediate.der")).unwrap();
    let got = event(&e.owner, &e.contract, "endorse_intermediate", json!({"der": b64(&der)})).await;
    let id = got["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(got, json!({"event": "IntermediateEndorsed", "data": {"id": id, "not_before": 1_584_556_795u64, "not_after": 1_899_590_400u64}}));
    let got = event(&e.owner, &e.contract, "enroll", enroll_args(&f, &id)).await;
    assert_eq!(got, json!({"event": "Enrolled", "data": {"kid": b64(&kid), "expires": 1_899_590_400u64}}));
    let (ctx, p) = proof(&f, "assert", &kid);
    let got = event(&e.owner, &e.contract, "verify", json!({"context": ctx, "proof": p})).await;
    assert_eq!(got, json!({"event": "Asserted", "data": {"consumer": e.owner.id(), "kid": b64(&kid), "counter": 1, "context": ctx}}));
}

/// An account other than the owner can endorse, register and enroll, as the README says.
/// Only the contract account can call `new` and `set_clock`.
#[tokio::test]
async fn callers_of_each_method() {
    let f = load("app-attest/contracts/fixtures/fresh-apple.json");
    let e = setup(3, false, &hx(&f["aaguid"])).await;
    let other = e.sb.dev_create_account().await.unwrap();
    let r = other.call(e.contract.id(), "set_clock").args_json(json!({"secs": FRESH_TIME})).transact().await.unwrap();
    assert!(format!("{:?}", r.failures()).contains("contract account only"), "{:?}", r.failures());
    set_clock(&e, FRESH_TIME).await;
    let probe = "contracts/fixtures/cd-args-probe-macos.json";
    call(&e.owner, &e.contract, "set_build", build_args(probe), "").await;
    call(&other, &e.contract, "register_build", build_args(probe), "").await;
    let der = std::fs::read(dsmack("app-attest/contracts/fixtures/apple-intermediate.der")).unwrap();
    let id = call(&other, &e.contract, "endorse_intermediate", json!({"der": b64(&der)}), "").await.unwrap();
    let kid = call(&other, &e.contract, "enroll", enroll_args(&f, id.as_str().unwrap()), "").await.unwrap();
    assert_eq!(kid, b64(&hx(&f["kid"])).as_str());

    let wasm = std::fs::read(PathBuf::from(std::env::var("WASM_DIR").unwrap()).join("dsmack_near.wasm")).unwrap();
    let c = e.sb.dev_deploy(&wasm).await.unwrap();
    let args = json!({"owner": other.id(), "aaguid": b64(&hx(&f["aaguid"])), "category": 3, "ios": false});
    let r = other.call(c.id(), "new").args_json(args).transact().await.unwrap();
    assert!(format!("{:?}", r.failures()).contains("Method new is private"), "{:?}", r.failures());
}

/// Every fixed-length argument of a call or a view rejects a value of the wrong length.
#[tokio::test]
async fn arguments_of_the_wrong_length_fail() {
    let (e, f, kid) = enrolled_mac().await;
    let short = b64(&[0u8; 31]);
    for (method, key, name) in [
        ("key", "kid", "kid must be 32 bytes"),
        ("intermediate", "id", "id must be 32 bytes"),
        ("rp_id_hash", "cdhash", "cdhash must be 32 bytes"),
        ("team_id_hash", "cdhash", "cdhash must be 32 bytes"),
        ("bundle_id_hash", "cdhash", "cdhash must be 32 bytes"),
        ("is_admitted", "cdhash", "cdhash must be 32 bytes"),
        ("build_of", "cdhash", "cdhash must be 32 bytes"),
        ("rp_of", "cdhash", "cdhash must be 32 bytes"),
        ("is_approved", "build", "build must be 32 bytes"),
    ] {
        let r = e.contract.view(method).args_json(json!({ key: short })).await.err().expect(method);
        assert!(format!("{r:?}").contains(name), "{method}: {r:?}");
    }
    let r = e.contract.view("evidence").args_json(json!({"consumer": e.owner.id(), "kid": short})).await.err().expect("evidence");
    assert!(format!("{r:?}").contains("kid must be 32 bytes"), "{r:?}");

    call(&e.owner, &e.contract, "enroll", enroll_args(&f, &short), "id must be 32 bytes").await;
    let (ctx, p) = proof(&f, "assert", &kid);
    for (field, name) in [("kid", "kid"), ("r", "r"), ("s", "s")] {
        let mut q = p.clone();
        q[field] = json!(short);
        call(&e.owner, &e.contract, "verify", json!({"context": ctx, "proof": q}), &format!("{name} must be 32 bytes")).await;
    }
    call(&e.owner, &e.contract, "verify", json!({"context": short, "proof": p}), "context must be 32 bytes").await;

    let wasm = std::fs::read(PathBuf::from(std::env::var("WASM_DIR").unwrap()).join("dsmack_near.wasm")).unwrap();
    let c = e.sb.dev_deploy(&wasm).await.unwrap();
    let r = c
        .call("new")
        .args_json(json!({"owner": e.owner.id(), "aaguid": b64(&[0u8; 15]), "category": 3, "ios": false}))
        .transact()
        .await
        .unwrap();
    assert!(format!("{:?}", r.failures()).contains("aaguid must be 16 bytes"), "{:?}", r.failures());
}

/// A malformed CodeDirectory fails with the message of the Solidity CDRegistry.
#[tokio::test]
async fn malformed_code_directory_fails() {
    let e = setup(3, false, b"appattest\0\0\0\0\0\0\0").await;
    approve_build(&e, "contracts/fixtures/cd-args-probe-macos.json").await;
    let j = load("contracts/fixtures/cd-args-probe-macos.json");
    let mut cd = hx(&j["cd"]);
    cd[0] ^= 1;
    let args = json!({"cd": b64(&cd), "page0": b64(&hx(&j["page0"])), "ent": b64(&hx(&j["ent"]))});
    call(&e.owner, &e.contract, "register_build", args, "blob").await;
    let args = json!({"cd": b64(&hx(&j["cd"])), "page0": b64(&[0u8; 8]), "ent": b64(&hx(&j["ent"]))});
    call(&e.owner, &e.contract, "register_build", args, "sha256/16KiB").await;
    // The CodeDirectory holds the hash of page 0.
    let args = json!({"cd": b64(&hx(&j["cd"])), "page0": b64(&[0u8; 16384]), "ent": b64(&hx(&j["ent"]))});
    call(&e.owner, &e.contract, "register_build", args, "page0 hash").await;
}

/// `verify` treats signature values as the P-256 precompile of the Solidity (RIP-7212)
/// does: both `s` and `n - s` verify, and zero or out-of-range values fail. Apple signs
/// with either form: `fresh-apple.json` `assert` has a high S.
#[tokio::test]
async fn verify_checks_the_signature_values() {
    const N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    let (e, f, kid) = enrolled_mac().await;
    let (ctx, p) = proof(&f, "assert", &kid);
    let with = |r: &[u8], s: &[u8]| {
        let mut q = p.clone();
        q["r"] = json!(b64(r));
        q["s"] = json!(b64(s));
        json!({"context": ctx, "proof": q})
    };
    let r = hx(&f["assert"]["r"]);
    let s = hx(&f["assert"]["s"]);
    let n = hex::decode(N).unwrap();
    // other_s = n - s, big-endian subtraction.
    let mut other_s = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = n[i] as i16 - s[i] as i16 - borrow;
        borrow = (d < 0) as i16;
        d += 256 * borrow;
        other_s[i] = d as u8;
    }
    let zero = [0u8; 32];
    let ones = [0xffu8; 32];
    let b = e.sb.dev_create_account().await.unwrap();
    for (rv, sv) in [(&zero[..], &s[..]), (&r[..], &zero[..]), (&n[..], &s[..]), (&r[..], &n[..]), (&ones[..], &ones[..])] {
        call(&b, &e.contract, "verify", with(rv, sv), "assertion signature").await;
    }
    let a = e.sb.dev_create_account().await.unwrap();
    call(&a, &e.contract, "verify", with(&r, &other_s), "").await;
    // The second form of the signature does not give a second use of the assertion.
    call(&a, &e.contract, "verify", with(&r, &s), "assertion replay").await;
}

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
    setup_with("dsmack_near_fixture_clock.wasm", platform_category, ios, aaguid).await
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

/// Approve and register the build of dsmack's probe app, which Apple signs for the fixtures.
async fn approve_probe_build(e: &Env) {
    let j = load("contracts/fixtures/cd-args-probe-macos.json");
    let args = json!({"cd": b64(&hx(&j["cd"])), "page0": b64(&hx(&j["page0"])), "ent": b64(&hx(&j["ent"]))});
    call(&e.sb.dev_create_account().await.unwrap(), &e.contract, "set_build", args.clone(), "Smart contract panicked: owner").await;
    call(&e.owner, &e.contract, "set_build", args.clone(), "").await;
    let h = call(&e.owner, &e.contract, "register_build", args, "").await.unwrap();
    assert_eq!(h.as_str().unwrap(), b64(&sha256(&hx(&j["cd"]))));
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

/// A consumer contract calls `verify` and reads the key ID in a callback.
#[tokio::test]
async fn consumer_contracts_call_verify() {
    let f = load("app-attest/contracts/fixtures/fresh-apple.json");
    let kid = hx(&f["kid"]);
    let e = setup(3, false, &hx(&f["aaguid"])).await;
    set_clock(&e, FRESH_TIME).await;
    approve_probe_build(&e).await;
    let id = endorse_apple(&e).await;
    let enroll = json!({"id": id, "cert": b64(&hx(&f["cert"])), "auth": b64(&hx(&f["auth"])), "client_data": b64(&hx(&f["clientData"]))});
    call(&e.owner, &e.contract, "enroll", enroll, "").await;

    let wasm = std::fs::read(PathBuf::from(std::env::var("WASM_DIR").unwrap()).join("dsmack_consumer.wasm")).unwrap();
    let mut consumers = Vec::new();
    for _ in 0..2 {
        let c = e.sb.dev_deploy(&wasm).await.unwrap();
        let r = c.call("new").args_json(json!({"dsmack": e.contract.id()})).transact().await.unwrap();
        assert!(r.is_success(), "{:?}", r.failures());
        consumers.push(c);
    }
    let user = e.sb.dev_create_account().await.unwrap();
    let (ctx, p) = proof(&f, "assert", &kid);
    let args = json!({"context": ctx, "proof": p});
    let mut results = Vec::new();
    for i in [0, 0, 1] {
        let r = user
            .call(consumers[i].id(), "check")
            .args_json(args.clone())
            .deposit(NearToken::from_millinear(100))
            .gas(Gas::from_tgas(300))
            .transact()
            .await
            .unwrap();
        println!("consumer check         {:7.1} Tgas", r.total_gas_burnt.as_tgas());
        results.push(r.json::<bool>().unwrap());
    }
    // The second call by the first consumer is a replay for that consumer, and the
    // promise failure reaches its callback. The second consumer has its own counter.
    assert_eq!(results, [true, false, true]);
    let last: Value = consumers[0].view("last_kid").await.unwrap().json().unwrap();
    assert_eq!(last.as_str().unwrap(), b64(&kid));
    let ev: Value = e.contract.view("evidence").args_json(json!({"consumer": consumers[0].id(), "kid": b64(&kid)})).await.unwrap().json().unwrap();
    assert_eq!(ev["counter"], 1);
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
    assert!(r.is_failure());
    let id = endorse_apple(&e).await;
    approve_probe_build(&e).await;
    let enroll = json!({"id": id, "cert": b64(&hx(&f["cert"])), "auth": b64(&hx(&f["auth"])), "client_data": b64(&hx(&f["clientData"]))});
    call(&e.owner, &e.contract, "enroll", enroll, "certificate validity").await;
}

/// An iOS deployment: the iPhone fixture, category 5 and the iOS key ACL.
#[tokio::test]
async fn ios_deployment() {
    let f = load("app-attest/contracts/fixtures/iphone-apple.json");
    let kid = hx(&f["kid"]);
    let e = setup(5, true, &hx(&f["aaguid"])).await;
    set_clock(&e, 1_790_200_000).await;
    let build = load("contracts/fixtures/resign/iphone-honest.json");
    let args = json!({"cd": b64(&hx(&build["cd"])), "page0": b64(&hx(&build["page0"])), "ent": b64(&hx(&build["ent"]))});
    call(&e.owner, &e.contract, "set_build", args.clone(), "").await;
    call(&e.owner, &e.contract, "register_build", args, "").await;
    let id = endorse_apple(&e).await;
    let enroll = json!({"id": id, "cert": b64(&hx(&f["cert"])), "auth": b64(&hx(&f["auth"])), "client_data": b64(&hx(&f["clientData"]))});
    let got = call(&e.owner, &e.contract, "enroll", enroll, "").await.unwrap();
    assert_eq!(got.as_str().unwrap(), b64(&kid));
    let a = e.sb.dev_create_account().await.unwrap();
    let (ctx, p) = proof(&f, "assert", &kid);
    call(&a, &e.contract, "verify", json!({"context": ctx, "proof": p}), "").await;
}

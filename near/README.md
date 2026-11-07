# dsmack on NEAR

Apple App Attest verification for NEAR smart contracts. A NEAR contract can check
that a signed message comes from a copy of an approved Mac program. It is a WASM
port of the Solidity verifiers in [`app-attest/`](../app-attest/README.md) and
[`contracts/`](../contracts/DEPLOY.md).

One contract holds the endorsed Apple intermediates, the enrolled keys and the
approved builds. Another contract calls `verify` and reads the key ID in a
callback. [`examples/consumer`](examples/consumer/src/lib.rs) shows the call.

## Contract

All byte arguments are base64.

| Method | Caller | Arguments |
|---|---|---|
| `new` | contract account | `owner`, `aaguid`, `category`, `ios` |
| `set_build` | owner | `cd`, `page0`, `ent` |
| `register_build` | anyone | `cd`, `page0`, `ent` |
| `endorse_intermediate` | anyone | `der` |
| `enroll` | anyone | `id`, `cert`, `auth`, `client_data` |
| `verify` | consumer contract | `context`, `proof` (`kid`, `auth`, `r`, `s`) |

- `set_build` sets the current approved build. CDHashes that were registered under an
  earlier build stop resolving.
- `register_build` admits a copy of the approved build: same code, same masked page 0,
  same CodeDirectory header and same entitlement shape, signed by any team.
- `endorse_intermediate` checks an Apple App Attestation CA against Apple's root key.
- `enroll` checks the certificate chain, the nonce, the key ACL, the authenticator data
  and that the build is admitted. It stores the key.
- `verify` checks an assertion by an enrolled key. The assertion counter and the evidence
  belong to the calling account, so a caller cannot use up the counter of another. An
  assertion is therefore fresh once for each calling account: a consumer derives
  `context` on chain from its own account ID and the action, and never takes it from
  the user.

Calls that store data take an attached deposit for the storage. The contract returns
the rest. Views: `key`, `evidence`, `intermediate`, `rp_id_hash`, `team_id_hash`,
`bundle_id_hash`, `is_admitted`, `build_id`, `is_approved`, `build_of`, `rp_of`. The last
two resolve a CDHash under any build that `set_build` ever approved, for a consumer that
pins one build.

Every failed check of the certificate, authenticator data, assertion and build code
panics with the message of the Solidity `require` that it replaces. A call argument of
the wrong length panics with `<name> must be <n> bytes`.

| Call | Gas |
|---|---:|
| `endorse_intermediate` | 82 Tgas |
| `enroll` | 83 Tgas |
| `verify` | 4 Tgas |
| `register_build` | 5 Tgas |

## Layout

| Path | Role |
|---|---|
| `core/` | Certificate, authenticator data, assertion and build checks. It has no NEAR dependency. |
| `contract/` | The NEAR contract. |
| `examples/consumer/` | A contract that calls `verify`. |
| `tests/` | Sandbox tests of the contracts. |
| `tools/capture_args.py` | Turns a capture from `app-attest/contracts/fixtures` into contract arguments. |

## Build

You need Podman.

```sh
near/build.sh
```

This writes `near/out/dsmack_near.wasm`, which you deploy, `dsmack_near_fixture_clock.wasm`
and `dsmack_consumer.wasm` for the sandbox tests. [DEPLOY.md](DEPLOY.md) explains how to
deploy and set up the contract.

## Test

The tests run in a Rust container and read the Apple fixtures of this repository.

```sh
near/test.sh      # core checks
near/build.sh
near/sandbox.sh   # contracts on near-sandbox 2.14.0
```

`core/tests/` ports `MacAppAttestV1.t.sol`, `Intermediate.t.sol` and `CDRegistry.t.sol`.
The Apple fixtures have expired, so the sandbox tests use the `fixture-clock` build and
set the clock to the timestamps of the Foundry tests.

Clippy, in the same image:

```sh
cargo clippy -p dsmack-attest-core --all-targets
RUSTFLAGS="--cfg near" cargo clippy -p dsmack-near -p dsmack-consumer --target wasm32-unknown-unknown
```

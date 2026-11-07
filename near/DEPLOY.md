# Deployment

## Build and check the code

`./build.sh` builds in the `rust:1-slim` image with `RUSTFLAGS="--cfg near"`. It prints
the SHA-256 of `out/dsmack_near.wasm`. After a deployment, compare it with the hash of the
code on the account:

```sh
sha256sum out/dsmack_near.wasm
```

Deploy `out/dsmack_near.wasm`, not the `fixture-clock` build. The `fixture-clock` build has
a `set_clock` method that the contract account can call. A holder of a key of the contract
account can then move the clock back, and expired certificates pass the checks again.

## Set up

Run these calls in order. All arguments are base64.

1. Deploy the contract and call `new` in one batch transaction that the contract account
   signs: only the contract account can call `new`. Its arguments are the owner account,
   the 16-byte AAGUID (`appattest` followed by zeros), the validation category (3 for
   Apple Development) and `ios` (false for a Mac).
2. Build the arguments of the approved build with
   `tools/capture_args.py build cd-args.json`. A `cd-args.json` comes from dsmack's
   `contracts/cd_args.py` for a signed `Runner.app`. The owner calls `set_build` with them.
3. Anyone calls `register_build` with the arguments of each signed copy that should be
   admitted. The result is the copy's CDHash.
4. Anyone calls `endorse_intermediate` with Apple's App Attestation CA certificate (DER).
   The result is the intermediate's `id`. Attach a deposit for the storage.
5. A device enrolls: `tools/capture_args.py capture.json enroll <id>` gives the arguments
   of `enroll`. Attach a deposit for the storage.
6. A consumer contract calls `verify` with an assertion:
   `tools/capture_args.py capture.json verify <assertion-name>`.

After step 1, delete every full-access key of the contract account. A holder of such a
key can deploy different code, and this contract is a trust root for its consumers.

A consumer derives `context` on chain from its own account ID, the account that receives
the result of the action, and the action, as `examples/consumer` does. An assertion is
fresh once for each calling account, and NEAR nodes see a transaction before it runs:
without the receiver in `context`, another account can send a copy of the proof first and
receive the result.

`set_build` replaces the approved build. Keys that enrolled under an earlier build stop
verifying until their CDHash resolves under the new build.

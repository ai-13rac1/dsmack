#!/usr/bin/env python3
"""Turn a dsmack App Attest capture into JSON arguments for the contract.

Usage: capture_args.py CAPTURE.json enroll INTERMEDIATE_ID_BASE64
       capture_args.py CAPTURE.json verify ASSERTION_NAME
       capture_args.py build CD_ARGS.json

A capture has the hex fields cert, auth, clientData and kid, and assertions that
have auth, context, r and s (see app-attest/contracts/fixtures in dsmack). The
`build` form reads a cd-args file (cd, page0, ent) for set_build and register_build.
The output is the JSON argument object, ready for a NEAR client.
"""
import base64
import hashlib
import json
import sys


def b64(hex_string: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_string.removeprefix("0x"))).decode()


def main(argv: list[str]) -> None:
    if len(argv) == 3 and argv[1] == "build":
        j = json.load(open(argv[2]))
        out = {"cd": b64(j["cd"]), "page0": b64(j["page0"]), "ent": b64(j["ent"])}
    elif len(argv) == 4 and argv[2] == "enroll":
        j = json.load(open(argv[1]))
        out = {"id": argv[3], "cert": b64(j["cert"]), "auth": b64(j["auth"]), "client_data": b64(j["clientData"])}
    elif len(argv) == 4 and argv[2] == "verify":
        j = json.load(open(argv[1]))
        a = j[argv[3]]
        # The context is the SHA-256 of the bytes that the app passed to generateAssertion.
        context = hashlib.sha256(bytes.fromhex(a["context"].removeprefix("0x"))).digest()
        out = {
            "context": base64.b64encode(context).decode(),
            "proof": {"kid": b64(j["kid"]), "auth": b64(a["auth"]), "r": b64(a["r"]), "s": b64(a["s"])},
        }
    else:
        sys.exit(__doc__)
    print(json.dumps(out))


main(sys.argv)

#!/usr/bin/env python3
"""Turn the files that a Mac writes for App Attest into a capture for capture_args.py.

Usage: capture_from_device.py ENROLL_DIR [NAME=ASSERTION.cbor:CLIENT_DATA ...]

ENROLL_DIR holds the output of `mar enroll`: keyId.txt, clientData.bin and
attestation.cbor. Each NAME=ASSERTION.cbor:CLIENT_DATA is one assertion: the object
that generateAssertion returned, and the bytes whose SHA-256 the app passed to it as
clientDataHash.

The tool checks that the key ID is the hash of the leaf certificate's key and that
each assertion signature verifies with that key. A failed check stops the tool, so
mixed-up files are found before the 3-day enrollment window starts to run out.
The output is a capture in the format of app-attest/contracts/fixtures/live-apple.json.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cryptography import x509  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

from verifier.core import decode  # noqa: E402


def hx(data: bytes) -> str:
    return "0x" + data.hex()


def fail(message: str) -> None:
    sys.exit(f"capture_from_device: {message}")


def capture(enroll_dir: Path, assertions: list[tuple[str, Path, Path]]) -> dict:
    kid = base64.b64decode((enroll_dir / "keyId.txt").read_text().strip(), validate=True)
    if len(kid) != 32:
        fail("keyId.txt is not 32 bytes of base64")
    client_data = (enroll_dir / "clientData.bin").read_bytes()
    att = decode((enroll_dir / "attestation.cbor").read_bytes())
    if not isinstance(att, dict) or att.get("fmt") != "apple-appattest":
        fail("attestation.cbor is not an apple-appattest object")
    x5c = att["attStmt"]["x5c"]
    auth = att["authData"]
    leaf = x509.load_der_x509_certificate(x5c[0])
    key = leaf.public_key()
    point = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if hashlib.sha256(point).digest() != kid:
        fail("keyId.txt is not the SHA-256 of the leaf certificate key")
    out = {
        "cert": hx(x5c[0]),
        "auth": hx(auth),
        "clientData": hx(client_data),
        "kid": hx(kid),
        "appHash": hx(auth[:32]),
        "aaguid": hx(auth[37:53]),
    }
    for name, path, context_path in assertions:
        obj = decode(path.read_bytes())
        a_auth, sig = obj["authenticatorData"], obj["signature"]
        context = context_path.read_bytes()
        nonce = hashlib.sha256(a_auth + hashlib.sha256(context).digest()).digest()
        try:
            key.verify(sig, nonce, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            fail(f"{name}: the signature does not verify over {context_path.name}")
        r, s = decode_dss_signature(sig)
        out[name] = {"context": hx(context), "auth": hx(a_auth), "r": hx(r.to_bytes(32, "big")), "s": hx(s.to_bytes(32, "big"))}
    return out


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        sys.exit(__doc__)
    assertions = []
    for arg in argv[2:]:
        name, _, files = arg.partition("=")
        cbor, _, context = files.partition(":")
        if not (name and cbor and context):
            sys.exit(__doc__)
        assertions.append((name, Path(cbor), Path(context)))
    print(json.dumps(capture(Path(argv[1]), assertions), indent=2))


if __name__ == "__main__":
    main(sys.argv)

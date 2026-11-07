"""Tests of capture_from_device.py and capture_args.py with the live-apple capture."""
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
LIVE = json.loads((REPO / "app-attest/contracts/fixtures/live-apple.json").read_text())


def unhex(v: str) -> bytes:
    return bytes.fromhex(v.removeprefix("0x"))


def cbor(v) -> bytes:
    """Definite-length CBOR of bytes, text, lists and maps: the App Attest wire subset."""
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError(n)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())


def device_files(tmp: Path) -> list[str]:
    """Write the files of `mar enroll` and two assertions, rebuilt from live-apple.json."""
    inter = (REPO / "app-attest/contracts/fixtures/apple-intermediate.der").read_bytes()
    att = {"fmt": "apple-appattest", "attStmt": {"x5c": [unhex(LIVE["cert"]), inter], "receipt": b""}, "authData": unhex(LIVE["auth"])}
    (tmp / "attestation.cbor").write_bytes(cbor(att))
    (tmp / "clientData.bin").write_bytes(unhex(LIVE["clientData"]))
    (tmp / "keyId.txt").write_text(base64.b64encode(unhex(LIVE["kid"])).decode() + "\n")
    args = []
    for name in ("a1", "a2"):
        a = LIVE[name]
        sig = encode_dss_signature(int(a["r"], 16), int(a["s"], 16))
        (tmp / f"{name}.cbor").write_bytes(cbor({"signature": sig, "authenticatorData": unhex(a["auth"])}))
        (tmp / f"{name}.bin").write_bytes(unhex(a["context"]))
        args.append(f"{name}={tmp / (name + '.cbor')}:{tmp / (name + '.bin')}")
    return args


def run(tool: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(HERE / tool), *args], capture_output=True, text=True)


def test_device_files_give_the_capture(tmp_path):
    r = run("capture_from_device.py", str(tmp_path), *device_files(tmp_path))
    assert r.returncode == 0, r.stderr
    got = json.loads(r.stdout)
    for k in ("cert", "auth", "clientData", "kid", "appHash", "aaguid"):
        assert got[k] == LIVE[k], k
    for name in ("a1", "a2"):
        assert got[name] == {k: LIVE[name][k] for k in ("context", "auth", "r", "s")}


def test_wrong_client_data_fails(tmp_path):
    args = device_files(tmp_path)
    swapped = [args[0].replace("a1.bin", "a2.bin")]
    r = run("capture_from_device.py", str(tmp_path), *swapped)
    assert r.returncode != 0 and "a1: the signature does not verify" in r.stderr


def test_wrong_key_id_fails(tmp_path):
    device_files(tmp_path)
    (tmp_path / "keyId.txt").write_text(base64.b64encode(bytes(32)).decode())
    r = run("capture_from_device.py", str(tmp_path))
    assert r.returncode != 0 and "not the SHA-256 of the leaf certificate key" in r.stderr


def b64(v: str) -> str:
    return base64.b64encode(unhex(v)).decode()


def test_capture_args(tmp_path):
    path = REPO / "app-attest/contracts/fixtures/live-apple.json"
    enroll = json.loads(run("capture_args.py", str(path), "enroll", "SUQ=").stdout)
    assert enroll == {"id": "SUQ=", "cert": b64(LIVE["cert"]), "auth": b64(LIVE["auth"]), "client_data": b64(LIVE["clientData"])}
    verify = json.loads(run("capture_args.py", str(path), "verify", "a1").stdout)
    a = LIVE["a1"]
    context = base64.b64encode(hashlib.sha256(unhex(a["context"])).digest()).decode()
    assert verify == {"context": context, "proof": {"kid": b64(LIVE["kid"]), "auth": b64(a["auth"]), "r": b64(a["r"]), "s": b64(a["s"])}}
    cd = REPO / "contracts/fixtures/cd-args-probe-macos.json"
    j = json.loads(cd.read_text())
    build = json.loads(run("capture_args.py", "build", str(cd)).stdout)
    assert build == {"cd": b64(j["cd"]), "page0": b64(j["page0"]), "ent": b64(j["ent"])}


@pytest.mark.parametrize("args", [[], ["x.json", "other"]])
def test_capture_args_usage(args):
    r = run("capture_args.py", *args)
    assert r.returncode != 0 and "Usage" in r.stderr

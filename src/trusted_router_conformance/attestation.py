"""Fresh, locally signed evidence for the SDKs' public cryptographic verifiers."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

CASES = frozenset(
    {
        "valid",
        "invalid-signature",
        "expired",
        "wrong-issuer",
        "wrong-audience",
        "wrong-nonce",
        "missing-nonce",
        "wrong-image",
        "missing-image-pin",
        "wrong-certificate",
        "missing-certificate-binding",
        "debug-enabled",
        "secure-boot-disabled",
        "missing-expiry",
    }
)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def build_fixture(case: str, certificate_der: bytes) -> dict[str, Any]:
    if case not in CASES:
        raise ValueError(f"unknown attestation case: {case}")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    nonce = secrets.token_hex(32)
    cert_hash = hashlib.sha256(certificate_der).hexdigest()
    image_digest = "sha256:" + "a" * 64
    claims: dict[str, Any] = {
        "iss": "https://confidentialcomputing.googleapis.com",
        "aud": ["quill-cloud"],
        "exp": int(time.time()) + 600,
        "dbgstat": "disabled-since-boot",
        "swname": "CONFIDENTIAL_SPACE",
        "secboot": True,
        "hwmodel": "GCP_AMD_SEV",
        "submods": {"container": {"image_digest": image_digest}},
        "eat_nonce": [nonce, cert_hash],
    }
    if case == "expired":
        claims["exp"] = int(time.time()) - 3600
    elif case == "wrong-issuer":
        claims["iss"] = "https://untrusted.invalid"
    elif case == "wrong-audience":
        claims["aud"] = ["another-workload"]
    elif case == "wrong-nonce":
        claims["eat_nonce"] = [secrets.token_hex(32), cert_hash]
    elif case == "missing-nonce":
        claims["eat_nonce"] = [cert_hash]
    elif case == "wrong-image":
        claims["submods"]["container"]["image_digest"] = "sha256:" + "b" * 64
    elif case == "wrong-certificate":
        claims["eat_nonce"] = [nonce, "c" * 64]
    elif case == "missing-certificate-binding":
        claims["eat_nonce"] = [nonce]
    elif case == "debug-enabled":
        claims["dbgstat"] = "enabled"
    elif case == "secure-boot-disabled":
        claims["secboot"] = False
    elif case == "missing-expiry":
        del claims["exp"]
    header = {"alg": "RS256", "typ": "JWT", "kid": "conformance-ephemeral"}
    payload = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}"
    signature = key.sign(payload.encode(), padding.PKCS1v15(), hashes.SHA256())
    if case == "invalid-signature":
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    return {
        "document": payload + "." + _b64(signature),
        "jwks": {
            "keys": [
                {
                    "kid": header["kid"],
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                    "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
                }
            ]
        },
        "nonce_hex": nonce,
        "certificate_der_base64": base64.b64encode(certificate_der).decode("ascii"),
        "image_digest": None if case == "missing-image-pin" else image_digest,
        "audience": "quill-cloud",
    }

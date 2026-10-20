from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from trusted_router_conformance.attestation import CASES, build_fixture
from trusted_router_conformance.runner import discover_scenarios


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_fixture_is_fresh_public_evidence_bound_to_certificate() -> None:
    first = build_fixture("valid", b"test-leaf")
    second = build_fixture("valid", b"test-leaf")
    assert first["nonce_hex"] != second["nonce_hex"]
    assert first["jwks"] != second["jwks"]
    assert set(first["jwks"]["keys"][0]) == {"kid", "kty", "alg", "use", "n", "e"}
    claims = json.loads(_decode(first["document"].split(".")[1]))
    assert claims["eat_nonce"] == [
        first["nonce_hex"],
        hashlib.sha256(b"test-leaf").hexdigest(),
    ]
    assert claims["exp"] > time.time()
    assert claims["submods"]["container"]["image_digest"] == first["image_digest"]
    assert base64.b64decode(first["certificate_der_base64"]) == b"test-leaf"


@pytest.mark.parametrize("case", sorted(CASES))
def test_fixtures_have_valid_signatures_except_signature_attack(case: str) -> None:
    fixture = build_fixture(case, b"test-leaf")
    key = fixture["jwks"]["keys"][0]
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(_decode(key["e"]), "big"),
        int.from_bytes(_decode(key["n"]), "big"),
    ).public_key()
    header, claims, signature = fixture["document"].split(".")
    args = (
        _decode(signature),
        f"{header}.{claims}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    if case == "invalid-signature":
        with pytest.raises(InvalidSignature):
            public_key.verify(*args)
    else:
        public_key.verify(*args)


def test_every_evidence_mutation_is_exercised_with_an_explicit_verdict() -> None:
    scenarios = [s for s in discover_scenarios().values() if s.attestation_case]
    assert {s.attestation_case for s in scenarios} == CASES
    for scenario in scenarios:
        assert scenario.expect["value_json_subset"] == {
            "verified": scenario.attestation_case == "valid"
        }
        assert scenario.expect["attempts"] == 0
        assert scenario.actions == ()


def test_unknown_fixture_case_fails_closed() -> None:
    with pytest.raises(ValueError, match="unknown attestation case"):
        build_fixture("typo", b"leaf")

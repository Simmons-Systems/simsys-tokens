import hashlib
import json
import pathlib

import pytest

from simsys_tokens.hashing import (
    handle_of,
    mint_token,
    token_hash,
    validate_handle,
    validate_role,
    validate_service,
)

VECTORS = json.loads((pathlib.Path(__file__).parent / "vectors.json").read_text())


@pytest.mark.parametrize("v", VECTORS["hash_vectors"])
def test_hash_matches_shared_vectors(v):
    assert token_hash(v["raw"]) == v["sha256"]


def test_preimage_is_the_full_token_not_the_hex_tail():
    raw = "demo-read-" + "a" * 64
    assert token_hash(raw) == hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert token_hash(raw) != hashlib.sha256(("a" * 64).encode("utf-8")).hexdigest()


def test_mint_shape():
    tok = mint_token("demo", "agent")
    service, role, hexpart = tok.split("-")
    assert (service, role) == ("demo", "agent")
    assert len(hexpart) == 64
    assert int(hexpart, 16) >= 0


def test_mint_is_unique():
    assert mint_token("s", "r") != mint_token("s", "r")


@pytest.mark.parametrize("slug", VECTORS["valid_slugs"])
def test_valid_slugs_accepted(slug):
    validate_service(slug)
    validate_role(slug)


@pytest.mark.parametrize("slug", VECTORS["invalid_slugs"])
def test_invalid_slugs_rejected(slug):
    with pytest.raises(ValueError):
        validate_service(slug)
    with pytest.raises(ValueError):
        validate_role(slug)


def test_handle_is_16_hex():
    assert handle_of("a" * 64) == "a" * 16


@pytest.mark.parametrize("bad", ["a" * 15, "a" * 17, "A" * 16, "z" * 16, "", "a" * 16 + "\n"])
def test_bad_handles_rejected(bad):
    with pytest.raises(ValueError):
        validate_handle(bad)


def test_trailing_newline_is_rejected_everywhere():
    # `$` in a Python regex matches before a trailing newline; fullmatch does not.
    # Without this the string "agent\n" becomes a legal role and lands in a token.
    for bad in ("agent\n", "demo\n"):
        with pytest.raises(ValueError):
            validate_role(bad)
        with pytest.raises(ValueError):
            validate_service(bad)

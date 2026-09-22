import pytest

from simsys_tokens.csrf import check_origin

SITE = "https://tokens.example.com"


def test_exact_origin_passes():
    assert check_origin(SITE, SITE, None) is True


def test_foreign_origin_fails():
    assert check_origin(SITE, "https://evil.example", None) is False


def test_referer_is_accepted_when_origin_is_absent():
    assert check_origin(SITE, None, f"{SITE}/ui/") is True


def test_foreign_referer_fails():
    assert check_origin(SITE, None, "https://evil.example/x") is False


def test_neither_header_fails_closed():
    # A default-allow here is a complete bypass of the control, and the
    # foreign-Origin case passes whether or not this branch is handled.
    assert check_origin(SITE, None, None) is False


@pytest.mark.parametrize("near", [
    "https://tokens.example.com.evil.example",
    "http://tokens.example.com",
    "https://tokens.example.com:8443",
])
def test_near_miss_origins_fail(near):
    assert check_origin(SITE, near, None) is False


def test_site_origin_must_be_absolute():
    with pytest.raises(ValueError):
        check_origin("not-an-origin", "not-an-origin", None)

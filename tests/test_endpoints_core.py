import pytest

from simsys_tokens.core import Endpoints
from simsys_tokens.models import SessionIdentity
from simsys_tokens.store import Store, ensure_schema

SITE = "https://tokens.example.com"
OP = SessionIdentity(user="leon", is_operator=True)
MEMBER = SessionIdentity(user="member", is_operator=False)


@pytest.fixture()
def ep(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    return Endpoints(Store(db, "demo"), SITE)


def _mint(ep, label="scout"):
    status, body = ep.handle_create(OP, None, {"label": label, "role": "agent"}, SITE, None)
    assert status == 201
    return body


# --- authorization ---------------------------------------------------------

def test_anonymous_is_401(ep):
    assert ep.handle_list(None, None, {})[0] == 401


def test_bearer_is_403_on_every_endpoint_including_list(ep):
    raw = _mint(ep)["token"]
    assert ep.handle_list(None, raw, {})[0] == 403
    assert ep.handle_create(None, raw, {"label": "x", "role": "agent"}, SITE, None)[0] == 403
    assert ep.handle_delete(None, raw, "0" * 16, SITE, None)[0] == 403


def test_non_operator_session_is_403_including_list(ep):
    # The listing is the endpoint dropped from enumerations. On a member-facing
    # portal an ungated GET hands the roster to any member with a login.
    assert ep.handle_list(MEMBER, None, {})[0] == 403
    assert ep.handle_create(MEMBER, None, {"label": "x", "role": "agent"}, SITE, None)[0] == 403


# --- CSRF ------------------------------------------------------------------

@pytest.mark.parametrize("origin,referer", [("https://evil.example", None), (None, None)])
def test_mutations_reject_bad_or_absent_origin(ep, origin, referer):
    assert ep.handle_create(OP, None, {"label": "x", "role": "agent"}, origin, referer)[0] == 403
    h = _mint(ep, "y")["handle"]
    assert ep.handle_patch(OP, None, h, {"label": "z"}, origin, referer)[0] == 403
    assert ep.handle_delete(OP, None, h, origin, referer)[0] == 403


def test_list_is_not_csrf_checked(ep):
    assert ep.handle_list(OP, None, {})[0] == 200


# --- ordering --------------------------------------------------------------

def test_credentials_are_checked_before_existence(ep):
    # An unauthenticated caller must not be able to probe which handles exist.
    assert ep.handle_delete(None, None, "0" * 16, SITE, None)[0] == 401
    assert ep.handle_delete(None, None, "deadbeefdeadbeef", SITE, None)[0] == 401


# --- responses -------------------------------------------------------------

def test_create_returns_the_raw_token_exactly_once(ep):
    body = _mint(ep)
    raw = body["token"]
    rows = ep.handle_list(OP, None, {})[1]["tokens"]
    assert all(raw not in str(r) for r in rows)


def test_list_never_exposes_the_full_digest(ep):
    _mint(ep)
    row = ep.handle_list(OP, None, {})[1]["tokens"][0]
    assert len(row["handle"]) == 16
    assert "token_sha256" not in row


def test_list_includes_policy_fields(ep):
    ep.handle_create(OP, None,
                     {"label": "p", "role": "agent", "priority": 5,
                      "rate_limit": '{"per_minute":10}'}, SITE, None)
    row = ep.handle_list(OP, None, {})[1]["tokens"][0]
    assert row["priority"] == 5 and row["rate_limit"] == '{"per_minute":10}'


def test_duplicate_live_label_is_409(ep):
    _mint(ep, "dup")
    assert ep.handle_create(OP, None, {"label": "dup", "role": "agent"}, SITE, None)[0] == 409


def test_bad_body_is_400(ep):
    assert ep.handle_create(OP, None, {"role": "agent"}, SITE, None)[0] == 400
    assert ep.handle_create(OP, None, {"label": "x", "role": "BAD-ROLE"}, SITE, None)[0] == 400


def test_bad_handle_length_is_400(ep):
    assert ep.handle_delete(OP, None, "abc", SITE, None)[0] == 400


def test_non_integer_limit_is_400_not_500(ep):
    assert ep.handle_list(OP, None, {"limit": "abc"})[0] == 400


@pytest.mark.parametrize("body", [
    {"label": "x", "role": "agent", "priority": "high"},
    {"label": "x", "role": "agent", "priority": True},   # isinstance(True, int) is True
    {"label": "x", "role": "agent", "rate_limit": "not json"},
    {"label": "x", "role": "agent", "rate_limit": 10},
    {"label": "x", "role": "agent", "rate_limit": '"just a string"'},
    {"label": "x", "role": "agent", "rate_limit": "[1,2]"},
    {"label": "x", "role": "agent", "rate_limit": "10"},
])
def test_bad_policy_values_are_400(ep, body):
    assert ep.handle_create(OP, None, body, SITE, None)[0] == 400


def test_unknown_handle_is_404(ep):
    assert ep.handle_delete(OP, None, "0" * 16, SITE, None)[0] == 404


def test_patch_can_change_policy_and_label(ep):
    h = _mint(ep, "before")["handle"]
    status, body = ep.handle_patch(OP, None, h, {"label": "after", "priority": 1}, SITE, None)
    assert status == 200 and body["label"] == "after" and body["priority"] == 1


def test_patch_allowed_on_a_revoked_token(ep):
    h = _mint(ep, "gone")["handle"]
    ep.handle_delete(OP, None, h, SITE, None)
    assert ep.handle_patch(OP, None, h, {"label": "was the old scout key"},
                           SITE, None)[0] == 200


def test_patch_cannot_change_role(ep):
    h = _mint(ep)["handle"]
    assert ep.handle_patch(OP, None, h, {"role": "admin"}, SITE, None)[0] == 400


@pytest.mark.parametrize("bad", ["", 42, None])
def test_patch_validates_label_like_create_does(ep, bad):
    h = _mint(ep)["handle"]
    assert ep.handle_patch(OP, None, h, {"label": bad}, SITE, None)[0] == 400


def test_patch_omitting_label_leaves_it_alone(ep):
    h = _mint(ep, "keep-me")["handle"]
    status, body = ep.handle_patch(OP, None, h, {"priority": 3}, SITE, None)
    assert status == 200 and body["label"] == "keep-me"

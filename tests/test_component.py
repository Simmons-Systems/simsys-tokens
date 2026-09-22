import pathlib
import re

# Anchor on __file__, not the cwd: a relative path only resolves when pytest is
# invoked from the repo root.
ASSET = (
    pathlib.Path(__file__).resolve().parents[1]
    / "simsys_tokens" / "static" / "simsys-tokens.js"
).read_text()


def test_defines_the_element():
    assert 'customElements.define("simsys-tokens"' in ASSET


def test_uses_light_dom_not_shadow():
    # Shadow DOM would block the host page's stylesheet, which is how tier 2
    # theming works at all.
    assert "attachShadow" not in ASSET


def test_ships_no_hardcoded_colors():
    # Tier 1 must inherit the page's cascade; tier 2 sets custom properties.
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", ASSET)
    assert not re.search(r"\brgb\(|\bhsl\(", ASSET)


def test_reads_theme_custom_properties():
    for prop in ("--st-bg", "--st-fg", "--st-accent", "--st-border"):
        assert prop in ASSET


def test_renders_nothing_on_403():
    # On a member-facing portal most sessions are not operators; an error box
    # would put "Forbidden" in front of most of the department.
    # Assert the STRUCTURE, not that "403" appears somewhere in the file — a
    # substring check cannot distinguish this guard from a comment mentioning it.
    assert re.search(
        r"res\.status\s*===\s*403\s*\|\|\s*res\.status\s*===\s*401", ASSET
    ), "the 403/401 early-return guard is missing or reshaped"
    assert re.search(r"replaceChildren\(\);\s*\n\s*return;", ASSET), \
        "the guard must clear the element and return, rendering nothing"


def test_the_raw_token_is_never_persisted():
    assert "localStorage" not in ASSET and "sessionStorage" not in ASSET
    # It is written to the DOM exactly once, in the copy-once panel.
    assert ASSET.count("out.token") == 1


def test_every_await_fetch_is_inside_a_catch():
    # `"catch" in ASSET` would be satisfied by the word appearing in a comment.
    # Count instead: every fetch site must have a guard, and an unhandled
    # rejection renders nothing, indistinguishable from the deliberate 403 path.
    fetches = len(re.findall(r"await fetch\(", ASSET))
    catches = len(re.findall(r"\}\s*catch\s*\(", ASSET))
    assert fetches >= 3, "expected fetches in refresh, create and revoke"
    assert catches >= fetches, f"{fetches} fetch sites but only {catches} catch blocks"


def test_connected_callback_cannot_reject_unhandled():
    # connectedCallback is not async, so refresh() there needs an explicit
    # .catch() or a rejection disappears with no symptom at all.
    assert re.search(r"this\.refresh\(\)\.catch\(", ASSET)


def test_listing_requests_revoked_rows():
    # The table renders a "revoked" status column. Without include=revoked the
    # component can never display a row it just revoked.
    assert "include=revoked" in ASSET


def test_refresh_happens_before_the_token_panel_is_shown():
    # refresh() calls replaceChildren(), so the reverse order wipes the
    # one-time panel milliseconds after it appears — the operator never sees
    # the secret and it is unrecoverable. Assert the ordering directly.
    refresh_at = ASSET.index("await this.refresh()")
    show_at = ASSET.index("this._showOnce(out.handle, out.token)")
    assert refresh_at < show_at, "_showOnce must come AFTER await this.refresh()"

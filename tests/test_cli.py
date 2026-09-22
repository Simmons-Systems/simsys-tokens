import json

from simsys_tokens.cli import main


def test_mint_init_creates_the_store(tmp_path, capsys):
    db = tmp_path / "sub" / "tokens.db"
    rc = main(["mint", "--init", "--service", "demo", "--role", "admin",
               "--label", "bootstrap", "--db", str(db)])
    assert rc == 0 and db.exists()
    assert "demo-admin-" in capsys.readouterr().out


def test_mint_without_init_refuses_a_missing_store(tmp_path):
    rc = main(["mint", "--service", "demo", "--role", "admin",
               "--label", "x", "--db", str(tmp_path / "nope.db")])
    assert rc != 0


def test_list_never_creates_a_store(tmp_path):
    # The audit check shells out to `list`; a list that auto-created an empty
    # store would report a never-adopted app as clean.
    db = tmp_path / "nope.db"
    assert main(["list", "--service", "demo", "--db", str(db)]) != 0
    assert not db.exists()


def test_revoke_never_creates_a_store(tmp_path):
    db = tmp_path / "nope.db"
    assert main(["revoke", "--service", "demo", "--handle", "0" * 16,
                 "--db", str(db)]) != 0
    assert not db.exists()


def test_list_json_shows_no_secret(tmp_path, capsys):
    db = tmp_path / "tokens.db"
    main(["mint", "--init", "--service", "demo", "--role", "agent",
          "--label", "scout", "--db", str(db)])
    raw = capsys.readouterr().out.strip().splitlines()[-1]
    main(["list", "--service", "demo", "--db", str(db), "--json"])
    out = capsys.readouterr().out
    assert raw not in out
    assert json.loads(out)[0]["label"] == "scout"


def test_list_reports_truncation_instead_of_silently_paging(tmp_path, capsys, monkeypatch):
    # The conformance check parses this output; a silent truncation would let it
    # conclude "no tokens beyond these" from one page.
    #
    # Patch the CLI's call site, NOT store.MAX_LIMIT. `list_rows(self,
    # include_revoked=False, limit=MAX_LIMIT)` binds that default at def time, so
    # monkeypatching the module attribute afterwards leaves the bound default at
    # 500 and the patch is silently inert.
    import simsys_tokens.store as store_mod
    real = store_mod.Store.list_rows
    monkeypatch.setattr(
        store_mod.Store, "list_rows",
        lambda self, include_revoked=False, limit=2: real(
            self, include_revoked=include_revoked, limit=limit
        ),
    )
    db = tmp_path / "tokens.db"
    for i in range(3):
        main(["mint", "--init", "--service", "demo", "--role", "agent",
              "--label", f"t{i}", "--db", str(db)])
    capsys.readouterr()
    rc = main(["list", "--service", "demo", "--db", str(db)])
    assert rc == 1 and "truncated" in capsys.readouterr().err


def test_revoking_an_already_revoked_token_reports_no_change(tmp_path, capsys):
    db = tmp_path / "tokens.db"
    main(["mint", "--init", "--service", "demo", "--role", "agent",
          "--label", "s", "--db", str(db)])
    handle = capsys.readouterr().out.split("handle: ")[1].split("\n")[0]
    main(["revoke", "--service", "demo", "--handle", handle, "--db", str(db)])
    capsys.readouterr()
    main(["revoke", "--service", "demo", "--handle", handle, "--db", str(db)])
    assert "already revoked" in capsys.readouterr().out


def test_created_by_is_attributable(tmp_path, capsys):
    db = tmp_path / "tokens.db"
    main(["mint", "--init", "--service", "demo", "--role", "agent",
          "--label", "s", "--db", str(db)])
    capsys.readouterr()
    main(["list", "--service", "demo", "--db", str(db), "--json"])
    assert json.loads(capsys.readouterr().out)[0]["created_by"].startswith("cli:")

"""Run: .venv/bin/python scripts/demo.py  ->  http://127.0.0.1:8000/demo

Deliberately has NO stylesheet of its own. Whatever you see is tier 1: the
component inheriting a bare page's cascade. If it is ugly here, it is ugly on
every adopter that does not theme it.
"""

import tempfile
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from simsys_tokens import SessionIdentity, install_tokens

app = FastAPI()
install_tokens(
    app,
    service="demo",
    db_path=Path(tempfile.gettempdir()) / "simsys-tokens-demo.db",
    site_origin="http://127.0.0.1:8000",
    session_resolver=lambda request: SessionIdentity(user="demo", is_operator=True),
)


@app.get("/demo", response_class=HTMLResponse)
def demo():
    return (
        '<!doctype html><meta charset="utf-8"><title>simsys-tokens tier 1</title>'
        "<h1>Tier 1 — no app CSS at all</h1>"
        '<script type="module" src="/simsys-tokens.js"></script>'
        '<simsys-tokens service="demo"></simsys-tokens>'
    )


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)

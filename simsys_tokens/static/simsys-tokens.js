// simsys-tokens: list / create / revoke, in the host page's own styling.
// Light DOM by design so the app's stylesheet can reach in. Ships no colours:
// tier 1 inherits the page cascade, tier 2 sets the --st-* custom properties.
//
// The API path is read from the `api` attribute so a mount with a custom
// api_prefix works: <simsys-tokens service="x" api="/internal/tokens">.
const CSS = `
simsys-tokens { display:block; color:var(--st-fg,currentColor);
  background:var(--st-bg,transparent); font:var(--st-font,inherit); }
simsys-tokens table { width:100%; border-collapse:collapse; }
simsys-tokens th, simsys-tokens td { text-align:left; padding:.4em .6em;
  border-bottom:1px solid var(--st-border,currentColor); }
simsys-tokens .st-new { padding:.6em; border:2px solid var(--st-accent,currentColor);
  border-radius:var(--st-radius,4px); font-family:monospace; word-break:break-all; }
simsys-tokens button { color:inherit; background:transparent;
  border:1px solid var(--st-border,currentColor); border-radius:var(--st-radius,4px);
  padding:.3em .7em; cursor:pointer; font:inherit; }
`;

class SimsysTokens extends HTMLElement {
  connectedCallback() {
    if (!document.getElementById("simsys-tokens-css")) {
      const s = document.createElement("style");
      s.id = "simsys-tokens-css";
      s.textContent = CSS;
      document.head.appendChild(s);
    }
    this.service = this.getAttribute("service") || "";
    this.api = this.getAttribute("api") || "/api/tokens";
    // .catch() because connectedCallback cannot await: without it a rejection
    // here is an unhandled promise rejection with no visible symptom.
    this.refresh().catch(() => {
      this.replaceChildren(this._msg("Could not load the token surface."));
    });
  }

  async refresh() {
    let res;
    try {
      // include=revoked: the table renders a "revoked" status column, and the
      // roster's whole point is "what existed and when did we kill it". Without
      // this the component can never show a revoked row it just created.
      res = await fetch(`${this.api}?include=revoked`,
                        { credentials: "same-origin" });
    } catch (err) {
      // Distinguish "cannot reach the server" from the deliberate silence below.
      this.replaceChildren(this._msg("Could not reach the token service."));
      return;
    }
    if (res.status === 403 || res.status === 401) {
      // Not an operator. Render nothing rather than an error box: on a
      // member-facing portal most sessions land here.
      this.replaceChildren();
      return;
    }
    if (!res.ok) { this.replaceChildren(this._msg("Could not load tokens.")); return; }
    let tokens;
    try {
      ({ tokens } = await res.json());
    } catch (err) {
      this.replaceChildren(this._msg("Token service returned an unreadable response."));
      return;
    }
    this.replaceChildren(this._form(), this._table(tokens));
  }

  _msg(text) { const p = document.createElement("p"); p.textContent = text; return p; }

  _state(r) {
    if (r.revoked_at) return "revoked";
    if (r.expires_at && r.expires_at <= new Date().toISOString()) return "expired";
    return "live";
  }

  _form() {
    const form = document.createElement("form");
    form.innerHTML =
      '<input name="label" placeholder="label, e.g. my-scout" required>' +
      '<input name="role" placeholder="role" required>' +
      '<input name="expires_at" placeholder="expires at (ISO-8601, optional)">' +
      ' <button>Create</button>';
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const body = { label: form.label.value, role: form.role.value };
      if (form.expires_at.value) body.expires_at = form.expires_at.value;
      let res, out;
      try {
        res = await fetch(this.api, {
          method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        });
        out = await res.json();
      } catch (err) {
        this.prepend(this._msg("Could not reach the token service."));
        return;
      }
      if (res.status !== 201) {
        this.prepend(this._msg(out.error || "Create failed."));
        return;
      }
      // ORDER IS LOAD-BEARING: refresh() calls replaceChildren(), so showing
      // the token first and refreshing after would wipe the one-time panel
      // milliseconds after it appeared — the secret would be unrecoverable and
      // the operator would never have seen it. Refresh, THEN prepend.
      await this.refresh();
      this._showOnce(out.handle, out.token);
    });
    return form;
  }

  // The raw token enters the DOM exactly once, here, and is never stored.
  _showOnce(handle, token) {
    const box = document.createElement("div");
    box.className = "st-new";
    box.textContent = token;
    const note = document.createElement("p");
    note.textContent =
      `Handle ${handle}. Copy this now — it is shown once and cannot be recovered. ` +
      `If you lose it, revoke this handle and create another.`;
    this.prepend(box, note);
  }

  _table(rows) {
    const t = document.createElement("table");
    t.innerHTML =
      "<thead><tr><th>Label</th><th>Role</th><th>Created</th><th>Expires</th>" +
      "<th>Last used</th><th>Status</th><th></th></tr></thead>";
    const body = document.createElement("tbody");
    for (const r of rows) {
      const tr = document.createElement("tr");
      for (const v of [r.label, r.role, r.created_at, r.expires_at || "never",
                       r.last_used_at || "never", this._state(r)]) {
        const td = document.createElement("td");
        td.textContent = v;
        tr.appendChild(td);
      }
      const td = document.createElement("td");
      if (!r.revoked_at) {
        const b = document.createElement("button");
        b.textContent = "Revoke";
        b.addEventListener("click", async () => {
          try {
            await fetch(`${this.api}/${r.handle}`,
                        { method: "DELETE", credentials: "same-origin" });
          } catch (err) {
            this.prepend(this._msg("Revoke failed — could not reach the service."));
            return;
          }
          await this.refresh();
        });
        td.appendChild(b);
      }
      tr.appendChild(td);
      body.appendChild(tr);
    }
    t.appendChild(body);
    return t;
  }
}

customElements.define("simsys-tokens", SimsysTokens);

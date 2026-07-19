"""
Analyst Connectivity Dashboard generator.

Usage:
    python build_dashboard.py <ConnectivityRequests.xlsx> <ActionItems.xlsx> [OERequests.xlsx] [output.html]

Produces two self-contained interactive HTML dashboards from the same data:
the analyst page (grouped by Technical Contact, written to the output path)
and an iSolved page (grouped by iSolved Contact, written to isolved.html next
to it), linked to each other in the header. The dashboards themselves can be
refreshed later by uploading new CR / AI Excel exports directly in the page
(no need to rerun this script).

Rules implemented:
  - Monthly production month = Ready For Production date, falling back to
    Production date when RFP is empty.
  - AI pending days = days since last comment, falling back to the AI
    creation (start) date when there is no comment.
"""
import os, sys, json, re
import pandas as pd
from datetime import datetime

# --- Password gate (client-side encryption) ------------------------------
# The dashboards are static, self-contained HTML served from GitHub Pages
# (no backend). A simple overlay is not enough: the content still sits in the
# DOM and can be revealed by deleting the overlay in dev-tools. So instead
# each generated page is ENCRYPTED at build time and shipped as ciphertext
# inside a small unlock wrapper. The real HTML — and the embedded data — is
# genuinely NOT in the file until the correct password decrypts it in the
# browser. Deleting DOM nodes reveals nothing, because there is nothing to
# reveal until decryption.
#
# Scheme (interoperable Python <-> browser Web Crypto, no third-party libs):
#   key material = PBKDF2-HMAC-SHA256(password, salt, iterations) -> 64 bytes
#                  split into a 32-byte cipher key + 32-byte MAC key
#   keystream    = HMAC-SHA256(cipher_key, iv || counter) blocks (CTR mode)
#   ciphertext   = plaintext XOR keystream
#   tag          = HMAC-SHA256(mac_key, iv || ciphertext)   (encrypt-then-MAC)
# A wrong password derives a different key, the tag check fails, and the page
# refuses to decrypt.
#
# The password is NEVER stored in this repo. It is read at build time from the
# DASH_PASSWORD environment variable, or from a local, git-ignored file
# `dashboard_password.txt` next to this script. Only ciphertext (which is
# useless without the password) is written into the committed HTML files.
import hashlib, hmac, struct, base64

PBKDF2_ITER = 200000


def resolve_password():
    pw = os.environ.get("DASH_PASSWORD")
    if pw:
        return pw
    pwfile = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "dashboard_password.txt")
    if os.path.exists(pwfile):
        with open(pwfile, "r", encoding="utf-8") as f:
            pw = f.read().strip()
        if pw:
            return pw
    sys.exit("ERROR: no dashboard password set. Put it in the DASH_PASSWORD "
             "environment variable, or in a git-ignored dashboard_password.txt "
             "next to build_dashboard.py, then rebuild. (Refusing to build an "
             "unprotected dashboard.)")


def encrypt_payload(plaintext, password, iterations=PBKDF2_ITER):
    pt = plaintext.encode("utf-8")
    salt = os.urandom(16)
    iv = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                             iterations, dklen=64)
    key_enc, key_mac = dk[:32], dk[32:]
    ks = bytearray()
    i = 0
    while len(ks) < len(pt):
        ks += hmac.new(key_enc, iv + struct.pack(">I", i), hashlib.sha256).digest()
        i += 1
    ct = bytes(a ^ b for a, b in zip(pt, ks))
    tag = hmac.new(key_mac, iv + ct, hashlib.sha256).digest()
    b = lambda x: base64.b64encode(x).decode()
    return {"v": 1, "salt": b(salt), "iv": b(iv), "iter": iterations,
            "ct": b(ct), "tag": b(tag)}


def wrap_encrypted(html, title, password):
    payload = json.dumps(encrypt_payload(html, password), ensure_ascii=False)
    return WRAPPER.replace("__TITLE__", title).replace("__PAYLOAD__", payload)


# The unlock wrapper: the only thing shipped in cleartext. It prompts for the
# password, decrypts the embedded payload with Web Crypto, and swaps the whole
# document for the decrypted dashboard. The password is cached in sessionStorage
# so navigating between the linked pages within a session only prompts once.
WRAPPER = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>__TITLE__</title>
<style>
  :root{
    --pw-bg:#0e141b; --pw-bg2:#151d27; --pw-glow:rgba(63,181,154,.20);
    --pw-card:#1b232c; --pw-card-line:rgba(255,255,255,.07);
    --pw-ink:#eef2f6; --pw-muted:#94a3b1;
    --pw-field:#0f161d; --pw-field-line:#2b3743; --pw-ring:rgba(63,181,154,.32);
    --pw-accent:#3fb59a; --pw-accent2:#2f9d85; --pw-on-accent:#08211b; --pw-err:#f0736f;
  }
  :root[data-pw-theme="light"]{
    --pw-bg:#e9ede8; --pw-bg2:#f6f8f4; --pw-glow:rgba(15,111,92,.15);
    --pw-card:#ffffff; --pw-card-line:#e4e8e3;
    --pw-ink:#17222e; --pw-muted:#5b6b7b;
    --pw-field:#f6f8f5; --pw-field-line:#d8ded8; --pw-ring:rgba(15,143,118,.25);
    --pw-accent:#0f8f76; --pw-accent2:#0f6f5c; --pw-on-accent:#ffffff; --pw-err:#c0392b;
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%}
  #pw-gate{position:fixed;inset:0;z-index:99999;display:none;align-items:center;justify-content:center;padding:24px;
    font:15px/1.5 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:var(--pw-ink);
    background:radial-gradient(1100px 560px at 50% -12%, var(--pw-glow), transparent 62%),
               linear-gradient(180deg, var(--pw-bg2), var(--pw-bg));}
  #pw-gate.show{display:flex}
  .pw-card{width:100%;max-width:384px;background:var(--pw-card);border:1px solid var(--pw-card-line);
    border-radius:18px;padding:38px 34px 30px;text-align:center;
    box-shadow:0 1px 0 rgba(255,255,255,.05) inset, 0 30px 70px -22px rgba(0,0,0,.55);
    animation:pw-in .45s cubic-bezier(.2,.7,.2,1) both}
  @keyframes pw-in{from{opacity:0;transform:translateY(12px) scale(.985)}to{opacity:1;transform:none}}
  .pw-badge{width:66px;height:66px;margin:0 auto 20px;border-radius:20px;display:grid;place-items:center;color:#fff;
    background:linear-gradient(145deg,var(--pw-accent),var(--pw-accent2));
    box-shadow:0 14px 30px -10px var(--pw-accent), 0 0 0 1px rgba(255,255,255,.14) inset}
  .pw-card h1{font-size:21px;font-weight:680;letter-spacing:.2px;margin:0 0 7px}
  .pw-card p{font-size:13.5px;color:var(--pw-muted);margin:0 0 22px}
  #pw-input{width:100%;padding:13px 15px;border:1px solid var(--pw-field-line);border-radius:11px;
    background:var(--pw-field);color:var(--pw-ink);font-size:15px;outline:none;margin-bottom:14px;
    transition:border-color .15s, box-shadow .15s}
  #pw-input::placeholder{color:var(--pw-muted);opacity:.85}
  #pw-input:focus{border-color:var(--pw-accent);box-shadow:0 0 0 3px var(--pw-ring)}
  #pw-btn{position:relative;width:100%;padding:13px;border:0;border-radius:11px;cursor:pointer;
    font-size:15px;font-weight:680;letter-spacing:.3px;color:var(--pw-on-accent);
    background:linear-gradient(145deg,var(--pw-accent),var(--pw-accent2));
    box-shadow:0 12px 26px -12px var(--pw-accent);transition:transform .08s, filter .15s, opacity .15s}
  #pw-btn:hover:not(:disabled){filter:brightness(1.07)}
  #pw-btn:active:not(:disabled){transform:translateY(1px)}
  #pw-btn:disabled{cursor:default;opacity:.85}
  #pw-btn.loading .pw-btn-label{visibility:hidden}
  .pw-spin{position:absolute;left:50%;top:50%;width:18px;height:18px;margin:-9px 0 0 -9px;border-radius:50%;
    border:2px solid currentColor;border-right-color:transparent;opacity:0;animation:pw-spin .7s linear infinite}
  #pw-btn.loading .pw-spin{opacity:.9}
  @keyframes pw-spin{to{transform:rotate(360deg)}}
  #pw-error{color:var(--pw-err);font-size:13px;margin-top:14px;min-height:17px;font-weight:560}
  .pw-card.shake{animation:pw-shake .4s}
  @keyframes pw-shake{10%,90%{transform:translateX(-1px)}20%,80%{transform:translateX(2px)}
    30%,50%,70%{transform:translateX(-5px)}40%,60%{transform:translateX(5px)}}
  @media(prefers-reduced-motion:reduce){.pw-card,.pw-spin{animation:none}}
</style>
</head>
<body>
<div id="pw-gate">
  <form id="pw-form" autocomplete="off">
    <div class="pw-card">
      <div class="pw-badge">
        <svg viewBox="0 0 24 24" width="30" height="30" fill="none" stroke="currentColor"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="4" y="10.5" width="16" height="10.5" rx="2.3"></rect>
          <path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"></path>
          <circle cx="12" cy="15.6" r="1.35" fill="currentColor" stroke="none"></circle>
        </svg>
      </div>
      <h1>Protected dashboard</h1>
      <p>Enter the password to continue.</p>
      <input id="pw-input" type="password" placeholder="Password" autocomplete="current-password">
      <button type="submit" id="pw-btn"><span class="pw-btn-label">Unlock</span><span class="pw-spin" aria-hidden="true"></span></button>
      <div id="pw-error" role="alert"></div>
    </div>
  </form>
</div>
<script id="pw-payload" type="application/json">__PAYLOAD__</script>
<script>
(function(){
  var P = JSON.parse(document.getElementById('pw-payload').textContent);
  var SKEY = 'dash-pw';
  var gate = document.getElementById('pw-gate');
  var input = document.getElementById('pw-input');
  var errEl = document.getElementById('pw-error');
  var btn = document.getElementById('pw-btn');

  function b64(s){ return Uint8Array.from(atob(s), function(c){ return c.charCodeAt(0); }); }

  async function decrypt(pw){
    if(!(window.crypto && crypto.subtle)) throw new Error('nocrypto');
    var salt=b64(P.salt), iv=b64(P.iv), ct=b64(P.ct), tag=b64(P.tag);
    var enc = new TextEncoder();
    var base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
    var bits = new Uint8Array(await crypto.subtle.deriveBits(
      {name:'PBKDF2', salt:salt, iterations:P.iter, hash:'SHA-256'}, base, 512));
    var keyEnc = bits.slice(0,32), keyMac = bits.slice(32,64);
    var macKey = await crypto.subtle.importKey('raw', keyMac, {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
    var macMsg = new Uint8Array(iv.length+ct.length); macMsg.set(iv,0); macMsg.set(ct,iv.length);
    var calc = new Uint8Array(await crypto.subtle.sign('HMAC', macKey, macMsg));
    if(calc.length!==tag.length || !calc.every(function(x,i){ return x===tag[i]; })) throw new Error('badpw');
    var encKey = await crypto.subtle.importKey('raw', keyEnc, {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
    var n = Math.ceil(ct.length/32), jobs=[];
    for(var i=0;i<n;i++){
      var msg = new Uint8Array(iv.length+4); msg.set(iv,0);
      new DataView(msg.buffer).setUint32(iv.length, i, false);
      jobs.push(crypto.subtle.sign('HMAC', encKey, msg));
    }
    var blocks = await Promise.all(jobs);
    var ks = new Uint8Array(n*32);
    blocks.forEach(function(b,i){ ks.set(new Uint8Array(b), i*32); });
    var out = new Uint8Array(ct.length);
    for(var j=0;j<ct.length;j++) out[j] = ct[j] ^ ks[j];
    return new TextDecoder('utf-8').decode(out);
  }

  // match the gate to the user's saved dashboard theme (falls back to the OS setting)
  try{
    var t = localStorage.getItem('dashTheme');
    if(t!=='dark' && t!=='light') t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.setAttribute('data-pw-theme', t);
  }catch(e){}

  var card = document.querySelector('.pw-card');
  function reveal(html){ document.open(); document.write(html); document.close(); }
  function showPrompt(){ gate.classList.add('show'); input.focus(); }
  function busy(on){ btn.disabled=on; btn.classList.toggle('loading', on); }

  async function tryPw(pw, fromSaved){
    try{
      var html = await decrypt(pw);
      try{ sessionStorage.setItem(SKEY, pw); }catch(e){}
      reveal(html);
    }catch(err){
      try{ sessionStorage.removeItem(SKEY); }catch(e){}
      busy(false);
      if(fromSaved){ showPrompt(); return; }
      errEl.textContent = (err && err.message==='badpw') ? 'Incorrect password.'
        : 'Could not unlock — this page must be opened over HTTPS to decrypt.';
      if(card){ card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake'); }
      input.select();
    }
  }

  document.getElementById('pw-form').addEventListener('submit', function(ev){
    ev.preventDefault();
    errEl.textContent=''; busy(true);
    tryPw(input.value, false);
  });

  var saved=null; try{ saved=sessionStorage.getItem(SKEY); }catch(e){}
  if(saved){ tryPw(saved, true); } else { showPrompt(); }
})();
</script>
</body>
</html>
"""

CR_KEEP = ["Request ID", "Carrier", "Customer", "Instance", "Request Type",
           "Migration", "IsMigration", "Is Migration", "Migration Request",
           "Migration Type", "Migration Phase",
           "Stage", "Status", "Technical Contact", "iSolved Contact",
           "Created Date", "Assignment Date", "Requirements Gathering",
           "Resource Assignment", "Dataset Validation", "Mapping", "Testing",
           "Ready For Production", "Production", "First Test File",
           "First Production File"]
AI_KEEP = ["ActionItemID", "ActionItemTitle", "ClientName", "CarrierName",
           "Requestor", "CurrentlyPendingOn", "StartDate", "DueDate",
           "Due Date", "DueOn", "LastCommentOwner", "LastCommentDate",
           "LastComment", "ConnectivityRequestID"]
OE_KEEP = ["OERequestID", "ConnectivityRequestID", "ClientName", "CarrierName",
           "RequestType", "PlanYearStartDate", "ClientDataExpectedDate",
           "ISolvedDataChanges", "UpdatedGroupStructure", "Status", "Stage",
           "TechnicalContact", "DataReadyDate", "OEFileSubmissionDate",
           "IsolvedContact", "CanResumeProductionPYSD", "ResumedProduction",
           "IsDraftOERequest", "Created", "CreatedBy"]
# MigrationSummary: joins to a CR by ConnectivityRequestID; MigrationTestingDate
# splits the Testing stage into internal (before) and carrier (after) testing
MS_KEEP = ["ConnectivityRequestID", "MigrationTestingDate"]
ACTIVE = ["In Progress", "Blocked", "On Hold", "Not Started"]

# mirrors norm()/baseKey() in the dashboard JS so the embed mask keeps every
# CR that an action item could attach to
_STOP = re.compile(r"\b(inc|llc|llp|ltd|co|corp|corporation|company|the|of)\b")


def _norm(s):
    s = re.sub(r"[^a-z0-9 ]", " ", str("" if s is None else s).lower())
    return re.sub(r"\s+", " ", _STOP.sub("", s)).strip()


def _base_key(client, carrier):
    return (_norm(client), _norm(re.sub(r"\(.*?\)", " ", str("" if carrier is None else carrier))))


def detect(paths):
    cr = ai = oe = None
    for p in paths:
        cols = set(pd.read_excel(p, nrows=0).columns)
        if "ActionItemID" in cols or "CurrentlyPendingOn" in cols:
            ai = p
        elif "OERequestID" in cols:
            oe = p
        elif "Request ID" in cols:
            cr = p
    if not cr or not ai:
        sys.exit("Could not identify the CR and AI reports from the given files.")
    return cr, ai, oe


def records(df, keep):
    df = df[[c for c in keep if c in df.columns]].copy()
    for c in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[c]):
            df[c] = df[c].dt.strftime("%Y-%m-%d")
    recs = json.loads(df.to_json(orient="records", date_format="iso"))
    return [{k: v for k, v in r.items() if v is not None} for r in recs]


def find_ms(paths):
    """Return the MigrationSummary frame from wherever it lives — a sheet in any
    of the given workbooks, or a standalone file — identified by the presence of
    the MigrationTestingDate column. First match wins; None if not present."""
    for p in paths:
        try:
            with pd.ExcelFile(p) as xl:
                for sh in xl.sheet_names:
                    try:
                        cols = pd.read_excel(xl, sheet_name=sh, nrows=0).columns
                    except Exception:
                        continue
                    if "MigrationTestingDate" in cols:
                        return pd.read_excel(xl, sheet_name=sh)
        except Exception:
            continue
    return None


def main():
    args = sys.argv[1:]
    out = "Analyst_Dashboard.html"
    if args and args[-1].lower().endswith((".html", ".htm")):
        out = args.pop()
    if len(args) < 2:
        sys.exit(__doc__)
    cr_path, ai_path, oe_path = detect(args)

    cr = pd.read_excel(cr_path)
    ai = pd.read_excel(ai_path)
    for c in ["StartDate", "LastCommentDate", "DueDate", "Due Date", "DueOn"]:
        if c in ai.columns:
            ai[c] = pd.to_datetime(ai[c], errors="coerce")

    # embed only rows the dashboards can use: every active CR (including ones
    # with no technical contact — the team page counts those as unassigned),
    # anything with a prod/RFP date, anything an action item points at, and
    # anything created in the last ~13 months so the team page's intake trend
    # is complete (CRs later cancelled still count as intake)
    ai_keys = {_base_key(r.get("ClientName"), r.get("CarrierName"))
               for _, r in ai.iterrows()}
    cr_keys = cr.apply(lambda r: _base_key(r.get("Customer"), r.get("Carrier")), axis=1)
    recent = pd.to_datetime(cr["Created Date"], errors="coerce") \
        >= (datetime.now() - pd.Timedelta(days=400))
    mask = cr["Status"].isin(ACTIVE) \
        | cr["Ready For Production"].notna() | cr["Production"].notna() \
        | cr_keys.isin(ai_keys) | recent.fillna(False)
    if "ConnectivityRequestID" in ai.columns:
        mask |= cr["Request ID"].isin(ai["ConnectivityRequestID"].dropna())
    oe_recs = []
    if oe_path:
        oe = pd.read_excel(oe_path)
        oe_recs = records(oe[oe["Status"].isin(ACTIVE)], OE_KEEP)
    ms_recs = []
    ms = find_ms(args)
    if ms is not None:
        if "MigrationTestingDate" in ms.columns:
            ms["MigrationTestingDate"] = pd.to_datetime(ms["MigrationTestingDate"], errors="coerce")
        ms_recs = records(ms, MS_KEEP)
    today = datetime.now().strftime("%Y-%m-%d")
    raw = {"generated": today,
           "dates": {"cr": today, "ai": today, "oe": today if oe_path else None},
           "cr": records(cr[mask], CR_KEEP), "ai": records(ai, AI_KEEP),
           "oe": oe_recs, "ms": ms_recs}

    raw_json = json.dumps(raw, ensure_ascii=False)

    password = resolve_password()

    def page(role, title, who, other_href, other_label):
        return (TEMPLATE.replace("__RAW__", raw_json)
                .replace("__ROLE__", role)
                .replace("__TITLE__", title)
                .replace("__WHO__", who)
                .replace("__OTHER_HREF__", other_href)
                .replace("__OTHER_LABEL__", other_label))

    iso_out = os.path.join(os.path.dirname(out), "isolved.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(wrap_encrypted(
            page("tc", "Analyst Dashboard", "analyst",
                 os.path.basename(iso_out), "Switch to iSolved view"),
            "Analyst Dashboard", password))
    with open(iso_out, "w", encoding="utf-8") as f:
        f.write(wrap_encrypted(
            page("isolved", "iSolved Dashboard", "iSolved contact",
                 os.path.basename(out), "Switch to Analyst view"),
            "iSolved Dashboard", password))
    team_out = os.path.join(os.path.dirname(out), "team.html")
    with open(team_out, "w", encoding="utf-8") as f:
        f.write(wrap_encrypted(
            TEAM_TEMPLATE.replace("__RAW__", raw_json),
            "Team Overview", password))
    print(f"Wrote {out} + {iso_out} + {team_out} (encrypted): {int(mask.sum())} CR rows, "
          f"{len(ai)} AI rows, {len(oe_recs)} OE rows, {len(ms_recs)} MS rows embedded")


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>__TITLE__</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
<style>
  :root{
    --ink:#1b2733; --ink-soft:#5b6b7b; --paper:#f5f6f4; --card:#ffffff;
    --line:#e2e6e1; --accent:#0f6f5c; --accent-soft:#e2f0ec;
    --amber:#965900; --amber-bg:#fdf2df; --red:#b3261e; --red-bg:#fbe9e7;
    --blue:#2b5d8a; --blue-bg:#e7eff6;
    --head:#1b2733; --pop:#1b2733; --th-bg:#fafbf9; --bar:#c9d6d1;
    --ring:rgba(27,39,51,.3); --chip-mute:#ececec; --chip-mute-ink:#555;
    /* stage colors: classic multi-hue palette, validated (s0 = intentionally
       neutral "pending"; blues separated for colorblind safety) */
    --s0:#8fa3bd; --s1:#5f8fd4; --s2:#38619e; --s3:#008aa0;
    --s4:#0f9682; --s5:#3f9d54; --s6:#b26a00; --s7:#00845f;
    --mono:'SF Mono',Consolas,'Liberation Mono',monospace;
    color-scheme:light;
  }
  :root[data-theme="dark"]{
    --ink:#e8edf2; --ink-soft:#9aa8b5; --paper:#12181f; --card:#1b232c;
    --line:#2c3742; --accent:#3fb59a; --accent-soft:#173229;
    --amber:#e0a24a; --amber-bg:#33270f; --red:#e57373; --red-bg:#3a1d1a;
    --blue:#7aa7cf; --blue-bg:#1c2a38;
    --head:#0d1319; --pop:#0d1319; --th-bg:#202a34; --bar:#3a4a45;
    --ring:rgba(232,237,242,.35); --chip-mute:#2c3742; --chip-mute-ink:#b6c2cd;
    /* dark stage colors — same hues re-selected for the dark surface */
    --s0:#7b8ca6; --s1:#6b95d6; --s2:#4a6fae; --s3:#1897ad;
    --s4:#1fa28e; --s5:#4fa960; --s6:#c08228; --s7:#2f9d85;
    color-scheme:dark;
  }
  *{box-sizing:border-box;margin:0}
  body{font:15px/1.45 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
       background:var(--paper);color:var(--ink);padding-bottom:60px}
  header{background:var(--head);color:#fff;padding:16px}
  header .wrap{display:flex;justify-content:space-between;align-items:flex-start;gap:16px 24px;flex-wrap:wrap}
  header h1{font-size:19px;font-weight:650;letter-spacing:.2px}
  header .sub{color:#9fb0bf;margin-top:6px;display:flex;align-items:center;flex-wrap:wrap;gap:8px}
  header .sub .sublabel{font-size:12px;font-weight:600;letter-spacing:.5px;text-transform:uppercase}
  header .sub #gen{display:flex;flex-wrap:wrap;gap:6px}
  header .sub .dchip{font-size:11px;font-weight:650;font-family:var(--mono);
        padding:2px 9px;border-radius:20px;white-space:nowrap}
  header .sub .dchip b{font-weight:700}
  /* the header is dark in both themes, so chips use a translucent tint with
     bright status text rather than the pale card-surface colours */
  header .sub .dchip.idle-ok{background:rgba(63,181,154,.15);color:#6fd0b6}
  header .sub .dchip.idle-warn{background:rgba(224,162,74,.17);color:#e8bd77}
  header .sub .dchip.idle-bad{background:rgba(229,115,115,.17);color:#f0a19d}
  .hright{display:flex;flex-direction:column;align-items:flex-end;gap:8px}
  .htop{display:flex;align-items:center;gap:12px}
  .viewlink{color:#9fb0bf;font-size:12.5px;text-decoration:underline dotted;
        text-underline-offset:2px;white-space:nowrap;display:inline-block;margin-top:6px;margin-right:12px}
  .viewlink:hover{color:#fff}
  .upload{display:flex;align-items:center;gap:8px}
  .upload label{background:#2e4155;color:#dfe8f0;font-size:12.5px;font-weight:650;
        padding:8px 14px;border-radius:8px;cursor:pointer;border:1px solid #45596e}
  .upload label:hover{background:#3a5069}
  #themebtn{font:inherit;font-size:15px;line-height:1;background:transparent;color:#9fb0bf;
        border:1px solid #45596e;border-radius:8px;padding:8px 10px;cursor:pointer}
  #themebtn:hover{background:#2e4155;color:#dfe8f0}
  #upmsg{font-size:12px;font-family:var(--mono);max-width:360px;text-align:right}
  #upmsg.ok{color:#8fd6b8} #upmsg.err{color:#ffb3ad}
  .wrap{max-width:1100px;margin:0 auto;padding:0 12px}
  .toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:16px 0 6px}
  select,input#emp{font:inherit;padding:9px 12px;border:1px solid var(--line);border-radius:8px;
         background:var(--card);min-width:230px;font-weight:600}
  .toolbar button{font:inherit;font-weight:650;border:1px solid var(--line);background:var(--card);
         border-radius:8px;padding:9px 14px;cursor:pointer}
  .toolbar button:hover{background:var(--accent-soft)}
  .search{position:relative}
  .search input{font:inherit;padding:9px 12px;border:1px solid var(--line);border-radius:8px;
         background:var(--card);min-width:260px}
  .search .results{display:none;position:absolute;top:calc(100% + 4px);left:0;min-width:100%;
         width:max-content;max-width:420px;background:var(--card);border:1px solid var(--line);
         border-radius:10px;box-shadow:0 4px 14px rgba(0,0,0,.28);z-index:40;max-height:320px;overflow:auto}
  .search .results .hit{padding:8px 12px;cursor:pointer;font-size:13px;border-bottom:1px solid var(--line)}
  .search .results .hit:last-child{border-bottom:none}
  .search .results .hit:hover{background:var(--accent-soft)}
  .search .results .hit small{color:var(--ink-soft);display:block;font-family:var(--mono);font-size:11px}
  .search .results .none{padding:8px 12px;color:var(--ink-soft);font-style:italic;font-size:13px}
  #repmodal{display:none;position:fixed;inset:0;background:rgba(20,30,40,.45);z-index:50;padding:20px}
  #repmodal.open{display:flex;align-items:center;justify-content:center}
  .repbox{background:var(--card);border-radius:12px;max-width:840px;width:100%;max-height:85vh;
         display:flex;flex-direction:column;padding:14px;box-shadow:0 10px 40px rgba(0,0,0,.3)}
  .rephead{display:flex;gap:8px;align-items:center;margin-bottom:10px}
  .rephead b{flex:1;font-size:14.5px}
  .rephead button{font:inherit;font-size:13px;font-weight:650;border:1px solid var(--line);
         background:var(--card);border-radius:8px;padding:6px 12px;cursor:pointer}
  .rephead button:hover{background:var(--accent-soft)}
  #reptext{flex:1;width:100%;min-height:340px;font:12.5px/1.5 var(--mono);border:1px solid var(--line);
         border-radius:8px;padding:10px;resize:vertical;white-space:pre;overflow:auto}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:12px 0 18px}
  .kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
  .kpi b{display:block;font-size:26px;font-weight:700}
  .kpi span{font-size:12px;color:var(--ink-soft);text-transform:uppercase;letter-spacing:.5px}
  .kpi .kpi-sub{display:block;font-size:11px;color:var(--ink-soft);text-transform:none;letter-spacing:0;margin-top:3px}
  h2{font-size:14px;text-transform:uppercase;letter-spacing:.8px;color:var(--ink-soft);
     margin:22px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
  .conn{background:var(--card);border:1px solid var(--line);border-radius:12px;
        padding:14px 16px;margin-bottom:10px}
  .conn .top{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
  .conn .name{font-weight:650;font-size:15.5px}
  .conn .name small{color:var(--ink-soft);font-weight:500}
  .chips{display:flex;gap:6px;flex-wrap:wrap}
  .chip{font-size:11.5px;font-weight:650;padding:3px 9px;border-radius:20px;white-space:nowrap}
  .copybtn{font:inherit;font-size:11.5px;font-weight:650;border:1px solid var(--line);
    background:var(--card);color:var(--ink-soft);border-radius:20px;padding:2px 10px;cursor:pointer;white-space:nowrap}
  .copybtn:hover{background:var(--accent-soft);color:var(--accent)}
  .chip.status-inprogress{background:var(--accent-soft);color:var(--accent)}
  .chip.status-blocked{background:var(--red-bg);color:var(--red)}
  .chip.status-onhold,.chip.status-notstarted{background:var(--chip-mute);color:var(--chip-mute-ink)}
  .chip.ctype{background:transparent;box-shadow:inset 0 0 0 1px var(--line);color:var(--ink-soft)}
  .chip.idle-ok{background:var(--accent-soft);color:var(--accent)}
  .chip.idle-warn{background:var(--amber-bg);color:var(--amber)}
  .chip.idle-bad{background:var(--red-bg);color:var(--red)}
  .rail{display:flex;gap:4px;margin:12px 0 6px}
  .rail .seg{flex:1;display:flex;flex-direction:column;gap:3px;min-width:0;position:relative;cursor:pointer}
  .rail .seg i{display:block;height:7px;border-radius:4px}
  .rail .seg.cur i{box-shadow:0 0 0 2px var(--ring)}
  .rail .seg span{font-size:9.5px;line-height:1.15;color:var(--ink-soft);text-align:center;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .rail .seg.todo span{color:#b6bfc7}
  .rail .seg.cur span{color:var(--ink);font-weight:700}
  .rail .seg .tip{display:none;position:absolute;bottom:calc(100% + 8px);left:50%;transform:translateX(-50%);
    background:var(--pop);color:#eef3f7;font-size:12px;line-height:1.45;padding:8px 11px;border-radius:8px;
    width:max-content;max-width:250px;white-space:normal;text-align:left;z-index:5;
    box-shadow:0 4px 14px rgba(0,0,0,.28);user-select:text;cursor:text}
  .rail .seg .tip::after{content:'';position:absolute;top:100%;left:50%;transform:translateX(-50%);
    border:6px solid transparent;border-top-color:var(--pop)}
  .rail .seg .tip small{display:block;color:#9fb0bf;margin-top:5px;font-size:10.5px;user-select:none}
  .rail .seg:hover .tip{display:block}
  .rail .seg:first-child .tip{left:0;transform:none}
  .rail .seg:last-child .tip{left:auto;right:0;transform:none}
  @media(max-width:600px){ .rail .seg span{display:none} }
  .stageline{font-size:12.5px;color:var(--ink-soft);margin-bottom:8px}
  .stageline b{color:var(--ink)}
  .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:6px 16px;
        font-size:13px;color:var(--ink-soft);margin-top:8px}
  .meta4{grid-template-columns:repeat(4,minmax(0,1fr))}
  @media(max-width:600px){ .meta4{grid-template-columns:1fr 1fr} }
  .meta b{color:var(--ink);font-weight:600}
  .meta .dt,.dt{font-family:var(--mono);font-size:12.5px}
  .aibox{margin-top:10px;border-left:3px solid var(--blue);background:var(--blue-bg);
         border-radius:0 8px 8px 0;padding:8px 12px;font-size:13px}
  .aibox .pend{font-weight:650;color:var(--blue)}
  .aibox .due-ok{color:var(--accent);font-weight:650}
  .aibox .due-warn{color:var(--amber);font-weight:700}
  .aibox .due-over{color:var(--red);font-weight:700}
  .aibox .none{color:var(--ink-soft);font-style:italic}
  details.ailist{margin-top:6px;font-size:12.5px;overflow-x:auto}
  details.ailist summary{cursor:pointer;color:var(--blue);font-weight:600}
  .aitable{display:grid;grid-template-columns:minmax(140px,1fr) max-content max-content max-content max-content max-content;
    gap:4px 16px;margin:8px 0 2px;align-items:baseline}
  .aitable .airow{display:contents}
  .aitable .head span{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--ink-soft)}
  .aitable .num{text-align:right}
  .ainote{font-size:11px;color:var(--ink-soft);font-style:italic;margin-top:4px}
  .cmt{cursor:help;font-size:12px;margin-left:2px}
  #cmtpop{display:none;position:fixed;background:var(--pop);color:#eef3f7;font-size:12px;line-height:1.5;
    padding:8px 11px;border-radius:8px;max-width:320px;white-space:pre-wrap;z-index:99;
    box-shadow:0 4px 14px rgba(0,0,0,.28);pointer-events:none}
  #cmtpop small{display:block;color:#9fb0bf;margin-top:5px;font-size:10.5px;white-space:normal}
  .prodhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:10px}
  .prodhead button{font:inherit;font-weight:700;border:1px solid var(--line);background:var(--card);
        border-radius:8px;padding:6px 12px;cursor:pointer}
  .prodhead select.mon{font-family:var(--mono);font-weight:700;font-size:15px;min-width:0;padding:6px 10px}
  .prodcount{font-size:13px;color:var(--ink-soft)}
  .prodcount b{color:var(--ink);font-size:16px}
  .yearsel{font:inherit;font-weight:700;font-family:var(--mono);font-size:13px;min-width:0;
        padding:2px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);
        color:var(--ink);letter-spacing:0}
  .stagebars{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;
        display:grid;grid-template-columns:max-content 1fr max-content max-content;gap:10px 14px;align-items:center}
  .stagebars .srow{display:contents}
  .stagebars .sname{font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;white-space:nowrap}
  .stagebars .sname i{width:10px;height:10px;border-radius:3px;display:inline-block;flex:none}
  .stagebars .strack{background:var(--paper);border-radius:6px;height:14px;overflow:hidden}
  .stagebars .sbar{height:100%;border-radius:6px;min-width:2px}
  .stagebars .sval{font-family:var(--mono);font-size:12.5px;font-weight:700;text-align:right}
  .stagebars .scnt{font-family:var(--mono);font-size:11px;color:var(--ink-soft);text-align:right}
  .stagebars .scnt .outbtn{color:var(--amber);cursor:pointer;text-decoration:underline dotted;text-underline-offset:2px}
  .stagebars .scnt .outbtn:hover{color:var(--red)}
  .stagebars .souts{grid-column:1/-1;background:var(--paper);border:1px dashed var(--line);border-radius:8px;
        padding:8px 12px;font-size:12.5px;display:flex;flex-direction:column;gap:4px;margin:-2px 0 4px}
  @media(max-width:600px){ .stagebars{grid-template-columns:max-content 1fr max-content} .stagebars .scnt{display:none} }
  .bars{display:flex;align-items:flex-end;gap:6px;height:110px;background:var(--card);
        border:1px solid var(--line);border-radius:10px;padding:12px 12px 26px;margin-bottom:12px}
  .barcol{flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;
          height:100%;position:relative;cursor:pointer}
  .barcol .bar{width:70%;max-width:34px;background:var(--bar);border-radius:4px 4px 0 0;min-height:2px}
  .barcol.sel .bar{background:var(--accent)}
  .barcol .lbl{position:absolute;bottom:-20px;font-size:10px;font-family:var(--mono);color:var(--ink-soft)}
  .barcol .val{font-size:10.5px;font-family:var(--mono);color:var(--ink-soft);margin-bottom:2px}
  table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
        border-radius:10px;overflow:hidden;font-size:13px}
  th{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--ink-soft);
     text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);background:var(--th-bg)}
  td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  tr:last-child td{border-bottom:none}
  td.dt{white-space:nowrap}
  .tag{font-size:10.5px;font-weight:700;padding:1px 7px;border-radius:10px}
  .tag.r{background:var(--accent-soft);color:var(--accent)}
  .tag.p{background:var(--amber-bg);color:var(--amber)}
  .empty{color:var(--ink-soft);font-style:italic;padding:14px}
  a.lnk{color:inherit;text-decoration:underline dotted;text-underline-offset:2px}
  a.lnk:hover{color:var(--blue);text-decoration:underline solid}
  .rankbtn{cursor:pointer}
  @media(max-width:600px){ .meta{grid-template-columns:1fr 1fr} th:nth-child(5),td:nth-child(5){display:none} }

  /* ── UI/UX Pro Max visual upgrade layer ─────────────────────────────
     Appended after the base rules: adds elevation, motion and focus
     polish on top of the existing tokens without changing structure. */
  :root{
    --shadow-sm:0 1px 2px rgba(16,32,44,.05),0 1px 3px rgba(16,32,44,.05);
    --shadow-md:0 2px 8px rgba(16,32,44,.07),0 10px 28px rgba(16,32,44,.07);
    --shadow-lg:0 18px 44px rgba(16,32,44,.16);
    --ease:cubic-bezier(.4,0,.2,1); --t:180ms;
    --focus:0 0 0 3px color-mix(in srgb, var(--accent) 32%, transparent);
    --head-grad:linear-gradient(165deg,#243543 0%,#161f29 100%);
    --accent-grad:linear-gradient(90deg,var(--accent),#12a488);
  }
  :root[data-theme="dark"]{
    --shadow-sm:0 1px 2px rgba(0,0,0,.45);
    --shadow-md:0 2px 10px rgba(0,0,0,.5),0 14px 32px rgba(0,0,0,.4);
    --shadow-lg:0 20px 48px rgba(0,0,0,.6);
    --focus:0 0 0 3px color-mix(in srgb, var(--accent) 42%, transparent);
    --head-grad:linear-gradient(165deg,#121b24 0%,#0a0f15 100%);
    --accent-grad:linear-gradient(90deg,var(--accent),#54c9ae);
  }
  body{-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
  /* header gains depth + a subtle gradient */
  header{background:var(--head-grad);box-shadow:var(--shadow-md);
    border-bottom:1px solid rgba(255,255,255,.06)}
  /* section headings get an accent marker */
  h2{position:relative;padding-left:13px}
  h2::before{content:'';position:absolute;left:0;top:1px;bottom:9px;width:3px;
    border-radius:3px;background:var(--accent-grad)}
  /* KPI cards: elevation + accent strip + hover lift + tabular figures */
  .kpi{position:relative;overflow:hidden;border-radius:12px;box-shadow:var(--shadow-sm);
    transition:transform var(--t) var(--ease),box-shadow var(--t) var(--ease),border-color var(--t) var(--ease)}
  .kpi::before{content:'';position:absolute;inset:0 0 auto 0;height:3px;background:var(--accent-grad)}
  .kpi:hover{transform:translateY(-2px);box-shadow:var(--shadow-md);
    border-color:color-mix(in srgb, var(--accent) 30%, var(--line))}
  .kpi b{font-variant-numeric:tabular-nums;letter-spacing:-.02em}
  /* connection / request cards: soft elevation that responds to hover */
  .conn{box-shadow:var(--shadow-sm);
    transition:box-shadow var(--t) var(--ease),border-color var(--t) var(--ease)}
  .conn:hover{box-shadow:var(--shadow-md);
    border-color:color-mix(in srgb, var(--accent) 22%, var(--line))}
  /* data panels join the same elevation family */
  .stagebars,.bars,table{box-shadow:var(--shadow-sm)}
  /* table rows highlight on hover (header row uses th, so it stays put) */
  td{transition:background-color var(--t) var(--ease)}
  tr:hover>td{background:var(--accent-soft)}
  /* interactive elements animate smoothly and show a clear focus ring */
  button,select,input,.upload label,.copybtn,a.viewlink,summary{
    transition:background-color var(--t) var(--ease),border-color var(--t) var(--ease),
      box-shadow var(--t) var(--ease),color var(--t) var(--ease),transform var(--t) var(--ease)}
  input:focus,select:focus{border-color:var(--accent)}
  button:focus-visible,select:focus-visible,input:focus-visible,
  a:focus-visible,summary:focus-visible,label:focus-visible{outline:none;box-shadow:var(--focus)}
  .toolbar button:hover,.prodhead button:hover,.rephead button:hover{
    border-color:color-mix(in srgb, var(--accent) 40%, var(--line))}
  /* floating surfaces sit higher off the page */
  .search .results,.repbox{box-shadow:var(--shadow-lg)}
  /* refined scrollbars */
  *::-webkit-scrollbar{width:11px;height:11px}
  *::-webkit-scrollbar-thumb{background:var(--line);border-radius:10px;border:3px solid var(--card)}
  *::-webkit-scrollbar-thumb:hover{background:var(--ink-soft)}
  /* honour reduced-motion preferences */
  @media(prefers-reduced-motion:reduce){
    *{transition-duration:.01ms!important;animation-duration:.01ms!important;scroll-behavior:auto!important}
  }
</style>
</head>
<body>
<header><div class="wrap">
  <div class="hleft">
    <h1>__TITLE__</h1>
    <div class="sub"><span class="sublabel">Data as of</span> <span id="gen"></span></div>
    <a class="viewlink" href="__OTHER_HREF__">__OTHER_LABEL__ &rarr;</a>
    <a class="viewlink" href="team.html">Team overview &rarr;</a>
  </div>
  <div class="hright">
    <div class="htop">
      <button id="themebtn" aria-label="Switch light / dark mode" title="Switch light / dark mode">&#127769;</button>
    </div>
    <div class="upload">
      <label for="files">&#8682; Update data (upload CR / AI / OE reports)</label>
      <input id="files" type="file" accept=".xlsx,.xls" multiple style="display:none">
    </div>
    <div id="upmsg"></div>
  </div>
</div></header>
<div class="wrap">
  <div class="toolbar">
    <label for="emp" style="font-weight:650">Employee</label>
    <input id="emp" list="emplist" placeholder="Type to search names&hellip;" autocomplete="off">
    <datalist id="emplist"></datalist>
    <button id="repbtn">&#128196; Generate report</button>
    <span class="search">
      <input id="connsearch" placeholder="&#128269; Search all connections&hellip;" autocomplete="off">
      <div id="connresults" class="results"></div>
    </span>
  </div>
  <div class="kpis" id="kpis"></div>

  <h2 id="connstoggle" style="cursor:pointer;user-select:none"><span id="connscaret">&#9662;</span> In-progress connections <span id="connscount"></span></h2>
  <div id="conns"></div>

  <h2 id="othertoggle" style="cursor:pointer;user-select:none"><span id="othercaret">&#9656;</span> Late action items <span id="othercount"></span> <span style="text-transform:none;letter-spacing:0;font-weight:400">&middot; on this __WHO__'s other CRs, requested by them, or where they're the responsible party &middot; click to expand</span></h2>
  <div id="otherais" style="display:none"></div>

  <h2 id="oestoggle" style="cursor:pointer;user-select:none"><span id="oescaret">&#9662;</span> In-progress OE requests <span id="oescount"></span></h2>
  <div id="oes"></div>

  <h2>Monthly production <span style="text-transform:none;letter-spacing:0;font-weight:400">&middot; counted on Ready-for-Production date (Production date if RFP is empty)</span></h2>
  <div class="prodhead">
    <button id="prev">&#8592;</button><select class="mon" id="mon"></select><button id="next">&#8594;</button>
    <div class="prodcount" id="prodcount"></div>
    <span class="search">
      <input id="prodsearch" placeholder="&#128269; Search all production&hellip;" autocomplete="off">
      <div id="prodresults" class="results"></div>
    </span>
  </div>
  <div class="bars" id="bars"></div>
  <div id="prodtable"></div>

  <h2>Average stage duration <span style="text-transform:none;letter-spacing:0;font-weight:400">&middot; stages completed in <select id="avgyear" class="yearsel"></select> &middot; outlier filter <select id="avgconf" class="yearsel"><option value="90">90%</option><option value="95">95%</option><option value="99">99%</option><option value="100">off</option></select> &middot; total production: <b id="avgprodcount" style="color:var(--ink)"></b></span></h2>
  <div id="stageavg"></div>
</div>
<div id="cmtpop"></div>
<div id="repmodal"><div class="repbox">
  <div class="rephead"><b id="reptitle">Report</b>
    <button id="repcopy">Copy</button><button id="repdl">Download .txt</button><button id="repclose">Close</button></div>
  <textarea id="reptext" readonly></textarea>
</div></div>
<script>
const RAW = __RAW__;
const STAGES = ["Pending Start","Requirements Gathering","Resource Assignment",
  "Dataset Validation","Mapping","Testing","Ready for Production","Production"];
const STAGE_SHORT = ["Pending","Req. Gathering","Resource Asgmt",
  "Validation","Mapping","Testing","Ready for Prod","Production"];
// stage colors come from CSS variables so each theme uses its own validated
// set (classic multi-hue palette, blues separated for colorblind safety)
const STAGE_COLORS = Array.from({length:8}, (_,i)=>`var(--s${i})`);
const STAGE_COLS = ["Created Date","Requirements Gathering","Resource Assignment",
  "Dataset Validation","Mapping","Testing","Ready For Production","Production"];
const ACTIVE = new Set(["In Progress","Blocked","On Hold","Not Started"]);
const MS = {"Requirements Gathering":"RG","Resource Assignment":"RA","Dataset Validation":"DV",
  "Mapping":"Mapping","Testing":"Testing","Ready For Production":"Ready for Prod",
  "Production":"Production","First Test File":"First test file","First Production File":"First prod file"};
const $ = s => document.querySelector(s);
const fmt = d => d || '—';
const BASE = 'https://d24ep0r8pqsi0a.cloudfront.net';
const crUrl = id => `${BASE}/ConnectivityRequests/ViewConnectivityRequest/${id}`;
const aiUrl = (crId, aiId) => `${BASE}/ActionItems/ViewConnectivityRequest/${crId}/ViewActionItem/${aiId}`;
const oeUrl = (crId, oeId) => `${BASE}/OERequests/ViewConnectivityRequest/${crId}/ViewOERequest/${oeId}`;
const OE_STAGES = ["Pending Start","Resource Assignment","Requirement Gathering",
  "Waiting for OE Data","Sending OE File","Get Carrier Confirmation","Completed"];
const OE_SHORT = ["Pending","Resource Asgmt","Req. Gathering",
  "Waiting Data","Sending File","Carrier Conf.","Completed"];
const OE_COLORS = [0,1,2,3,4,6,7].map(i=>`var(--s${i})`);

// ---------- page role ----------
// which CR-sheet role this page groups by: the analyst page uses the
// Technical Contact column, the iSolved page the iSolved Contact column;
// each card also shows the other role's contact
const ROLE = '__ROLE__';
const crEmp   = r => txt(ROLE==='tc' ? r['Technical Contact'] : r['iSolved Contact']);
const crOther = r => txt(ROLE==='tc' ? r['iSolved Contact'] : r['Technical Contact']);
const oeEmp   = r => txt(ROLE==='tc' ? r['TechnicalContact'] : r['IsolvedContact']);
const oeOther = r => txt(ROLE==='tc' ? r['IsolvedContact'] : r['TechnicalContact']);
const OTHER_ROLE_LABEL = ROLE==='tc' ? 'isolved contact' : 'technical contact';
// weekend for working-day counts: Friday & Saturday for analysts,
// Saturday & Sunday for iSolved contacts (UTC day numbers, 0 = Sunday)
const WEEKEND = new Set(ROLE==='tc' ? [5,6] : [6,0]);
const WEEKEND_LABEL = ROLE==='tc' ? 'Friday & Saturday' : 'Saturday & Sunday';

// ---------- date + text helpers ----------
// format a Date's LOCAL calendar day. Uploads keep dates as raw Excel serials,
// so this is a fallback for data cached by older versions, where UTC-based
// toISOString() would land on the previous day for timezones ahead of UTC
const localDay = d => d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
function toISO(v){
  if(v==null || v==='') return null;
  if(v instanceof Date && !isNaN(v)) return localDay(v);
  if(typeof v==='number'){ // excel serial (UTC-based math, no tz involved)
    const d = new Date(Math.round((v-25569)*86400*1000));
    return isNaN(d)?null:d.toISOString().slice(0,10);
  }
  const s = String(v).trim();
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})($|[T ])/);
  if(m){
    // full timestamps (e.g. an upload cached as JSON serializes its Dates to
    // UTC) are converted back to the local calendar day; date-only strings
    // are taken as-is
    if(m[4]){ const d = new Date(s); if(!isNaN(d)) return localDay(d); }
    return m[1]+'-'+m[2]+'-'+m[3];
  }
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if(m) return m[3]+'-'+m[1].padStart(2,'0')+'-'+m[2].padStart(2,'0');
  const d = new Date(s);
  return isNaN(d)?null:localDay(d);
}
const STOP = /\b(inc|llc|llp|ltd|co|corp|corporation|company|the|of)\b/g;
function norm(s){
  if(s==null) return '';
  return String(s).toLowerCase().replace(/[^a-z0-9 ]/g,' ')
    .replace(STOP,'').replace(/\s+/g,' ').trim();
}
const txt = v => (v==null ? '' : String(v).trim());
const daysBetween = (iso, today) => Math.floor((today - new Date(iso+'T00:00:00Z'))/86400000);
// working days in the same span — the page role decides the weekend days
function workDaysBetween(iso, today){
  const start = new Date(iso+'T00:00:00Z');
  const days = Math.floor((today - start)/86400000);
  if(days <= 0) return 0;
  const weeks = Math.floor(days/7);
  let wd = weeks*5, dow = start.getUTCDay();
  for(let k = days - weeks*7; k > 0; k--){
    dow = (dow + 1) % 7;
    if(!WEEKEND.has(dow)) wd++;
  }
  return wd;
}
const dur = (d, wd) => d!=null ? `${d}d (${wd}wd)` : '—';
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
// responsible party for an AI = its CurrentlyPendingOn value
const respOf = i => i.on || '—';
// speech-bubble icon whose hover popup shows the AI's last comment
const cmtPop = i => {
  if(!i.cmt) return '';
  // the AI system stores line breaks as <br/> tags; render them as real breaks
  let c = i.cmt.replace(/<br\s*\/?>/gi, '\n').replace(/\n{3,}/g, '\n\n').trim();
  if(!c) return '';
  if(c.length>500) c = c.slice(0,500)+'…';
  const meta = [i.owner, i.last].filter(Boolean).join(' · ');
  return ` <span class="cmt" data-c="${esc(c)}" data-m="${esc(meta)}">&#128172;</span>`;
};
// exact key, and a fallback key with any "(...)" stripped from the carrier so
// "Third Party (Optum)" on an AI still catches a CR filed as "Third Party"
const normCarrier = k => norm(String(k==null?'':k).replace(/\([^)]*\)/g,' '));
const exactKey = (client, carrier) => norm(client)+'||'+norm(carrier);
const baseKey = (client, carrier) => norm(client)+'||'+normCarrier(carrier);

// ---------- fuzzy matching (the AI and CR systems spell names differently) ----------
// clients: exports truncate long names, so accept a prefix when both are long
const clientAlike = (a,b) => !!(a && b && (a===b ||
  ((a.startsWith(b) || b.startsWith(a)) && Math.min(a.length,b.length)>=20)));
// carriers: tolerate spacing/plural drift ("SunLife"/"Sun Life", "Pet Benefits"/
// "Pet Benefit"), acronyms ("BCBS"/"Blue Cross Blue Shield", "VSP"/"Vision
// Service Plan"), a single-word name appearing as a token ("Optum"/"HSA w/Optum"),
// and a shared distinctive first word ("Cigna/CBS"/"Cigna Healthcare")
function carrierAlike(a,b){
  if(!a || !b) return false;
  if(a===b) return true;
  const sq = s => s.split(' ').map(w=>w.replace(/s$/,'')).join('');
  const A = sq(a), B = sq(b);
  if(Math.min(A.length,B.length)>=4 && (A.startsWith(B) || B.startsWith(A))) return true;
  const acr = s => { const w = s.split(' '); return w.length>1 ? w.map(x=>x[0]).join('') : ''; };
  const A0 = a.replace(/ /g,''), B0 = b.replace(/ /g,'');
  const aa = acr(a), ab = acr(b);
  if(aa.length>=3 && B0.startsWith(aa)) return true;
  if(ab.length>=3 && A0.startsWith(ab)) return true;
  if(aa.length===2 && B0.startsWith(aa) && B0.length<=4) return true;
  if(ab.length===2 && A0.startsWith(ab) && A0.length<=4) return true;
  const ta = a.split(' '), tb = b.split(' ');
  if(ta.length===1 && a.length>=3 && tb.includes(a)) return true;
  if(tb.length===1 && b.length>=3 && ta.includes(b)) return true;
  if(ta[0].length>=5 && ta[0]===tb[0]) return true;
  return false;
}
const aiAlike = (i, cnc, cnk) => clientAlike(i.nc, cnc) && carrierAlike(i.nk, cnk);

// migration flag: a dedicated column when the CR report has one, else infer
// from the request type; null = the report carries no migration info
const MIG_COLS = ['Migration','IsMigration','Is Migration','Migration Request','Migration Type'];
function migOf(r){   // the platform migrated from ("eBenefits Network"), "No", or null
  for(const col of MIG_COLS){
    const v = txt(r[col]);
    if(v) return v;
  }
  return /migration/i.test(txt(r['Request Type'])) ? 'Yes' : null;
}
const isMig = m => !!m && !['no','false','0','n','none','-'].includes(String(m).toLowerCase());
const migLabel = m => m==null ? '—' : m;

// ---------- core processing (used for both embedded data and uploads) ----------
// Testing starts at the First Test File date; but if that date is more than
// FTF_MAX_LEAD days before the Testing-stage date, it's treated as a stale /
// wrong entry and the Testing-stage date is used instead
const FTF_MAX_LEAD = 30;
function testingStart(r){
  const ftf = toISO(r['First Test File']);
  const tst = toISO(r['Testing']);
  if(!ftf) return tst;
  if(tst && daysBetween(ftf, new Date(tst+'T00:00:00Z')) > FTF_MAX_LEAD) return tst;
  return ftf;
}
function process(crRows, aiRows, oeRows, generated){
  // each report's captured (header) date, so "days since / pending" counts are
  // measured against the snapshot the data came from, per report
  const rdates = RAW.dates || {};
  const crRef = new Date((rdates.cr||generated)+'T00:00:00Z');
  const aiRef = new Date((rdates.ai||generated)+'T00:00:00Z');

  // all open AIs, keyed by client+carrier; pending clock = last comment date, else start date
  const aiItems = [];
  for(const r of aiRows){
    // comments from "System Admin" are automated due-date reminders — ignore
    // the comment and its date entirely
    const isBot = /^system\s*admin$/i.test(txt(r['LastCommentOwner']));
    const last = isBot ? null : toISO(r['LastCommentDate']);
    const start = toISO(r['StartDate']);
    const eff = last || start;
    aiItems.push({
      id: r['ActionItemID'],
      crid: r['ConnectivityRequestID'] ?? null,
      client: txt(r['ClientName']), carrier: txt(r['CarrierName']),
      key: exactKey(r['ClientName'], r['CarrierName']),
      bkey: baseKey(r['ClientName'], r['CarrierName']),
      nc: norm(r['ClientName']), nk: normCarrier(r['CarrierName']),
      due: toISO(r['DueDate'] ?? r['Due Date'] ?? r['DueOn']),
      on: txt(r['CurrentlyPendingOn'])||null,
      title: txt(r['ActionItemTitle'])||null,
      owner: isBot ? null : txt(r['LastCommentOwner'])||null,
      req: txt(r['Requestor'])||null,
      cmt: isBot ? null : txt(r['LastComment'])||null,
      last, start, eff,
      days: eff ? daysBetween(eff, aiRef) : null,
      wdays: eff ? workDaysBetween(eff, aiRef) : null,
      noComment: !last,
      used: false, cardTcs: []
    });
  }
  aiItems.sort((a,b)=>String(a.eff).localeCompare(String(b.eff)));
  // AIs with a ConnectivityRequestID link by id (authoritative); only AIs
  // without one (older report formats) fall back to name matching
  const aiByCr = {}, aiByKey = {}, aiByBase = {}, aiNamed = [];
  for(const it of aiItems){
    if(it.crid!=null){ (aiByCr[it.crid] = aiByCr[it.crid]||[]).push(it); continue; }
    aiNamed.push(it);
    (aiByKey[it.key] = aiByKey[it.key]||[]).push(it);
    (aiByBase[it.bkey] = aiByBase[it.bkey]||[]).push(it);
  }

  const dateCols = ['Created Date','Assignment Date',...Object.keys(MS)];
  const conns = [];
  for(const r of crRows){
    if(!ACTIVE.has(txt(r['Status'])) || !crEmp(r)) continue;
    const dates = dateCols.map(c=>toISO(r[c])).filter(Boolean);
    const lastCr = dates.length ? dates.sort().at(-1) : null;
    const byId = aiByCr[r['Request ID']] || [];
    let named = aiByKey[exactKey(r['Customer'], r['Carrier'])] || [];
    if(!named.length) named = aiByBase[baseKey(r['Customer'], r['Carrier'])] || [];
    if(!named.length){
      const cnc = norm(r['Customer']), cnk = normCarrier(r['Carrier']);
      named = aiNamed.filter(i=>aiAlike(i, cnc, cnk));
    }
    const items = byId.concat(named).sort((a,b)=>String(a.eff).localeCompare(String(b.eff)));
    let ai = null, lastAi = null;
    if(items.length){
      const cardCr = {id: r['Request ID'], tc: crEmp(r)||null,
        customer: txt(r['Customer']), carrier: txt(r['Carrier']), status: txt(r['Status'])};
      items.forEach(i=>{ i.used=true; i.cardTcs.push(cardCr.tc); if(!i.cr) i.cr = cardCr; });
      const latest = items.at(-1);
      lastAi = latest.eff;
      ai = {count: items.length, latest, items};
    }
    // last activity, measured against the report it came from: CR stage
    // activity vs the CR date, AI activity vs the AI date
    let lastAny = null, idleRef = crRef;
    if(lastAi && (!lastCr || lastAi >= lastCr)){ lastAny = lastAi; idleRef = aiRef; }
    else if(lastCr){ lastAny = lastCr; }
    const milestones = {};
    for(const [col,label] of Object.entries(MS)){
      // Testing milestone follows the same rule as the rail (see testingStart)
      const v = col==='Testing' ? testingStart(r) : toISO(r[col]);
      if(v) milestones[label]=v;
    }
    // Testing phase starts at the First Test File date (see testingStart)
    const stageDates = STAGE_COLS.map(col=>col?toISO(r[col]):null);
    const ti = STAGE_COLS.indexOf('Testing');
    stageDates[ti] = testingStart(r);
    conns.push({
      id: r['Request ID'], tc: crEmp(r),
      carrier: txt(r['Carrier']), customer: txt(r['Customer']),
      instance: txt(r['Instance']), type: txt(r['Request Type']), mig: migOf(r),
      stage: txt(r['Stage']), status: txt(r['Status']), isolved: crOther(r),
      assigned: toISO(r['Assignment Date']),
      stageDates,
      noTestFile: !toISO(r['First Test File']),
      milestones, lastCr, ai, lastAny,
      idleDays: lastAny ? daysBetween(lastAny, idleRef) : null,
      idleWdays: lastAny ? workDaysBetween(lastAny, idleRef) : null
    });
  }

  // production: prioritize Ready For Production date, fall back to Production
  const production = [];
  for(const r of crRows){
    const rfp = toISO(r['Ready For Production']), pr = toISO(r['Production']);
    const use = rfp || pr;
    if(!use) continue;
    production.push({
      _i: production.length,
      id: r['Request ID'], tc: crEmp(r)||null,
      carrier: txt(r['Carrier']), customer: txt(r['Customer']),
      status: txt(r['Status']), date: use, rfp, prod: pr,
      month: use.slice(0,7)
    });
  }

  // stage history for every CR with an assigned contact (any status), used by
  // the average-stage-duration section
  const stageRows = [];
  for(const r of crRows){
    if(!crEmp(r)) continue;
    const sd = STAGE_COLS.map(col=>col?toISO(r[col]):null);
    const ti = STAGE_COLS.indexOf('Testing');
    sd[ti] = testingStart(r);
    stageRows.push({tc: crEmp(r), sd, id: r['Request ID'],
      customer: txt(r['Customer']), carrier: txt(r['Carrier'])});
  }

  // OE requests: active ones assigned to a technical contact
  const oes = [];
  for(const r of (oeRows||[])){
    if(!ACTIVE.has(txt(r['Status'])) || !oeEmp(r)) continue;
    oes.push({
      id: r['OERequestID'], crId: r['ConnectivityRequestID'],
      tc: oeEmp(r), client: txt(r['ClientName']), carrier: txt(r['CarrierName']),
      type: txt(r['RequestType']), status: txt(r['Status']), stage: txt(r['Stage']),
      pysd: toISO(r['PlanYearStartDate']), expected: toISO(r['ClientDataExpectedDate']),
      dataReady: toISO(r['DataReadyDate']), submitted: toISO(r['OEFileSubmissionDate']),
      isolved: oeOther(r), dataChanges: txt(r['ISolvedDataChanges']),
      groupStructure: txt(r['UpdatedGroupStructure']),
      canResume: txt(r['CanResumeProductionPYSD']), resumed: txt(r['ResumedProduction']),
      draft: Number(r['IsDraftOERequest'])===1,
      created: toISO(r['Created']), createdBy: txt(r['CreatedBy'])
    });
  }

  // resolve a CR for every AI not already tied to a card above: by CR id
  // first, then by name (live / cancelled / unassigned CRs)
  const crById = {}, crIx = {}, crIxB = {}, crInfos = [];
  for(const r of crRows){
    const info = {id: r['Request ID'], tc: crEmp(r)||null,
      customer: txt(r['Customer']), carrier: txt(r['Carrier']), status: txt(r['Status']),
      nc: norm(r['Customer']), nk: normCarrier(r['Carrier'])};
    crInfos.push(info);
    crById[info.id] = info;
    const k = exactKey(r['Customer'], r['Carrier']), bk = baseKey(r['Customer'], r['Carrier']);
    if(!crIx[k] || (!crIx[k].tc && info.tc)) crIx[k] = info;
    if(!crIxB[bk] || (!crIxB[bk].tc && info.tc)) crIxB[bk] = info;
  }
  for(const it of aiItems){
    if(it.cr) continue;
    let cr = (it.crid!=null ? crById[it.crid] : null)
          || crIx[it.key] || crIxB[it.bkey] || null;
    if(!cr){
      const f = crInfos.filter(x=>aiAlike(it, x.nc, x.nk));
      cr = f.find(x=>x.tc) || f[0] || null;
    }
    it.cr = cr;
  }

  const tcSet = new Set(crInfos.map(x=>x.tc).filter(Boolean));
  const employees = [...new Set([...conns.map(c=>c.tc), ...production.map(p=>p.tc).filter(Boolean),
    ...oes.map(o=>o.tc), ...aiItems.map(i=>i.cr&&i.cr.tc).filter(Boolean),
    ...aiItems.map(i=>i.req).filter(rq=>rq && tcSet.has(rq))])].sort();
  return {generated, connections: conns, production, oes, aiAll: aiItems, employees, stageRows};
}

// ---------- state + rendering ----------
// uploads are cached in IndexedDB (localStorage's ~5MB quota is too small for
// full reports and fails silently); a copy saved by the old localStorage
// version is migrated on first load
const DB_KEY = 'analystDash';
const idb = () => new Promise((res,rej)=>{
  const rq = indexedDB.open('analystDashDB',1);
  rq.onupgradeneeded = () => rq.result.createObjectStore('kv');
  rq.onsuccess = () => res(rq.result); rq.onerror = () => rej(rq.error);
});
const dbGet = key => idb().then(db => new Promise((res,rej)=>{
  const rq = db.transaction('kv').objectStore('kv').get(key);
  rq.onsuccess = () => res(rq.result); rq.onerror = () => rej(rq.error);
}));
const dbSet = (key,val) => idb().then(db => new Promise((res,rej)=>{
  const tx = db.transaction('kv','readwrite'); tx.objectStore('kv').put(val,key);
  tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error);
}));
const dbDel = key => idb().then(db => new Promise((res,rej)=>{
  const tx = db.transaction('kv','readwrite'); tx.objectStore('kv').delete(key);
  tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error);
}));

// restore an upload saved in this browser when it is newer than the embedded
// data, or whenever the file ships with no embedded data (an emptied file) so the
// saved copy becomes the source of truth; otherwise drop the stale copy so a
// fresh build that carries data starts clean
RAW.oe = RAW.oe || [];
RAW.ms = RAW.ms || [];
RAW.dates = RAW.dates || {};
async function restoreSaved(){
  let saved = null;
  try{ const s = await dbGet(DB_KEY); if(s) saved = JSON.parse(s); }catch(e){}
  try{ // migrate a copy saved by the old localStorage version, then clear it
    if(!saved) saved = JSON.parse(localStorage.getItem(DB_KEY)||'null');
    localStorage.removeItem(DB_KEY);
  }catch(e){}
  if(saved && (!RAW.cr.length || saved.generated > RAW.generated)){
    RAW.cr = saved.cr; RAW.ai = saved.ai; RAW.generated = saved.generated;
    if(saved.oe && saved.oe.length) RAW.oe = saved.oe;
    if(saved.ms && saved.ms.length) RAW.ms = saved.ms;
    if(saved.dates) RAW.dates = saved.dates;
    DATA = process(RAW.cr, RAW.ai, RAW.oe, RAW.generated);
  } else if(saved){
    dbDel(DB_KEY).catch(()=>{});
  }
}
let DATA = process(RAW.cr, RAW.ai, RAW.oe, RAW.generated);
let curEmp = null, curMonth = null, curAvgYear = null, curAvgConf = 99;

const stageIdx = s => { let t = String(s).toLowerCase();
  if(t==='obtain customer dataset') t = 'dataset validation'; // stage removed from the rail
  const i = STAGES.findIndex(x=>x.toLowerCase()===t); return i<0?0:i; };
const statusCls = s => 'status-'+s.toLowerCase().replace(/\s+/g,'');
// one rule for all warnings, counted in WORKING days: <4 ok, 4-9 amber, >=10 red
const idleCls = n => n==null?'idle-ok':(n>=10?'idle-bad':(n>=4?'idle-warn':'idle-ok'));

// per-report data dates for the "Data as of" line; falls back to the single
// generated date for older cached data that has no per-report dates
function dataDates(sep){
  const d = RAW.dates || {};
  const parts = [['CR',d.cr],['AI',d.ai],['OE',d.oe]].filter(x=>x[1]).map(x=>x[0]+' '+x[1]);
  return parts.length ? parts.join(sep) : DATA.generated;
}
// the same dates as coloured chips for the header, shaded by how many working
// days old each report is (same thresholds as the idle chips)
function dateChips(){
  const d = RAW.dates || {};
  const items = [['CR',d.cr],['AI',d.ai],['OE',d.oe]].filter(x=>x[1]);
  if(!items.length) return esc(DATA.generated || '');
  const nowMid = new Date(localDay(new Date())+'T00:00:00Z');
  return items.map(([k,v])=>{
    const age = workDaysBetween(v, nowMid);
    return `<span class="dchip ${idleCls(age)}" title="${age} working day${age===1?'':'s'} old">${k} <b>${v}</b></span>`;
  }).join('');
}
function initSelectors(){
  $('#gen').innerHTML = dateChips();
  const activeCounts = {};
  DATA.connections.forEach(c=>activeCounts[c.tc]=(activeCounts[c.tc]||0)+1);
  const emps = [...DATA.employees].sort((a,b)=>{
    const d = (activeCounts[b]?1:0)-(activeCounts[a]?1:0);
    return d!==0?d:a.localeCompare(b);
  });
  $('#emplist').innerHTML = emps.map(e=>
    `<option value="${e}">${activeCounts[e]?`${activeCounts[e]} active`:''}</option>`).join('');
  if(!emps.includes(curEmp)) curEmp = emps[0];
  $('#emp').value = curEmp;
  const months = [...new Set(DATA.production.map(p=>p.month))].sort();
  if(!months.includes(curMonth)) curMonth = months.at(-1) || null;
}

function render(){
  const conns = DATA.connections.filter(c=>c.tc===curEmp)
      .sort((a,b)=>(b.idleDays??-1)-(a.idleDays??-1));
  const oes = (DATA.oes||[]).filter(o=>o.tc===curEmp)
      .sort((a,b)=>String(a.pysd||'9999').localeCompare(String(b.pysd||'9999')));
  const months = [...new Set(DATA.production.map(p=>p.month))].sort();
  const thisMonth = months.at(-1);
  const mine = DATA.production.filter(p=>p.tc===curEmp);
  const others = otherFor(curEmp);
  const openAIs = conns.reduce((s,c)=>s+(c.ai?c.ai.count:0),0);
  const stageCounts = STAGES.map((_,i)=>conns.filter(c=>stageIdx(c.stage)===i).length);
  const stageSub = STAGES.map((s,i)=>stageCounts[i]?`${stageCounts[i]} ${s.toLowerCase()}`:null).filter(Boolean).join(' · ');
  const oeStageCounts = OE_STAGES.map((_,i)=>oes.filter(o=>oeStageIdx(o.stage)===i).length);
  const oeSub = OE_STAGES.map((s,i)=>oeStageCounts[i]?`${oeStageCounts[i]} ${s.toLowerCase()}`:null).filter(Boolean).join(' · ');
  const myResp = conns.reduce((s,c)=>s+(c.ai?c.ai.items.filter(i=>i.on===curEmp).length:0),0);

  $('#kpis').innerHTML = [
    [conns.length,'Active connections', stageSub],
    [conns.filter(c=>c.status==='On Hold').length,'On hold'],
    [openAIs,'Open action items', myResp?`${myResp} pending on ${ROLE==='tc'?'the Analyst':'the iSolved contact'}`:''],
    [oes.length,'In-progress OEs', oeSub],
    [mine.filter(p=>p.month===thisMonth).length,'Production this month'],
  ].map(([v,l,d])=>`<div class="kpi"><b>${v}</b><span>${l}</span>${d?`<span class="kpi-sub">${d}</span>`:''}</div>`).join('');

  $('#conns').innerHTML = conns.length ? conns.map(connCard).join('')
      : '<div class="empty">No in-progress connections for this employee.</div>';
  $('#connscount').textContent = `(${conns.length})`;
  $('#othercount').textContent = `(${others.length})`;
  $('#otherais').innerHTML = others.length ? aiTable(others)
      : '<div class="empty">No late action items for this employee.</div>';
  $('#oes').innerHTML = oes.length ? oes.map(oeCard).join('')
      : '<div class="empty">No in-progress OE requests for this employee. Upload the OE report above to load OE data.</div>';
  $('#oescount').textContent = `(${oes.length})`;
  renderProd(months, mine);
  renderStageAvgs();
}

// people excluded from production rankings (e.g. leads); their own counts still
// display — they just don't occupy a rank or count toward anyone's "of N"
const RANK_EXCLUDE = new Set(['dina medhat']);
const inRank = name => !!name && !RANK_EXCLUDE.has(String(name).trim().toLowerCase());
// rank an employee by production count among ranked people with production CRs
// matching pred (ties share the same rank)
function prodRank(emp, pred){
  const counts = {};
  DATA.production.forEach(p=>{ if(p.tc && pred(p)) counts[p.tc]=(counts[p.tc]||0)+1; });
  const c = counts[emp]||0;
  const pool = Object.entries(counts).filter(([n])=>inRank(n)).map(([,v])=>v);
  return {c, n: pool.length, r: 1 + pool.filter(v=>v>c).length, ranked: inRank(emp)};
}

// full production ranking (month or year scope), shown in the report modal
// so it can be copied or downloaded like the other reports
function showRankList(scope){
  const isYear = scope==='year';
  const label = isYear ? curAvgYear : curMonth;
  const pred = isYear ? (p=>p.month.slice(0,4)===curAvgYear) : (p=>p.month===curMonth);
  const counts = {};
  DATA.production.forEach(p=>{ if(p.tc && inRank(p.tc) && pred(p)) counts[p.tc]=(counts[p.tc]||0)+1; });
  const list = Object.entries(counts).sort((a,b)=>b[1]-a[1] || a[0].localeCompare(b[0]));
  const L = [`PRODUCTION RANKING — ${label}`, ''];
  let r = 0, prev = null;
  list.forEach(([name,c],idx)=>{
    if(c!==prev){ r = idx+1; prev = c; }
    L.push(`#${String(r).padStart(2,' ')}  ${name} — ${c} CR${c>1?'s':''}${name===curEmp?'   ←':''}`);
  });
  L.push('', `${list.length} ${ROLE==='tc'?'analysts':'iSolved contacts'} with production in ${label}`);
  $('#reptitle').textContent = `Production ranking — ${label}`;
  $('#reptext').value = L.join('\n');
  $('#repmodal').classList.add('open');
}
// click a rank link to open the full ranking
document.addEventListener('click', e => {
  const b = e.target.closest('.rankbtn');
  if(b) showRankList(b.dataset.scope);
});

// average time spent in each stage (start of the stage to the start of the
// next recorded one) over the CRs the selected employee took to production in
// the chosen year; the early admin stages are skipped and durations outside
// the chosen confidence band are dropped as outliers.
// Shown as a bar per stage in calendar weeks
const AVG_FIRST_STAGE = 3;   // skip Pending Start, Req. Gathering, Resource Asgmt
const Z = {90:1.645, 95:1.96, 99:2.576};
// split stage intervals into kept / outliers using the chosen confidence
// band (mean ± z·σ); 'off' keeps everything, samples under 3 are never trimmed
function splitOutliers(list){
  const z = Z[curAvgConf];
  if(!z || list.length<3) return {kept:list, cut:[]};
  const m = list.reduce((a,x)=>a+x.d,0)/list.length;
  const sd = Math.sqrt(list.reduce((a,x)=>a+(x.d-m)*(x.d-m),0)/list.length);
  if(!sd) return {kept:list, cut:[]};
  const kept = [], cut = [];
  for(const x of list) (Math.abs(x.d-m)<=z*sd ? kept : cut).push(x);
  return {kept, cut};
}
function renderStageAvgs(){
  // only CRs that reached Ready For Production / Production are counted, so
  // connections still moving through the pipeline don't skew the averages
  const RFP_I = STAGE_COLS.indexOf('Ready For Production');
  const mine = (DATA.stageRows||[]).filter(s=>s.tc===curEmp && (s.sd[RFP_I] || s.sd[RFP_I+1]));
  // a CR belongs to the year of its production date (RFP falling back to
  // Production — the monthly production rule); all of its completed stage
  // intervals count toward that year, whenever each stage finished
  const prodYearOf = s => (s.sd[RFP_I] || s.sd[RFP_I+1]).slice(0,4);
  const dataYear = String(DATA.generated).slice(0,4);
  const years = [...new Set(mine.map(prodYearOf))].sort().reverse();
  if(!years.includes(curAvgYear)) curAvgYear = years.includes(dataYear) ? dataYear : (years[0]||dataYear);
  const sel = $('#avgyear');
  sel.innerHTML = (years.length?years:[curAvgYear]).map(y=>`<option${y===curAvgYear?' selected':''}>${y}</option>`).join('');
  sel.onchange = e => { curAvgYear = e.target.value; renderStageAvgs(); };
  const conf = $('#avgconf');
  conf.value = String(curAvgConf);
  conf.onchange = e => { curAvgConf = +e.target.value; renderStageAvgs(); };
  // total production for the chosen year (Ready-for-Production date, falling
  // back to Production date) with the rank among everyone who produced then
  const yrank = prodRank(curEmp, p=>p.month.slice(0,4)===curAvgYear);
  $('#avgprodcount').innerHTML = `${yrank.c} CR${yrank.c===1?'':'s'} in ${curAvgYear}`
    + (yrank.c && yrank.ranked ? ` &middot; <a class="lnk rankbtn" data-scope="year" title="show the full ranking">rank #${yrank.r} of ${yrank.n}</a>` : '');
  const ints = [];   // completed intervals on this year's produced CRs
  for(const s of mine){
    if(prodYearOf(s)!==curAvgYear) continue;
    for(let i=AVG_FIRST_STAGE;i<STAGES.length;i++){
      const start = s.sd[i];
      if(!start) continue;
      let end = null;
      for(let j=i+1;j<s.sd.length;j++) if(s.sd[j]){ end = s.sd[j]; break; }
      if(!end) continue;
      const d = daysBetween(start, new Date(end+'T00:00:00Z'));
      if(d>=0) ints.push({i, d, id: s.id, customer: s.customer, carrier: s.carrier, start, end});
    }
  }
  const rows = [];
  for(let i=AVG_FIRST_STAGE;i<STAGES.length;i++){
    const all = ints.filter(x=>x.i===i);
    const {kept, cut} = splitOutliers(all);
    if(kept.length) rows.push([i, kept.reduce((a,x)=>a+x.d,0)/kept.length, kept, cut]);
  }
  const max = Math.max(...rows.map(r=>r[1]), 1);
  $('#stageavg').innerHTML = rows.length ? `<div class="stagebars">
    ${rows.map(([i,avg,kept,cut])=>`<div class="srow">
      <span class="sname"><i style="background:${STAGE_COLORS[i]}"></i>${STAGES[i]}</span>
      <div class="strack"><div class="sbar" style="width:${Math.max(3, avg/max*100)}%;background:${STAGE_COLORS[i]}"></div></div>
      <span class="sval">${(avg/7).toFixed(1)} wk</span>
      <span class="scnt">${kept.length} CR${kept.length>1?'s':''}${cut.length?` &middot; <a class="outbtn" data-i="${i}" title="show / hide the removed CRs">${cut.length} outlier${cut.length>1?'s':''} removed</a>`:''}</span>
    </div>${cut.length?`<div class="souts" id="souts-${i}" style="display:none">
      ${cut.map(x=>`<div><a class="lnk" href="${crUrl(x.id)}" target="_blank">#${x.id}</a> ${esc(x.customer)} — ${esc(x.carrier)} &middot; <span class="dt">${(x.d/7).toFixed(1)} wk (${x.start} &rarr; ${x.end})</span></div>`).join('')}
    </div>`:''}`).join('')}
  </div>` : `<div class="empty">No production CRs with measurable stages in ${curAvgYear} for this employee.</div>`;
  document.querySelectorAll('#stageavg .outbtn').forEach(b=>{
    b.onclick = () => { const el = document.getElementById('souts-'+b.dataset.i);
      if(el) el.style.display = el.style.display==='none' ? '' : 'none'; };
  });
}

// open AIs shown in the "other" section for an employee: items not already on
// one of their connection cards, sitting on their CRs, requested by them, or
// pending on them as the responsible party
function otherFor(emp){
  return (DATA.aiAll||[]).filter(i =>
      !i.cardTcs.includes(emp) && ((i.cr && i.cr.tc===emp) || i.req===emp || i.on===emp))
    .sort((a,b)=>(b.days??-1)-(a.days??-1));
}

function aiTable(items){
  const crIdOf = a => a.cr ? a.cr.id : (a.crid!=null ? a.crid : null);
  const aiCell = a => crIdOf(a)!=null && a.id!=null
    ? `<a class="lnk" href="${aiUrl(crIdOf(a),a.id)}" target="_blank">${a.title||('AI #'+a.id)}</a>`
    : (a.title||(a.id!=null?'AI #'+a.id:'—'));
  return `<table>
    <tr><th>Client — Carrier</th><th>CR</th><th>CR status</th><th>Action item</th><th>Responsible</th><th>Requestor</th><th>Last activity</th><th>Days pending</th></tr>
    ${items.map(a=>`<tr>
      <td>${a.client} — ${a.carrier}</td>
      <td class="dt">${crIdOf(a)!=null?`<a class="lnk" href="${crUrl(crIdOf(a))}" target="_blank">#${crIdOf(a)}</a>`:'—'}</td>
      <td>${a.cr?a.cr.status:'—'}</td>
      <td>${aiCell(a)}${cmtPop(a)}</td>
      <td>${respOf(a)}</td>
      <td>${a.req||'—'}</td>
      <td class="dt">${a.eff||'—'}${a.noComment?'*':''}</td>
      <td class="dt">${dur(a.days,a.wdays)}</td></tr>`).join('')}
  </table>
  ${items.some(a=>a.noComment)?'<div class="ainote">* no comments yet — dates and days pending count from when the AI was created.</div>':''}`;
}

function tipsFor(stages, sd, idx){
  const today = new Date(DATA.generated+'T00:00:00Z');
  const nextStart = i => { for(let j=i+1;j<sd.length;j++) if(sd[j]) return sd[j]; return null; };
  return stages.map((s,i)=>{
    const start = sd[i];
    if(start){
      const end = nextStart(i);
      if(end){ const e = new Date(end+'T00:00:00Z');
        return `${s}: started ${start} — took ${dur(daysBetween(start,e),workDaysBetween(start,e))} — next phase ${end}`; }
      if(i>=idx && i<stages.length-1) return `${s}: started ${start} — ${dur(daysBetween(start,today),workDaysBetween(start,today))} so far (in progress)`;
      return `${s}: started ${start}`;
    }
    if(i===idx) return `${s}: in progress`;
    return i<idx ? `${s}: done` : `${s}: not started`;
  });
}

const TESTING_IDX = STAGES.indexOf('Testing');
// a CR that reached Testing without a First Test File date gets a * marker
const testStar = c => c.noTestFile && stageIdx(c.stage) >= TESTING_IDX;
// "Forms" requests skip the EDI pipeline, so the card shows the request type as the stage
const isForms = c => /^\s*forms?\s*(only)?\s*$/i.test(c.type||'');

function stageTips(c){
  const tips = tipsFor(STAGES, c.stageDates || [], stageIdx(c.stage));
  if(testStar(c)) tips[TESTING_IDX] += ' · * no test file sent yet';
  return tips;
}

function connCard(c){
  const idx = stageIdx(c.stage);
  const today = new Date(DATA.generated+'T00:00:00Z');
  const tips = stageTips(c);
  const rail = STAGES.map((s,i)=>`<div class="seg ${i<idx?'done':(i===idx?'cur':'todo')}" data-tip="${tips[i]}">
      <div class="tip">${tips[i]}<small>click bar to copy &middot; or select this text</small></div>
      <i style="background:${STAGE_COLORS[i]}${i>idx?';opacity:.22':''}"></i><span>${STAGE_SHORT[i]}${i===TESTING_IDX&&testStar(c)?'*':''}</span></div>`).join('');
  const ms = Object.entries(c.milestones).map(([k,v])=>`<div>${k} <b class="dt">${v}</b></div>`).join('');
  let aibox;
  if(c.ai){
    const a = c.ai, L = a.latest;
    const aiLink = i => i.id!=null ? `<a class="lnk" href="${aiUrl(c.id,i.id)}" target="_blank">${i.title||('AI #'+i.id)}</a>` : (i.title||'');
    // due-date intervals in working days overdue: <4 ok, 4-9 amber, >=10 red
    const dueCls = d => { const o = workDaysBetween(d, today);
      return o>=10?'due-over':(o>=4?'due-warn':'due-ok'); };
    const dueTag = i => i.due ? ` &middot; due <span class="dt ${dueCls(i.due)}">${i.due}</span>` : '';
    const list = `<div class="airow head"><span>Action item</span><span>Responsible</span><span>Requestor</span><span>Last activity</span><span class="num">Days pending</span><span>Due date</span></div>`
      + a.items.map(i=>`<div class="airow"><span>${aiLink(i)}${cmtPop(i)}</span><span class="pend">${respOf(i)}</span><span>${i.req||'—'}</span><span class="dt">${i.eff||'—'}${i.noComment?'*':''}</span><span class="dt num">${dur(i.days,i.wdays)}</span><span class="dt">${i.due?`<span class="${dueCls(i.due)}">${i.due}</span>`:'—'}</span></div>`).join('');
    const note = a.items.some(i=>i.noComment)
      ? '<div class="ainote">* no comments yet — dates and days pending count from when the AI was created.</div>' : '';
    aibox = `<div class="aibox">
      ${a.count} open AI${a.count>1?'s':''} &middot; latest: <b>${aiLink(L)}</b>${cmtPop(L)},
      pending on <span class="pend">${L.on||'—'}</span> for <b>${dur(L.days,L.wdays)}</b>
      &middot; ${L.noComment?`created <span class="dt">${fmt(L.eff)}</span> <i>· no comments yet</i>`:`last activity <span class="dt">${fmt(L.eff)}</span>${L.owner?` by ${L.owner}`:''}`}${dueTag(L)}
      <details class="ailist"><summary>${a.count>1?'All open items':'Item details'}</summary><div class="aitable">${list}</div>${note}</details>
    </div>`;
  } else {
    aibox = `<div class="aibox"><span class="none">No open action items linked to this client + carrier.</span></div>`;
  }
  return `<div class="conn" id="conn-${c.id}">
    <div class="top">
      <div class="name"><a class="lnk" href="${crUrl(c.id)}" target="_blank">${c.carrier} <small>— ${c.customer}</small></a> <small class="dt">CR #${c.id}</small></div>
      <div class="chips">
        ${isForms(c)?`<span class="chip ctype">${c.type}</span>`:''}
        ${isMig(c.mig)?`<span class="chip" style="background:var(--blue-bg);color:var(--blue)">${/^yes$/i.test(c.mig)?'Migration':c.mig}</span>`
          :(c.mig!=null?'<span class="chip" style="background:var(--accent-soft);color:var(--accent)">New Orders</span>':'')}
        <span class="chip ${statusCls(c.status)}">${c.status}</span>
        <span class="chip ${idleCls(c.idleWdays)}">${c.idleDays==null?'no activity':dur(c.idleDays,c.idleWdays)+' since activity'}</span>
        <button class="copybtn" data-copy="conn:${c.id}" title="Copy this connection's report">Copy</button>
      </div>
    </div>
    <div class="rail">${rail}</div>
    <div class="meta meta4">
      <div>Stage <b>${isForms(c)?c.type:`${c.stage} (${idx+1}/${STAGES.length})`}</b></div>
      <div>Instance <b>${c.instance||'—'}</b></div>
      <div>Migration <b>${migLabel(c.mig)}</b></div>
      <div>Assigned <b class="dt">${fmt(c.assigned)}</b></div>
      <div>Last CR update <b class="dt">${fmt(c.lastCr)}</b></div>
      <div>Last activity (CR or AI) <b class="dt">${fmt(c.lastAny)}</b></div>
      <div>${OTHER_ROLE_LABEL} <b>${c.isolved||'—'}</b></div>
      ${ms}
    </div>
    ${aibox}
  </div>`;
}

const oeStageIdx = s => { const i = OE_STAGES.findIndex(x=>x.toLowerCase()===String(s).toLowerCase());
  return i<0?0:i; };

function oeStageTips(o){
  // the OE report has no per-stage dates; map the ones it does have onto the
  // stages they start: Created -> Pending Start, DataReadyDate -> Sending OE
  // File, OEFileSubmissionDate -> Get Carrier Confirmation
  const sd = [o.created, null, null, null, o.dataReady, o.submitted, null];
  const tips = tipsFor(OE_STAGES, sd, oeStageIdx(o.stage));
  if(o.expected) tips[3] += ` · client data expected ${o.expected}`;
  return tips;
}

function oeCard(o){
  const idx = oeStageIdx(o.stage);
  const tips = oeStageTips(o);
  const rail = OE_STAGES.map((s,i)=>`<div class="seg ${i<idx?'done':(i===idx?'cur':'todo')}" data-tip="${tips[i]}">
      <div class="tip">${tips[i]}<small>click bar to copy &middot; or select this text</small></div>
      <i style="background:${OE_COLORS[i]}${i>idx?';opacity:.22':''}"></i><span>${OE_SHORT[i]}</span></div>`).join('');
  return `<div class="conn">
    <div class="top">
      <div class="name"><a class="lnk" href="${oeUrl(o.crId,o.id)}" target="_blank">${o.carrier} <small>— ${o.client}</small></a> <small class="dt">OE #${o.id} &middot; CR #${o.crId}</small></div>
      <div class="chips">
        ${o.draft?'<span class="chip status-notstarted">Draft</span>':''}
        ${o.dataChanges==='Yes'?'<span class="chip idle-warn">iSolved data changes</span>':''}
        ${o.groupStructure==='Yes'?'<span class="chip idle-warn">Updated group structure</span>':''}
        <span class="chip ${statusCls(o.status)}">${o.status}</span>
        <button class="copybtn" data-copy="oe:${o.id}" title="Copy this OE request's report">Copy</button>
      </div>
    </div>
    <div class="rail">${rail}</div>
    <div class="stageline">Stage <b>${o.stage}</b> (${idx+1}/${OE_STAGES.length}) &middot; ${o.type||''}</div>
    <div class="meta">
      <div>Plan year start <b class="dt">${fmt(o.pysd)}</b></div>
      <div>Client data expected <b class="dt">${fmt(o.expected)}</b></div>
      <div>Data ready <b class="dt">${fmt(o.dataReady)}</b></div>
      <div>OE file submitted <b class="dt">${fmt(o.submitted)}</b></div>
      <div>iSolved data changes <b>${o.dataChanges||'—'}</b></div>
      <div>Updated group structure <b>${o.groupStructure||'—'}</b></div>
      <div>Can resume prod before PYSD <b>${o.canResume||'—'}</b></div>
      <div>Resumed production <b>${o.resumed||'—'}</b></div>
      <div>${OTHER_ROLE_LABEL} <b>${o.isolved||'—'}</b></div>
      <div>Created <b class="dt">${fmt(o.created)}</b>${o.createdBy?` by ${o.createdBy}`:''}</div>
    </div>
  </div>`;
}

function renderProd(months, mine){
  if(!months.length){ $('#bars').innerHTML=''; $('#mon').innerHTML='';
    $('#prodcount').textContent=''; $('#prodtable').innerHTML='<div class="empty">No production dates found.</div>'; return; }
  if(!months.includes(curMonth)) curMonth = months.at(-1);
  const mi = months.indexOf(curMonth);
  const start = Math.max(0, Math.min(mi-6, months.length-12));
  const win = months.slice(start, start+12);
  const counts = win.map(m=>mine.filter(p=>p.month===m).length);
  const max = Math.max(1,...counts);
  $('#bars').innerHTML = win.map((m,i)=>`
    <div class="barcol ${m===curMonth?'sel':''}" data-m="${m}">
      <div class="val">${counts[i]||''}</div>
      <div class="bar" style="height:${(counts[i]/max)*100}%"></div>
      <div class="lbl">${m.slice(2).replace('-','/')}</div>
    </div>`).join('');
  document.querySelectorAll('.barcol').forEach(el=>el.onclick=()=>{curMonth=el.dataset.m;render();});

  const rows = mine.filter(p=>p.month===curMonth).sort((a,b)=>a.date.localeCompare(b.date));
  const team = DATA.production.filter(p=>p.month===curMonth).length;
  $('#mon').innerHTML = months.map(m=>`<option${m===curMonth?' selected':''}>${m}</option>`).join('');
  $('#mon').onchange = e => { curMonth = e.target.value; render(); };
  const mrank = prodRank(curEmp, p=>p.month===curMonth);
  $('#prodcount').innerHTML = `<b>${rows.length}</b> for ${curEmp} &middot; team total ${team}`
    + (team ? ` &middot; <b>${Math.round(rows.length/team*1000)/10}%</b> of team total` : '')
    + (rows.length && mrank.ranked ? ` &middot; <a class="lnk rankbtn" data-scope="month" title="show the full ranking">rank <b>#${mrank.r}</b> of ${mrank.n}</a>` : '');
  $('#prodtable').innerHTML = rows.length ? `<table>
    <tr><th>CR</th><th>Customer - Carrier</th><th>Ready for Production date</th><th>Production date</th><th>Status</th><th></th></tr>
    ${rows.map(p=>`<tr id="prod-${p._i}"><td class="dt"><a class="lnk" href="${crUrl(p.id)}" target="_blank">#${p.id}</a></td><td>${p.customer} - ${p.carrier}</td>
      <td class="dt">${p.rfp||'—'}</td>
      <td class="dt">${p.prod||'—'}</td><td>${p.status}</td>
      <td><button class="copybtn" data-copy="prod:${p._i}" title="Copy this production record">Copy</button></td></tr>`).join('')}
  </table>` : '<div class="empty">No production CRs for this employee in this month.</div>';

  const idx = months.indexOf(curMonth);
  $('#prev').disabled = idx<=0; $('#next').disabled = idx>=months.length-1;
  $('#prev').onclick=()=>{ if(idx>0){curMonth=months[idx-1];render();} };
  $('#next').onclick=()=>{ if(idx<months.length-1){curMonth=months[idx+1];render();} };
}

// ---------- analyst report ----------
function connReport(c){
  const L = [];
  L.push(`${c.carrier} — ${c.customer} (CR #${c.id})`);
  L.push(crUrl(c.id));
  L.push(`Status: ${c.status} · Stage: ${isForms(c)?c.type:`${c.stage}${testStar(c)?' * (no test file sent yet)':''}`} · Migration: ${migLabel(c.mig)}`);
  L.push(`Assigned: ${c.assigned||'—'} · Last CR update: ${c.lastCr||'—'} · Last activity: ${c.lastAny||'—'}${c.idleDays!=null?` (${dur(c.idleDays,c.idleWdays)} idle)`:''}`);
  if(c.ai){
    L.push(`Action items (${c.ai.count} open):`);
    c.ai.items.forEach(i=>{
      L.push(`  - ${i.title||('AI #'+i.id)} — responsible ${respOf(i)} · requested by ${i.req||'—'} · pending for ${dur(i.days,i.wdays)}`
        +` · ${i.noComment?`created ${i.eff||'—'}, no comments yet`:`last activity ${i.eff||'—'}`}${i.due?` · due ${i.due}`:''}`);
      if(i.id!=null) L.push(`    ${aiUrl(c.id,i.id)}`);
    });
  } else L.push(`Action items: none open`);
  return L;
}

function prodReport(p){
  return [
    `${p.customer} — ${p.carrier} (CR #${p.id})`,
    crUrl(p.id),
    `Status: ${p.status} · Ready for Production: ${p.rfp||'—'} · Production: ${p.prod||'—'}`,
    `Technical contact: ${p.tc||'—'}`
  ];
}

function oeReport(o){
  const idx = oeStageIdx(o.stage);
  const L = [];
  L.push(`${o.carrier} — ${o.client} (OE #${o.id} · CR #${o.crId})`);
  L.push(oeUrl(o.crId, o.id));
  L.push(`Status: ${o.status} · Stage: ${o.stage} (${idx+1}/${OE_STAGES.length})${o.type?` · ${o.type}`:''}${o.draft?' · Draft':''}`);
  L.push(`Plan year start: ${o.pysd||'—'} · Client data expected: ${o.expected||'—'}`);
  L.push(`Data ready: ${o.dataReady||'—'} · OE file submitted: ${o.submitted||'—'}`);
  L.push(`iSolved data changes: ${o.dataChanges||'—'} · Updated group structure: ${o.groupStructure||'—'}`);
  L.push(`Can resume production before PYSD: ${o.canResume||'—'} · Resumed production: ${o.resumed||'—'}`);
  L.push(`isolved contact: ${o.isolved||'—'} · Technical contact: ${o.tc||'—'}`);
  L.push(`Created: ${o.created||'—'}${o.createdBy?` by ${o.createdBy}`:''}`);
  return L;
}

function buildReport(){
  const conns = DATA.connections.filter(c=>c.tc===curEmp)
      .sort((a,b)=>(b.idleDays??-1)-(a.idleDays??-1));
  const others = otherFor(curEmp);
  const sendingOes = (DATA.oes||[]).filter(o=>o.tc===curEmp
      && String(o.stage).trim().toLowerCase()==='sending oe file')
    .sort((a,b)=>String(a.pysd||'9999').localeCompare(String(b.pysd||'9999')));
  const openAIs = conns.reduce((s,c)=>s+(c.ai?c.ai.count:0),0);
  const L = [];
  L.push(`CONNECTIVITY REPORT — ${curEmp}`);
  L.push(`Data as of ${dataDates(', ')} · wd = working days (${WEEKEND_LABEL} excluded)`);
  L.push(`${conns.length} in-progress connections · ${conns.filter(c=>c.status==='On Hold').length} on hold · ${openAIs} open action items · ${others.length} open AIs on other CRs · ${sendingOes.length} OEs sending file`);
  conns.forEach((c,n)=>{
    L.push('');
    L.push(`${'='.repeat(70)}`);
    connReport(c).forEach((t,j)=>L.push(j===0 ? `${n+1}) ${t}` : `   ${t}`));
  });
  if(sendingOes.length){
    L.push('');
    L.push(`${'='.repeat(70)}`);
    L.push(`OE REQUESTS — SENDING OE FILE (${sendingOes.length}):`);
    sendingOes.forEach((o,n)=>{
      L.push('');
      oeReport(o).forEach((t,j)=>L.push(j===0 ? `${n+1}) ${t}` : `   ${t}`));
    });
  }
  if(others.length){
    L.push('');
    L.push(`${'='.repeat(70)}`);
    L.push(`LATE ACTION ITEMS — on this __WHO__'s other CRs, requested by them, or where they're the responsible party (${others.length}):`);
    others.forEach(a=>{
      const cid = a.cr ? a.cr.id : (a.crid!=null ? a.crid : null);
      L.push(`  - ${a.title||('AI #'+a.id)} — ${a.client} / ${a.carrier}${cid!=null?` (CR #${cid}${a.cr?`, ${a.cr.status}`:''})`:''}`);
      L.push(`    responsible ${respOf(a)} · requested by ${a.req||'—'} · pending for ${dur(a.days,a.wdays)} · ${a.noComment?`created ${a.eff||'—'}, no comments yet`:`last activity ${a.eff||'—'}`}${a.due?` · due ${a.due}`:''}`);
      if(a.id!=null && cid!=null) L.push(`    ${aiUrl(cid,a.id)}`);
    });
  }
  return L.join('\n');
}
$('#repbtn').onclick = () => {
  $('#reptitle').textContent = `Report — ${curEmp} · ${DATA.generated}`;
  $('#reptext').value = buildReport();
  $('#repmodal').classList.add('open');
};
$('#repclose').onclick = () => $('#repmodal').classList.remove('open');
$('#repmodal').onclick = e => { if(e.target.id==='repmodal') $('#repmodal').classList.remove('open'); };
$('#repcopy').onclick = () => {
  navigator.clipboard.writeText($('#reptext').value).then(()=>{
    $('#repcopy').textContent='Copied!'; setTimeout(()=>$('#repcopy').textContent='Copy',1200);
  });
};
$('#repdl').onclick = () => {
  const blob = new Blob([$('#reptext').value], {type:'text/plain;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `report_${curEmp.replace(/[^\w]+/g,'_')}_${DATA.generated}.txt`;
  a.click(); URL.revokeObjectURL(a.href);
};

// ---------- upload handling ----------
// employee box is a searchable input: picking a datalist entry switches at
// once; enter/blur also accepts a partial name and snaps back to a valid one
const resolveEmp = v => {
  const t = String(v||'').trim().toLowerCase();
  if(!t) return null;
  return DATA.employees.find(x=>x.toLowerCase()===t)
      || DATA.employees.find(x=>x.toLowerCase().includes(t)) || null;
};
$('#emp').oninput = e => {
  const hit = DATA.employees.find(x=>x===e.target.value);
  if(hit && hit!==curEmp){ curEmp = hit; render(); }
};
$('#emp').onchange = e => {
  const hit = resolveEmp(e.target.value);
  if(hit && hit!==curEmp){ curEmp = hit; render(); }
  e.target.value = curEmp;
};
$('#emp').onfocus = e => e.target.select();
// dropdown search helper: shows hits while typing, hides on blur, and calls
// pick() with the chosen hit's data-* attributes
function wireSearch(input, box, hitsFor, hitHtml, pick){
  const show = () => {
    const q = $(input).value.trim().toLowerCase();
    if(!q){ $(box).style.display='none'; return; }
    const hits = hitsFor(q);
    $(box).innerHTML = hits.length ? hits.map(hitHtml).join('')
      : '<div class="none">No matches.</div>';
    $(box).style.display='block';
  };
  $(input).oninput = show;
  $(input).onfocus = show;
  $(input).onblur = () => setTimeout(()=>{ $(box).style.display='none'; }, 150);
  $(box).onmousedown = e => {
    const h = e.target.closest('.hit');
    if(!h) return;
    $(box).style.display='none'; $(input).value='';
    pick(h.dataset);
  };
}
// scroll to an element and flash-highlight it
function jumpTo(el){
  if(!el) return;
  el.scrollIntoView({behavior:'smooth', block:'center'});
  const oldBg = el.style.background;
  el.style.boxShadow = '0 0 0 3px var(--accent)';
  el.style.background = 'var(--accent-soft)';
  setTimeout(()=>{ el.style.boxShadow=''; el.style.background = oldBg; }, 1600);
}
// global connection search: matches every active connection (all employees)
// by client, carrier or CR #; picking one switches to its assigned contact
// (the analyst here, the iSolved contact on the iSolved page) and jumps to
// the card
wireSearch('#connsearch', '#connresults',
  q => { const qid = q.replace(/^#/,'');   // digit queries also match partial CR ids
    return DATA.connections.filter(c =>
      c.customer.toLowerCase().includes(q) || c.carrier.toLowerCase().includes(q)
      || (/^\d+$/.test(qid) && String(c.id).includes(qid))).slice(0,15); },
  c => `<div class="hit" data-id="${c.id}">${esc(c.carrier)} — ${esc(c.customer)}
      <small>CR #${c.id} &middot; ${esc(c.status)} &middot; ${esc(c.tc)}</small></div>`,
  d => {
    const c = DATA.connections.find(x=>String(x.id)===d.id);
    if(!c) return;
    if(c.tc!==curEmp){ curEmp = c.tc; $('#emp').value = curEmp; render(); }
    if($('#conns').style.display==='none') $('#connstoggle').click();
    jumpTo(document.getElementById('conn-'+c.id));
  });
// production search: matches every CR with a production / RFP date (all
// employees, all months); picking one switches to that person and month and
// jumps to the row
wireSearch('#prodsearch', '#prodresults',
  q => { const qid = q.replace(/^#/,'');   // digit queries also match partial CR ids
    return DATA.production.filter(p => p.tc &&
      (p.customer.toLowerCase().includes(q) || p.carrier.toLowerCase().includes(q)
      || (/^\d+$/.test(qid) && String(p.id).includes(qid)))).slice(0,15); },
  p => `<div class="hit" data-i="${p._i}">${esc(p.carrier)} — ${esc(p.customer)}
      <small>CR #${p.id} &middot; ${p.date} &middot; ${esc(p.tc)}</small></div>`,
  d => {
    const p = DATA.production[+d.i];
    if(!p) return;
    if(p.tc!==curEmp || p.month!==curMonth){
      curEmp = p.tc; $('#emp').value = curEmp; curMonth = p.month; render();
    }
    jumpTo(document.getElementById('prod-'+p._i));
  });
// collapse / expand sections: "other action items" starts collapsed,
// connections & OEs start expanded
function toggler(h2, body, caret, open){
  $(body).style.display = open ? '' : 'none';
  $(caret).innerHTML = open ? '&#9662;' : '&#9656;';
  $(h2).onclick = () => toggler(h2, body, caret, !open);
}
toggler('#othertoggle', '#otherais', '#othercaret', false);
toggler('#connstoggle', '#conns', '#connscaret', true);
toggler('#oestoggle', '#oes', '#oescaret', true);
// light / dark mode: toggle in the header, remembered in this browser and
// shared by both pages; first visit follows the OS preference
function applyTheme(t){
  document.documentElement.dataset.theme = t;
  $('#themebtn').textContent = t==='dark' ? '☀️' : '🌙';
  try{ localStorage.setItem('dashTheme', t); }catch(e){}
}
let savedTheme = null;
try{ savedTheme = localStorage.getItem('dashTheme'); }catch(e){}
applyTheme(savedTheme==='dark' || savedTheme==='light' ? savedTheme
  : (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
$('#themebtn').onclick = () =>
  applyTheme(document.documentElement.dataset.theme==='dark' ? 'light' : 'dark');
// per-card / per-row copy buttons
document.addEventListener('click', e => {
  const b = e.target.closest('.copybtn');
  if(!b || !b.dataset.copy || !navigator.clipboard) return;
  const [kind, id] = b.dataset.copy.split(':');
  let lines = null;
  if(kind==='conn'){ const c = DATA.connections.find(x=>String(x.id)===id); if(c) lines = connReport(c); }
  else if(kind==='prod'){ const p = DATA.production[+id]; if(p) lines = prodReport(p); }
  else if(kind==='oe'){ const o = (DATA.oes||[]).find(x=>String(x.id)===id); if(o) lines = oeReport(o); }
  if(!lines) return;
  navigator.clipboard.writeText(lines.join('\n')).then(()=>{
    b.textContent='Copied!'; setTimeout(()=>b.textContent='Copy',1200);
  });
});
// last-comment popup: fixed-position so table/scroll containers can't clip it
document.addEventListener('mouseover', e => {
  const pop = $('#cmtpop');
  const t = e.target.closest ? e.target.closest('.cmt') : null;
  if(!t){ pop.style.display='none'; return; }
  pop.replaceChildren(document.createTextNode(t.dataset.c||''));
  if(t.dataset.m){ const s = document.createElement('small'); s.textContent = t.dataset.m; pop.appendChild(s); }
  pop.style.display='block';
  const r = t.getBoundingClientRect();
  let x = r.left + r.width/2 - pop.offsetWidth/2;
  x = Math.max(8, Math.min(x, innerWidth - pop.offsetWidth - 8));
  let y = r.top - pop.offsetHeight - 8;
  if(y < 8) y = r.bottom + 8;
  pop.style.left = x+'px'; pop.style.top = y+'px';
});
// click a progress-bar phase to copy its tooltip text
document.addEventListener('click', e => {
  const seg = e.target.closest('.rail .seg');
  if(!seg || !seg.dataset.tip || e.target.closest('.tip')) return; // clicks inside the tooltip = selecting text
  if(!navigator.clipboard) return;
  navigator.clipboard.writeText(seg.dataset.tip).then(()=>{
    const h = seg.querySelector('.tip small');
    if(h){ const old = h.innerHTML; h.textContent = 'Copied!'; setTimeout(()=>h.innerHTML = old, 1200); }
  });
});
// the report's own date: an export timestamp in the filename (YYYY-MM-DD or
// YYYY_MM_DD) if present, else the file's last-modified (download) date
function fileDate(f){
  const m = String(f.name).match(/(20\d\d)[-_](\d\d)[-_](\d\d)/);
  if(m) return `${m[1]}-${m[2]}-${m[3]}`;
  if(f.lastModified) return localDay(new Date(f.lastModified));
  return localDay(new Date());
}
$('#files').onchange = async e => {
  const msg = $('#upmsg');
  try{
    if(typeof XLSX==='undefined') throw new Error('Excel parser unavailable — check internet connection.');
    const files = [...e.target.files];
    if(!files.length) return;
    msg.className=''; msg.textContent='Reading…';
    let newCr=null, newAi=null, newOe=null, newMs=null, names=[];
    let crDate=null, aiDate=null, oeDate=null;
    for(const f of files){
      // no cellDates: date cells stay raw Excel serial numbers, which encode
      // the sheet's literal calendar day — no timezone interpretation at all
      const wb = XLSX.read(await f.arrayBuffer());
      const rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], {defval:null});
      const cols = new Set(Object.keys(rows[0]||{}));
      const tags = [];
      if(cols.has('ActionItemID')||cols.has('CurrentlyPendingOn')){ newAi=rows; aiDate=fileDate(f); tags.push('AI'); }
      else if(cols.has('OERequestID')){ newOe=rows.filter(r=>ACTIVE.has(txt(r['Status']))); oeDate=fileDate(f); tags.push('OE'); }
      else if(cols.has('Request ID')){ newCr=rows; crDate=fileDate(f); tags.push('CR'); }
      // MigrationSummary — any sheet in the workbook carrying MigrationTestingDate
      const mss = wb.SheetNames.find(n=>((XLSX.utils.sheet_to_json(wb.Sheets[n],{header:1})[0])||[]).includes('MigrationTestingDate'));
      if(mss){ newMs = XLSX.utils.sheet_to_json(wb.Sheets[mss], {defval:null}); tags.push('MigrationSummary'); }
      names.push(f.name + (tags.length ? ` (${tags.join(', ')})` : ' (unrecognized — skipped)'));
    }
    if(!newCr && !newAi && !newOe && !newMs) throw new Error('No file matched the CR, AI, OE or MigrationSummary report format.');
    if(newCr){ RAW.cr = newCr; RAW.dates.cr = crDate; }
    if(newAi){ RAW.ai = newAi; RAW.dates.ai = aiDate; }
    if(newOe){ RAW.oe = newOe; RAW.dates.oe = oeDate; }
    if(newMs){ RAW.ms = newMs; }
    // "today" for day-based calcs = the newest report date currently loaded
    RAW.generated = [RAW.dates.cr, RAW.dates.ai, RAW.dates.oe].filter(Boolean).sort().at(-1) || localDay(new Date());
    DATA = process(RAW.cr, RAW.ai, RAW.oe, RAW.generated);
    let saveWarn = '';
    try{ await dbSet(DB_KEY, JSON.stringify(RAW)); }
    catch(e){ saveWarn = ` — warning: couldn't save for next visit (${e && e.message || e})`; }
    initSelectors(); render();
    msg.className='ok';
    msg.textContent = `Updated: ${names.join(', ')} — ${DATA.connections.length} active connections, ${RAW.ai.length} AIs, ${DATA.oes.length} in-progress OEs`
      + (newCr&&newAi&&newOe ? '' : ' (other reports kept from previous data)') + saveWarn;
  }catch(err){ msg.className='err'; msg.textContent='Update failed: '+err.message; }
  e.target.value='';
};

restoreSaved().catch(()=>{}).then(()=>{
  initSelectors(); render();
  if(!RAW.cr.length && !RAW.ai.length){
    const m = $('#upmsg'); m.className = 'ok';
    m.textContent = 'No data loaded yet — use "Update data" above to upload the CR, AI and OE reports.';
  }
});
</script>
</body>
</html>
"""

TEAM_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Team Overview</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
<style>
  :root{
    --ink:#1b2733; --ink-soft:#5b6b7b; --paper:#f5f6f4; --card:#ffffff;
    --line:#e2e6e1; --accent:#0f6f5c; --accent-soft:#e2f0ec;
    --amber:#965900; --amber-bg:#fdf2df; --red:#b3261e; --red-bg:#fbe9e7;
    --blue:#2b5d8a; --blue-bg:#e7eff6;
    --head:#1b2733; --pop:#1b2733; --th-bg:#fafbf9; --bar:#c9d6d1;
    --ring:rgba(27,39,51,.3); --chip-mute:#ececec; --chip-mute-ink:#555;
    --mono:'SF Mono',Consolas,'Liberation Mono',monospace;
    color-scheme:light;
    --s0:#8fa3bd; --s1:#5f8fd4; --s2:#38619e; --s3:#008aa0;
    --s4:#0f9682; --s5:#3f9d54; --s6:#b26a00; --s7:#00845f;
  }
  :root[data-theme="dark"]{
    --ink:#e8edf2; --ink-soft:#9aa8b5; --paper:#12181f; --card:#1b232c;
    --line:#2c3742; --accent:#3fb59a; --accent-soft:#173229;
    --amber:#e0a24a; --amber-bg:#33270f; --red:#e57373; --red-bg:#3a1d1a;
    --blue:#7aa7cf; --blue-bg:#1c2a38;
    --head:#0d1319; --pop:#0d1319; --th-bg:#202a34; --bar:#3a4a45;
    --ring:rgba(232,237,242,.35); --chip-mute:#2c3742; --chip-mute-ink:#b6c2cd;
    color-scheme:dark;
    --s0:#7b8ca6; --s1:#6b95d6; --s2:#4a6fae; --s3:#1897ad;
    --s4:#1fa28e; --s5:#4fa960; --s6:#c08228; --s7:#2f9d85;
  }
  *{box-sizing:border-box;margin:0}
  body{font:15px/1.45 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
       background:var(--paper);color:var(--ink);padding-bottom:60px}
  header{background:var(--head);color:#fff;padding:16px}
  header .wrap{display:flex;justify-content:space-between;align-items:flex-start;gap:16px 24px;flex-wrap:wrap}
  header h1{font-size:19px;font-weight:650;letter-spacing:.2px}
  header .sub{color:#9fb0bf;margin-top:6px;display:flex;align-items:center;flex-wrap:wrap;gap:8px}
  header .sub .sublabel{font-size:12px;font-weight:600;letter-spacing:.5px;text-transform:uppercase}
  header .sub #gen{display:flex;flex-wrap:wrap;gap:6px}
  header .sub .dchip{font-size:11px;font-weight:650;font-family:var(--mono);
        padding:2px 9px;border-radius:20px;white-space:nowrap}
  header .sub .dchip b{font-weight:700}
  header .sub .dchip.idle-ok{background:rgba(63,181,154,.15);color:#6fd0b6}
  header .sub .dchip.idle-warn{background:rgba(224,162,74,.17);color:#e8bd77}
  header .sub .dchip.idle-bad{background:rgba(229,115,115,.17);color:#f0a19d}
  .hright{display:flex;flex-direction:column;align-items:flex-end;gap:8px}
  .htop{display:flex;align-items:center;gap:12px}
  .viewlink{color:#9fb0bf;font-size:12.5px;text-decoration:underline dotted;
        text-underline-offset:2px;white-space:nowrap;display:inline-block;margin-top:6px;margin-right:12px}
  .viewlink:hover{color:#fff}
  .upload{display:flex;align-items:center;gap:8px}
  .upload label{background:#2e4155;color:#dfe8f0;font-size:12.5px;font-weight:650;
        padding:8px 14px;border-radius:8px;cursor:pointer;border:1px solid #45596e}
  .upload label:hover{background:#3a5069}
  #themebtn{font:inherit;font-size:15px;line-height:1;background:transparent;color:#9fb0bf;
        border:1px solid #45596e;border-radius:8px;padding:8px 10px;cursor:pointer}
  #themebtn:hover{background:#2e4155;color:#dfe8f0}
  #upmsg{font-size:12px;font-family:var(--mono);max-width:360px;text-align:right}
  #upmsg.ok{color:#8fd6b8} #upmsg.err{color:#ffb3ad}
  .wrap{max-width:1100px;margin:0 auto;padding:0 12px}
  h2{font-size:14px;text-transform:uppercase;letter-spacing:.8px;color:var(--ink-soft);
     margin:22px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
  h2 .note{text-transform:none;letter-spacing:0;font-weight:400}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0 18px}
  .kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
  .kpi b{display:block;font-size:26px;font-weight:700}
  .kpi span{font-size:12px;color:var(--ink-soft);text-transform:uppercase;letter-spacing:.5px}
  .kpi .kpi-sub{display:block;font-size:11px;color:var(--ink-soft);text-transform:none;letter-spacing:0;margin-top:3px}
  .kpi.warn b{color:var(--amber)} .kpi.bad b{color:var(--red)}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
  .legend{display:flex;gap:16px;font-size:12px;color:var(--ink-soft);margin-bottom:12px;flex-wrap:wrap}
  .legend i{width:10px;height:10px;border-radius:3px;display:inline-block;margin-right:6px;vertical-align:-1px}
  .gbars{display:flex;align-items:flex-end;gap:8px;height:150px;margin-bottom:24px}
  .gcol{flex:1;display:flex;flex-direction:column;justify-content:flex-end;height:100%;position:relative}
  .gpair{display:flex;align-items:flex-end;justify-content:center;gap:2px;height:100%}
  .gbar{width:11px;max-width:30%;border-radius:4px 4px 0 0;min-height:2px}
  .gbar.in{background:var(--blue)} .gbar.out{background:var(--accent)} .gbar.cx{background:var(--bar)}
  .glbl{position:absolute;bottom:-20px;left:0;right:0;text-align:center;font-size:10px;
        font-family:var(--mono);color:var(--ink-soft)}
  .gval{font-size:10px;font-family:var(--mono);color:var(--ink-soft);text-align:center;margin-bottom:3px}
  .hrows{display:grid;grid-template-columns:max-content 1fr max-content max-content;gap:9px 14px;align-items:center}
  .hrows.w3{grid-template-columns:max-content 1fr max-content}
  .hrow{display:contents}
  .hname{font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;white-space:nowrap}
  .hname i{width:10px;height:10px;border-radius:3px;display:inline-block;flex:none}
  .htrack{background:var(--paper);border-radius:6px;height:14px;overflow:hidden}
  .hbar{height:100%;border-radius:6px;min-width:2px;background:var(--accent)}
  .hval{font-family:var(--mono);font-size:12.5px;font-weight:700;text-align:right}
  .hsub{font-family:var(--mono);font-size:11px;color:var(--ink-soft);text-align:right;white-space:nowrap}
  .hnote{font-size:11px;color:var(--ink-soft);font-style:italic;margin-top:10px}
  .risks{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}
  .risk{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
  .risk b{display:block;font-size:22px;font-weight:700}
  .risk span{font-size:12px;color:var(--ink-soft)}
  .risk.warn b{color:var(--amber)} .risk.bad b{color:var(--red)}
  .risk .drill{margin-top:6px;font-size:11.5px;color:var(--blue);cursor:pointer;
        text-decoration:underline dotted;text-underline-offset:2px}
  .risk .drill:hover{color:var(--ink)}
  .rlist{display:none;margin-top:8px;border-top:1px solid var(--line);padding-top:8px;
        max-height:220px;overflow:auto;font-size:12px}
  .rlist div{padding:3px 0;border-bottom:1px solid var(--line)}
  .rlist div:last-child{border-bottom:none}
  .empty{color:var(--ink-soft);font-style:italic;padding:14px}
  a.lnk{color:inherit;text-decoration:underline dotted;text-underline-offset:2px}
  a.lnk:hover{color:var(--blue);text-decoration:underline solid}
  .dt{font-family:var(--mono);font-size:12.5px}
  .yearsel{font:inherit;font-weight:700;font-family:var(--mono);font-size:13px;min-width:0;
        padding:2px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);
        color:var(--ink);letter-spacing:0;cursor:pointer}
  .stagebars{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;
        display:grid;grid-template-columns:max-content 1fr max-content max-content;gap:10px 14px;align-items:center}
  .stagebars .srow{display:contents}
  .stagebars .sname{font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;white-space:nowrap}
  .stagebars .sname i{width:10px;height:10px;border-radius:3px;display:inline-block;flex:none}
  .stagebars .strack{background:var(--paper);border-radius:6px;height:14px;overflow:hidden}
  .stagebars .sbar{height:100%;border-radius:6px;min-width:2px}
  .stagebars .sval{font-family:var(--mono);font-size:12.5px;font-weight:700;text-align:right}
  .stagebars .scnt{font-family:var(--mono);font-size:11px;color:var(--ink-soft);text-align:right}
  .stagebars .scnt .outbtn{color:var(--amber);cursor:pointer;text-decoration:underline dotted;text-underline-offset:2px}
  .stagebars .scnt .outbtn:hover{color:var(--red)}
  .stagebars .scnt .msbtn{color:var(--blue);cursor:pointer;text-decoration:underline dotted;text-underline-offset:2px}
  .stagebars .scnt .msbtn:hover{color:var(--ink)}
  .stagebars .souts{grid-column:1/-1;background:var(--paper);border:1px dashed var(--line);border-radius:8px;
        padding:8px 12px;font-size:12.5px;display:flex;flex-direction:column;gap:4px;margin:-2px 0 4px}
  .stagebars .msplit{grid-column:1/-1;display:grid;grid-template-columns:minmax(150px,230px) minmax(60px,1fr) max-content max-content;
        gap:8px 14px;align-items:center;background:var(--paper);border:1px dashed var(--line);border-radius:8px;padding:10px 12px;margin:-2px 0 6px}
  .stagebars .msplit .msrow{display:contents}
  .stagebars .msplit .msname{display:flex;align-items:flex-start;gap:8px}
  .stagebars .msplit .msname i{width:9px;height:9px;border-radius:3px;display:inline-block;flex:none;margin-top:3px}
  .stagebars .msplit .msname .mslbl{display:flex;flex-direction:column;line-height:1.25;font-size:12.5px;font-weight:600}
  .stagebars .msplit .msname .mslbl small{color:var(--ink-soft);font-weight:400;font-size:11px}
  .stagebars .msplit .mstrack{background:var(--card);border-radius:6px;height:12px;overflow:hidden}
  .stagebars .msplit .msbar{height:100%;border-radius:6px;min-width:2px}
  .stagebars .msplit .msval{font-family:var(--mono);font-size:12px;font-weight:700;text-align:right}
  .stagebars .msplit .mscnt{font-family:var(--mono);font-size:11px;color:var(--ink-soft);text-align:right}
  .stagebars .msplit .mscnt .outbtn{color:var(--amber);cursor:pointer;text-decoration:underline dotted;text-underline-offset:2px}
  .stagebars .msplit .mscnt .outbtn:hover{color:var(--red)}
  .stagebars .msplit .msouts{grid-column:1/-1;display:flex;flex-direction:column;gap:3px;font-size:12px;padding:4px 2px 2px;border-top:1px dashed var(--line)}
  @media(max-width:600px){ .stagebars .msplit{grid-template-columns:minmax(120px,1fr) 1fr max-content} .stagebars .msplit .mscnt{display:none} }
  @media(max-width:600px){ .stagebars{grid-template-columns:max-content 1fr max-content} .stagebars .scnt{display:none} }

  /* ── UI/UX Pro Max visual upgrade layer ─────────────────────────────
     Appended after the base rules: adds elevation, motion and focus
     polish on top of the existing tokens without changing structure. */
  :root{
    --shadow-sm:0 1px 2px rgba(16,32,44,.05),0 1px 3px rgba(16,32,44,.05);
    --shadow-md:0 2px 8px rgba(16,32,44,.07),0 10px 28px rgba(16,32,44,.07);
    --shadow-lg:0 18px 44px rgba(16,32,44,.16);
    --ease:cubic-bezier(.4,0,.2,1); --t:180ms;
    --focus:0 0 0 3px color-mix(in srgb, var(--accent) 32%, transparent);
    --head-grad:linear-gradient(165deg,#243543 0%,#161f29 100%);
    --accent-grad:linear-gradient(90deg,var(--accent),#12a488);
  }
  :root[data-theme="dark"]{
    --shadow-sm:0 1px 2px rgba(0,0,0,.45);
    --shadow-md:0 2px 10px rgba(0,0,0,.5),0 14px 32px rgba(0,0,0,.4);
    --shadow-lg:0 20px 48px rgba(0,0,0,.6);
    --focus:0 0 0 3px color-mix(in srgb, var(--accent) 42%, transparent);
    --head-grad:linear-gradient(165deg,#121b24 0%,#0a0f15 100%);
    --accent-grad:linear-gradient(90deg,var(--accent),#54c9ae);
  }
  body{-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
  /* header gains depth + a subtle gradient */
  header{background:var(--head-grad);box-shadow:var(--shadow-md);
    border-bottom:1px solid rgba(255,255,255,.06)}
  /* section headings get an accent marker */
  h2{position:relative;padding-left:13px}
  h2::before{content:'';position:absolute;left:0;top:1px;bottom:9px;width:3px;
    border-radius:3px;background:var(--accent-grad)}
  /* KPI cards: elevation + accent strip + hover lift + tabular figures */
  .kpi{position:relative;overflow:hidden;border-radius:12px;box-shadow:var(--shadow-sm);
    transition:transform var(--t) var(--ease),box-shadow var(--t) var(--ease),border-color var(--t) var(--ease)}
  .kpi::before{content:'';position:absolute;inset:0 0 auto 0;height:3px;background:var(--accent-grad)}
  .kpi:hover{transform:translateY(-2px);box-shadow:var(--shadow-md);
    border-color:color-mix(in srgb, var(--accent) 30%, var(--line))}
  .kpi b{font-variant-numeric:tabular-nums;letter-spacing:-.02em}
  /* connection / request cards: soft elevation that responds to hover */
  .conn{box-shadow:var(--shadow-sm);
    transition:box-shadow var(--t) var(--ease),border-color var(--t) var(--ease)}
  .conn:hover{box-shadow:var(--shadow-md);
    border-color:color-mix(in srgb, var(--accent) 22%, var(--line))}
  /* data panels join the same elevation family */
  .stagebars,.bars,table{box-shadow:var(--shadow-sm)}
  /* table rows highlight on hover (header row uses th, so it stays put) */
  td{transition:background-color var(--t) var(--ease)}
  tr:hover>td{background:var(--accent-soft)}
  /* interactive elements animate smoothly and show a clear focus ring */
  button,select,input,.upload label,.copybtn,a.viewlink,summary{
    transition:background-color var(--t) var(--ease),border-color var(--t) var(--ease),
      box-shadow var(--t) var(--ease),color var(--t) var(--ease),transform var(--t) var(--ease)}
  input:focus,select:focus{border-color:var(--accent)}
  button:focus-visible,select:focus-visible,input:focus-visible,
  a:focus-visible,summary:focus-visible,label:focus-visible{outline:none;box-shadow:var(--focus)}
  .toolbar button:hover,.prodhead button:hover,.rephead button:hover{
    border-color:color-mix(in srgb, var(--accent) 40%, var(--line))}
  /* floating surfaces sit higher off the page */
  .search .results,.repbox{box-shadow:var(--shadow-lg)}
  /* refined scrollbars */
  *::-webkit-scrollbar{width:11px;height:11px}
  *::-webkit-scrollbar-thumb{background:var(--line);border-radius:10px;border:3px solid var(--card)}
  *::-webkit-scrollbar-thumb:hover{background:var(--ink-soft)}
  /* honour reduced-motion preferences */
  @media(prefers-reduced-motion:reduce){
    *{transition-duration:.01ms!important;animation-duration:.01ms!important;scroll-behavior:auto!important}
  }
</style>
</head>
<body>
<header><div class="wrap">
  <div class="hleft">
    <h1>Team Overview</h1>
    <div class="sub"><span class="sublabel">Data as of</span> <span id="gen"></span></div>
    <a class="viewlink" href="index.html">Analyst view &rarr;</a>
    <a class="viewlink" href="isolved.html">iSolved view &rarr;</a>
  </div>
  <div class="hright">
    <div class="htop">
      <button id="themebtn" aria-label="Switch light / dark mode" title="Switch light / dark mode">&#127769;</button>
    </div>
    <div class="upload">
      <label for="files">&#8682; Update data (upload CR / AI / OE reports)</label>
      <input id="files" type="file" accept=".xlsx,.xls" multiple style="display:none">
    </div>
    <div id="upmsg"></div>
  </div>
</div></header>
<div class="wrap">
  <div class="kpis" id="kpis"></div>

  <h2>Intake vs output <span class="note">&middot; CRs created, taken to production, and cancelled each month</span></h2>
  <div class="card">
    <div class="legend">
      <span><i style="background:var(--blue)"></i>Created</span>
      <span><i style="background:var(--accent)"></i>Produced</span>
      <span><i style="background:var(--bar)"></i>Cancelled</span>
    </div>
    <div class="gbars" id="gbars"></div>
    <div id="gnote" class="hnote"></div>
  </div>

  <h2>Pipeline stage duration <span style="text-transform:none;letter-spacing:0;font-weight:400">&middot; average time connections spent in each stage &middot; year <select id="duryear" class="yearsel"></select> &middot; show <select id="durstate" class="yearsel"><option value="All">all</option><option value="prod">production</option><option value="inprog">in progress</option></select> &middot; request type <select id="durtype" class="yearsel"></select> &middot; migration <select id="durmig" class="yearsel"></select> &middot; outlier filter <select id="durconf" class="yearsel"><option value="90">90%</option><option value="95">95%</option><option value="99">99%</option><option value="100">off</option></select> &middot; total: <b id="durcount" style="color:var(--ink)"></b></span></h2>
  <div class="card" id="stagedur"></div>

  <h2>Cycle time trend <span class="note">&middot; average days from assignment to ready-for-production, by month produced</span></h2>
  <div class="card">
    <div class="gbars" id="cbars" style="height:120px"></div>
    <div id="cnote" class="hnote"></div>
  </div>

  <h2>Pipeline <span class="note">&middot; where active connections sit, and how long they have been sitting there</span></h2>
  <div class="card" id="pipeline"></div>

  <h2>Aging of active work <span class="note">&middot; days since assignment</span></h2>
  <div class="card" id="aging"></div>

  <h2>Workload balance <span class="note">&middot; active connections and open action items per analyst</span></h2>
  <div class="card" id="workload"></div>

  <h2>Needs attention</h2>
  <div class="risks" id="risks"></div>
</div>
<script>
const RAW = __RAW__;
RAW.oe = RAW.oe || []; RAW.ms = RAW.ms || []; RAW.dates = RAW.dates || {};

const STAGES = ["Pending Start","Requirements Gathering","Resource Assignment",
  "Dataset Validation","Mapping","Testing","Ready for Production","Production"];
const STAGE_COLS = ["Created Date","Requirements Gathering","Resource Assignment",
  "Dataset Validation","Mapping","Testing","Ready For Production","Production"];
const OE_STAGES = ["Pending Start","Resource Assignment","Requirement Gathering",
  "Waiting for OE Data","Sending OE File","Get Carrier Confirmation","Completed"];
const ACTIVE = new Set(["In Progress","Blocked","On Hold","Not Started"]);
const STAGE_COLORS = Array.from({length:8}, (_,i)=>`var(--s${i})`);
// an action item pending on one of these is waiting on someone outside the team
const EXTERNAL = /carrier|client|partner|vendor/i;
const $ = s => document.querySelector(s);
const BASE = 'https://d24ep0r8pqsi0a.cloudfront.net';
const crUrl = id => `${BASE}/ConnectivityRequests/ViewConnectivityRequest/${id}`;

// ---------- helpers (same rules as the analyst / iSolved pages) ----------
const localDay = d => d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
function toISO(v){
  if(v==null || v==='') return null;
  if(v instanceof Date && !isNaN(v)) return localDay(v);
  if(typeof v==='number'){ const d = new Date(Math.round((v-25569)*86400*1000));
    return isNaN(d)?null:d.toISOString().slice(0,10); }
  const s = String(v).trim();
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})($|[T ])/);
  if(m){ if(m[4]){ const d = new Date(s); if(!isNaN(d)) return localDay(d); } return m[1]+'-'+m[2]+'-'+m[3]; }
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if(m) return m[3]+'-'+m[1].padStart(2,'0')+'-'+m[2].padStart(2,'0');
  const d = new Date(s);
  return isNaN(d)?null:localDay(d);
}
const txt = v => (v==null ? '' : String(v).trim());
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const daysBetween = (iso, today) => Math.floor((today - new Date(iso+'T00:00:00Z'))/86400000);
const WEEKEND = new Set([5,6]);
function workDaysBetween(iso, today){
  const start = new Date(iso+'T00:00:00Z');
  const days = Math.floor((today - start)/86400000);
  if(days <= 0) return 0;
  const weeks = Math.floor(days/7);
  let wd = weeks*5, dow = start.getUTCDay();
  for(let k = days - weeks*7; k > 0; k--){ dow = (dow+1)%7; if(!WEEKEND.has(dow)) wd++; }
  return wd;
}
const stageIdx = s => { let t = String(s).toLowerCase();
  if(t==='obtain customer dataset') t = 'dataset validation';
  const i = STAGES.findIndex(x=>x.toLowerCase()===t); return i<0?0:i; };
const idleCls = n => n==null?'idle-ok':(n>=10?'idle-bad':(n>=4?'idle-warn':'idle-ok'));
const pct = (a,b) => b? Math.round(a/b*100) : 0;
function quantile(arr, q){
  if(!arr.length) return 0;
  const s = [...arr].sort((x,y)=>x-y);
  const pos = (s.length-1)*q, base = Math.floor(pos), rest = pos-base;
  return Math.round(s[base+1]!==undefined ? s[base]+rest*(s[base+1]-s[base]) : s[base]);
}
const mean = a => a.length ? Math.round(a.reduce((s,x)=>s+x,0)/a.length) : 0;

// Testing starts at the First Test File date; but if that date is more than
// FTF_MAX_LEAD days before the Testing-stage date, it's treated as a stale /
// wrong entry and the Testing-stage date is used instead (same rule as the
// analyst page)
const FTF_MAX_LEAD = 30;
function testingStart(r){
  const ftf = toISO(r['First Test File']);
  const tst = toISO(r['Testing']);
  if(!ftf) return tst;
  if(tst && daysBetween(ftf, new Date(tst+'T00:00:00Z')) > FTF_MAX_LEAD) return tst;
  return ftf;
}

// ---------- aggregate the three reports into team-level numbers ----------
function teamStats(){
  const cr = RAW.cr||[], ai = RAW.ai||[], oe = RAW.oe||[];
  const asOf = RAW.dates.cr || RAW.generated;
  const today = new Date(asOf+'T00:00:00Z');
  const aiToday = new Date((RAW.dates.ai || RAW.generated)+'T00:00:00Z');

  const active = cr.filter(r=>ACTIVE.has(txt(r['Status'])));
  const unassigned = active.filter(r=>!txt(r['Technical Contact']));
  const stalled = active.filter(r=>['Blocked','On Hold'].includes(txt(r['Status'])));
  const analysts = [...new Set(active.map(r=>txt(r['Technical Contact'])).filter(Boolean))];

  // ---- intake / output / cancellation by month, plus cycle times ----
  const prod = [], created = [], cancelled = [], cycles = [];
  for(const r of cr){
    const p = toISO(r['Ready For Production']) || toISO(r['Production']);
    const a = toISO(r['Assignment Date']);
    const c = toISO(r['Created Date']);
    const isCanc = txt(r['Status'])==='Cancelled';
    if(c){ created.push(c.slice(0,7)); if(isCanc) cancelled.push({m:c.slice(0,7), assigned:!!a}); }
    if(p){
      prod.push({m:p.slice(0,7), tc:txt(r['Technical Contact'])});
      if(a){ const d = daysBetween(a, new Date(p+'T00:00:00Z'));
        if(d>=0 && d<2000) cycles.push({d, m:p.slice(0,7)}); }
    }
  }
  const months = [...new Set([...created, ...prod.map(p=>p.m)])].sort();
  const win = months.slice(-12);
  const series = win.map(m=>({m,
    created: created.filter(x=>x===m).length,
    produced: prod.filter(x=>x.m===m).length,
    cancelled: cancelled.filter(x=>x.m===m).length}));

  // cycle time: average per month + the p90 tail the average hides
  const cycWin = cycles.filter(c=>win.includes(c.m));
  const cycTrend = win.map(m=>{ const v = cycles.filter(c=>c.m===m).map(c=>c.d);
    return {m, avg: mean(v), n: v.length}; }).filter(x=>x.n);
  const cycAll = cycWin.map(c=>c.d);

  // ---- aging of active work (survivorship-free view of the same question) ----
  const ages = active.map(r=>{ const a = toISO(r['Assignment Date']);
    return a ? {r, d: daysBetween(a, today)} : null; }).filter(Boolean);
  const ageVals = ages.map(x=>x.d);
  const aged90 = ages.filter(x=>x.d>90), aged180 = ages.filter(x=>x.d>180);
  const BUCKETS = [['0-30',0,30],['31-60',31,60],['61-90',61,90],['91-180',91,180],['180+',181,1e9]];
  const buckets = BUCKETS.map(([label,lo,hi])=>({label, n: ages.filter(x=>x.d>=lo&&x.d<=hi).length}));

  // ---- how long active work has sat in its CURRENT stage ----
  const inStage = STAGES.map(()=>[]);
  for(const r of active){
    const ds = STAGE_COLS.map(c=>toISO(r[c])).filter(Boolean).sort();
    const since = ds.length ? ds.at(-1) : null;
    if(since) inStage[stageIdx(txt(r['Stage']))].push(daysBetween(since, today));
  }
  const stageCounts = STAGES.map((_,i)=>active.filter(r=>stageIdx(txt(r['Stage']))===i).length);
  const stageAvg = inStage.map(v=>v.length?mean(v):null);

  // ---- action items: staleness, who holds them, who blocks us ----
  const aiRows = ai.map(r=>{
    const bot = /^system\s*admin$/i.test(txt(r['LastCommentOwner']));
    const eff = (bot?null:toISO(r['LastCommentDate'])) || toISO(r['StartDate']);
    return {r, on: txt(r['CurrentlyPendingOn']), carrier: txt(r['CarrierName']),
      d: eff? daysBetween(eff, aiToday) : null};
  });
  const stale90 = aiRows.filter(x=>x.d!=null && x.d>90);
  const ext = aiRows.filter(x=>EXTERNAL.test(x.on));
  const internal = aiRows.filter(x=>x.on && !EXTERNAL.test(x.on));
  const byCarrier = {};
  ext.forEach(x=>{ if(x.carrier) byCarrier[x.carrier] = (byCarrier[x.carrier]||0)+1; });
  const holders = {};
  internal.forEach(x=>{ holders[x.on] = (holders[x.on]||0)+1; });
  const holdRank = Object.entries(holders).sort((a,b)=>b[1]-a[1]);

  // ---- stalled testing: in Testing but no test file has ever been sent ----
  const inTesting = active.filter(r=>stageIdx(txt(r['Stage']))===STAGES.indexOf('Testing'));
  const stalledTest = inTesting.filter(r=>!toISO(r['First Test File']));

  // ---- active CRs with no action item at all (no progress trail) ----
  const aiCrIds = new Set(ai.map(r=>r['ConnectivityRequestID']).filter(v=>v!=null).map(String));
  const noAI = active.filter(r=>!aiCrIds.has(String(r['Request ID'])));

  // ---- migration programme split ----
  const mig = {};
  active.forEach(r=>{ const m = txt(r['Migration'])||'—'; mig[m] = (mig[m]||0)+1; });
  const migActive = active.filter(r=>{ const m = txt(r['Migration']).toLowerCase();
    return m && !['no','false','0','n','none','-'].includes(m); }).length;

  // ---- OEs ----
  const oeActive = oe.filter(r=>ACTIVE.has(txt(r['Status'])));
  const oePast = oeActive.filter(r=>{ const p = toISO(r['PlanYearStartDate']); return p && p < asOf; });

  // ---- workload per analyst: CRs + the action items pending on them ----
  const load = analysts.map(a=>({a,
    n: active.filter(r=>txt(r['Technical Contact'])===a).length,
    ai: internal.filter(x=>x.on===a).length})).sort((x,y)=>y.n-x.n);

  const thisMonth = win.at(-1), prevMonth = win.at(-2);
  const out2026 = win.slice(-6).map(m=>prod.filter(p=>p.m===m).length);
  const avgOut = out2026.length ? out2026.reduce((a,b)=>a+b,0)/out2026.length : 0;

  return {asOf, cr, active, unassigned, stalled, analysts, series, win, load, stageCounts, stageAvg,
    prod, ages, ageVals, aged90, aged180, buckets, stale90, ext, internal, byCarrier, holdRank,
    stalledTest, inTesting, noAI, mig, migActive, oeActive, oePast, thisMonth, prevMonth,
    cycMean: mean(cycAll), cycP90: quantile(cycAll, .9), cycTrend, avgOut,
    cancelled, aiTotal: ai.length};
}

// ---------- pipeline stage duration (production + in-progress, team-wide) ----------
// Average calendar time each connection spent in a stage: from the start of the
// stage to the start of the next recorded stage — or to today, when the
// connection is still sitting in that stage (no later stage recorded yet).
// Connections that reached Ready For Production / Production are grouped by the
// year of that production date; in-progress connections (active status, no
// production date) are counted in the current data year. Filterable by request
// type and migration; every stage from Pending Start onward is shown; intervals
// outside the chosen confidence band are dropped as outliers (analyst-page rule).
const AVG_FIRST_STAGE = 0;   // include every stage from Pending Start onward
const DUR_Z = {90:1.645, 95:1.96, 99:2.576};
let curDurYear = null, curDurState = 'All', curDurType = 'All', curDurMig = 'All', curDurConf = 99;
// split stage intervals into kept / outliers using the chosen confidence band
// (mean ± z·σ); 'off' keeps everything, samples under 3 are never trimmed
function splitDurOutliers(list){
  const z = DUR_Z[curDurConf];
  if(!z || list.length<3) return {kept:list, cut:[]};
  const m = list.reduce((a,x)=>a+x.d,0)/list.length;
  const sd = Math.sqrt(list.reduce((a,x)=>a+(x.d-m)*(x.d-m),0)/list.length);
  if(!sd) return {kept:list, cut:[]};
  const kept = [], cut = [];
  for(const x of list) (Math.abs(x.d-m)<=z*sd ? kept : cut).push(x);
  return {kept, cut};
}
function renderStageDur(){
  const RFP_I = STAGE_COLS.indexOf('Ready For Production');
  const dataYear = String(RAW.generated).slice(0,4);
  const today = new Date(RAW.generated+'T00:00:00Z');
  const rows = [];
  for(const r of (RAW.cr||[])){
    const sd = STAGE_COLS.map(col=>toISO(r[col]));
    sd[STAGE_COLS.indexOf('Testing')] = testingStart(r);
    const prodDate = sd[RFP_I] || sd[RFP_I+1];
    const active = ACTIVE.has(txt(r['Status']));
    if(!prodDate && !active) continue;   // only produced or in-progress connections
    rows.push({sd, produced: !!prodDate, year: prodDate ? prodDate.slice(0,4) : dataYear,
      type: txt(r['Request Type'])||'—', mig: txt(r['Migration'])||'—', id: r['Request ID'],
      customer: txt(r['Customer']), carrier: txt(r['Carrier'])});
  }
  // year dropdown — default to the data year when present, else the latest
  const years = [...new Set(rows.map(r=>r.year))].sort().reverse();
  if(!years.includes(curDurYear)) curDurYear = years.includes(dataYear) ? dataYear : (years[0]||dataYear);
  const ysel = $('#duryear');
  ysel.innerHTML = (years.length?years:[curDurYear]).map(y=>`<option${y===curDurYear?' selected':''}>${y}</option>`).join('');
  ysel.onchange = e => { curDurYear = e.target.value; renderStageDur(); };
  // in-progress / production dropdown — narrows the year's connections to one kind
  const inYear = rows.filter(r=>r.year===curDurYear);
  const ssel = $('#durstate');
  ssel.value = curDurState;
  ssel.onchange = e => { curDurState = e.target.value; renderStageDur(); };
  const inState = inYear.filter(r => curDurState==='All' ? true
    : curDurState==='prod' ? r.produced : !r.produced);
  // request-type dropdown — built from the request types present in that slice
  const types = [...new Set(inState.map(r=>r.type))].sort();
  if(curDurType!=='All' && !types.includes(curDurType)) curDurType = 'All';
  const tsel = $('#durtype');
  tsel.innerHTML = ['All',...types].map(tp=>
    `<option value="${esc(tp)}"${tp===curDurType?' selected':''}>${tp==='All'?'All types':esc(tp)}</option>`).join('');
  tsel.onchange = e => { curDurType = e.target.value; renderStageDur(); };
  // migration dropdown — built from the migration programmes present in that slice
  const migs = [...new Set(inState.map(r=>r.mig))].sort();
  if(curDurMig!=='All' && !migs.includes(curDurMig)) curDurMig = 'All';
  const msel = $('#durmig');
  msel.innerHTML = ['All',...migs].map(mg=>
    `<option value="${esc(mg)}"${mg===curDurMig?' selected':''}>${mg==='All'?'All Connections':esc(mg)}</option>`).join('');
  msel.onchange = e => { curDurMig = e.target.value; renderStageDur(); };
  // outlier-filter dropdown
  const csel = $('#durconf');
  csel.value = String(curDurConf);
  csel.onchange = e => { curDurConf = +e.target.value; renderStageDur(); };

  const sel = inState.filter(r=>(curDurType==='All' || r.type===curDurType)
    && (curDurMig==='All' || r.mig===curDurMig));
  const nProd = sel.filter(r=>r.produced).length, nProg = sel.length - nProd;
  $('#durcount').textContent = `${sel.length} connection${sel.length===1?'':'s'} in ${curDurYear}`
    + (curDurState==='All' && nProg ? ` (${nProd} produced · ${nProg} in progress)` : '')
    + (curDurType==='All' ? '' : ` · ${curDurType}`)
    + (curDurMig==='All' ? '' : ` · ${curDurMig}`);
  // interval per stage, kept as objects so removed outliers can be listed. The
  // end is the next recorded stage; if none and the connection is still in
  // progress, the stage is still running, so today is used as the end.
  const ints = STAGES.map(()=>[]);
  for(const r of sel){
    for(let i=AVG_FIRST_STAGE;i<STAGES.length;i++){
      const start = r.sd[i];
      if(!start) continue;
      let endISO = null;
      for(let j=i+1;j<r.sd.length;j++) if(r.sd[j]){ endISO = r.sd[j]; break; }
      let end, endLabel;
      if(endISO){ end = new Date(endISO+'T00:00:00Z'); endLabel = endISO; }
      else if(!r.produced){ end = today; endLabel = RAW.generated; }  // still in this stage
      else continue;   // produced connection's terminal stage has no duration
      const d = daysBetween(start, end);
      if(d>=0) ints[i].push({d, id: r.id, customer: r.customer, carrier: r.carrier, start, end: endLabel});
    }
  }
  // average of the kept intervals per stage, after trimming outliers
  const drows = [];
  for(let i=AVG_FIRST_STAGE;i<STAGES.length;i++){
    const {kept, cut} = splitDurOutliers(ints[i]);
    if(kept.length) drows.push([i, kept.reduce((a,x)=>a+x.d,0)/kept.length, kept, cut]);
  }
  const max = Math.max(...drows.map(r=>r[1]), 1);
  const slowest = drows.length ? drows.slice().sort((a,b)=>b[1]-a[1])[0] : null;
  // migration testing split (needs a loaded MigrationSummary): for migration
  // connections only, Internal = testing start -> migration testing date, Carrier
  // = migration testing date -> production. Shown as an expandable under Testing.
  const TEST_I = STAGES.indexOf('Testing');
  const msMap = {};
  for(const m of (RAW.ms||[])){
    if(m.ConnectivityRequestID!=null && m.MigrationTestingDate)
      msMap[m.ConnectivityRequestID] = toISO(m.MigrationTestingDate);
  }
  const internalRaw = [], carrierRaw = [];
  for(const r of sel){
    if(r.mig==='No' || r.mig==='—') continue;   // migration connections only
    const mtd = msMap[r.id];
    if(!mtd) continue;
    const tStart = r.sd[TEST_I];
    const prod = r.sd[TEST_I+1] || r.sd[TEST_I+2];   // ready-for-production, else production
    if(tStart){ const d = daysBetween(tStart, new Date(mtd+'T00:00:00Z'));
      if(d>=0) internalRaw.push({d, id:r.id, customer:r.customer, carrier:r.carrier, start:tStart, end:mtd}); }
    if(prod){ const d = daysBetween(mtd, new Date(prod+'T00:00:00Z'));
      if(d>=0) carrierRaw.push({d, id:r.id, customer:r.customer, carrier:r.carrier, start:mtd, end:prod}); }
  }
  const intSplit = splitDurOutliers(internalRaw), carSplit = splitDurOutliers(carrierRaw);
  const avgKept = k => k.length ? k.reduce((a,x)=>a+x.d,0)/k.length : null;
  const iAvg = avgKept(intSplit.kept), cAvg = avgKept(carSplit.kept);
  const hasSplit = !!(intSplit.kept.length || carSplit.kept.length);
  const msMax = Math.max(iAvg||0, cAvg||0, 1);
  const msBar = (key, label, sub, avg, sp, color) => `<div class="msrow">
      <span class="msname"><i style="background:${color}"></i><span class="mslbl">${label}<small>${sub}</small></span></span>
      <div class="mstrack"><div class="msbar" style="width:${Math.max(2,(avg||0)/msMax*100)}%;background:${color}"></div></div>
      <span class="msval">${avg!=null?(avg/7).toFixed(1)+' wk':'—'}</span>
      <span class="mscnt">${sp.kept.length} migration${sp.kept.length===1?'':'s'}${sp.cut.length?` · <a class="outbtn" data-i="${key}" title="show / hide the removed migrations">${sp.cut.length} outlier${sp.cut.length===1?'':'s'} removed</a>`:''}</span>
    </div>${sp.cut.length?`<div class="msouts" id="douts-${key}" style="display:none">
      ${sp.cut.map(x=>`<div><a class="lnk" href="${crUrl(x.id)}" target="_blank">#${x.id}</a> ${esc(x.customer)} — ${esc(x.carrier)} &middot; <span class="dt">${(x.d/7).toFixed(1)} wk (${x.start} &rarr; ${x.end})</span></div>`).join('')}
    </div>`:''}`;
  const msBlock = hasSplit ? `<div class="msplit" id="ms-split" style="display:none">
    ${msBar('msint','Internal testing','testing start &rarr; migration testing date', iAvg, intSplit, 'var(--s4)')}
    ${msBar('mscar','Carrier testing','migration testing date &rarr; production', cAvg, carSplit, 'var(--s6)')}
  </div>` : '';
  $('#stagedur').innerHTML = drows.length ? `<div class="stagebars">
    ${drows.map(([i,avg,kept,cut])=>`<div class="srow">
      <span class="sname"><i style="background:${STAGE_COLORS[i]}"></i>${STAGES[i]}</span>
      <div class="strack"><div class="sbar" style="width:${Math.max(2,avg/max*100)}%;background:${STAGE_COLORS[i]}"></div></div>
      <span class="sval">${(avg/7).toFixed(1)} wk</span>
      <span class="scnt">${kept.length} conn${kept.length>1?'s':''}${cut.length?` · <a class="outbtn" data-i="${i}" title="show / hide the removed connections">${cut.length} outlier${cut.length>1?'s':''} removed</a>`:''}${i===TEST_I&&hasSplit?` · <a class="msbtn" title="internal vs carrier testing for migrations">migration split</a>`:''}</span>
    </div>${cut.length?`<div class="souts" id="douts-${i}" style="display:none">
      ${cut.map(x=>`<div><a class="lnk" href="${crUrl(x.id)}" target="_blank">#${x.id}</a> ${esc(x.customer)} — ${esc(x.carrier)} &middot; <span class="dt">${(x.d/7).toFixed(1)} wk (${x.start} &rarr; ${x.end})</span></div>`).join('')}
    </div>`:''}${i===TEST_I?msBlock:''}`).join('')}
  </div><div class="hnote">Average time from the start of each stage to the start of the next recorded one —
    or to today for a stage a connection is still sitting in. Covers connections produced in ${curDurYear}${curDurYear===dataYear?' plus those currently in progress':''}${curDurType==='All'?'':` · ${esc(curDurType)}`}${curDurMig==='All'?'':` · ${esc(curDurMig)}`}.${hasSplit?' Migrations also carry an internal/carrier testing split under the Testing stage.':''}${slowest?` The longest stage is ${STAGES[slowest[0]]} at ${(slowest[1]/7).toFixed(1)} weeks.`:''}</div>`
    : `<div class="empty">No connections with measurable stages in ${curDurYear}${curDurType==='All'?'':' for this request type'}.</div>`;
  document.querySelectorAll('#stagedur .outbtn').forEach(b=>{
    b.onclick = () => { const el = document.getElementById('douts-'+b.dataset.i);
      if(el) el.style.display = el.style.display==='none' ? '' : 'none'; };
  });
  const mb = document.querySelector('#stagedur .msbtn');
  if(mb) mb.onclick = () => { const el = document.getElementById('ms-split');
    if(el) el.style.display = el.style.display==='none' ? '' : 'none'; };
}

// ---------- render ----------
function render(){
  const t = teamStats();
  $('#gen').innerHTML = dateChips();

  const nowProd = t.prod.filter(p=>p.m===t.thisMonth).length;
  const prevProd = t.prod.filter(p=>p.m===t.prevMonth).length;
  const delta = prevProd ? Math.round((nowProd-prevProd)/prevProd*100) : null;
  const loads = t.load.map(l=>l.n);
  const cancTotal = t.cr.filter(r=>txt(r['Status'])==='Cancelled').length;
  const cancRate = pct(cancTotal, t.cr.length);
  const cancRecent = t.cancelled.filter(c=>t.win.includes(c.m)).length;
  const createdWin = t.series.reduce((a,s)=>a+s.created,0);
  const clear = t.avgOut ? (t.active.length/t.avgOut).toFixed(1) : '—';

  $('#kpis').innerHTML = [
    [t.active.length,'Active connections', `${t.analysts.length} analysts · average ${mean(loads)} each`, ''],
    [nowProd,`Produced ${t.thisMonth||''}`, delta==null?'':`${delta>=0?'+':''}${delta}% vs ${t.prevMonth}`, ''],
    [t.cycMean+'d','Average cycle time', `p90 ${t.cycP90}d — the tail the average hides`, ''],
    [clear+' mo','To clear backlog', `at ~${Math.round(t.avgOut)}/month, no new intake`, ''],
    [t.unassigned.length,'Unassigned', 'active CRs with no analyst', t.unassigned.length?'warn':''],
    [t.aged90.length,'Aging > 90d', `${t.aged180.length} over 180d`, t.aged90.length?'bad':''],
    [cancRate+'%','Cancelled', `${cancRecent} of ${createdWin} recent CRs already cancelled`, cancRate>=40?'warn':''],
    [t.oeActive.length,'Active OEs', `${t.oePast.length} past plan-year start`, t.oePast.length?'warn':''],
  ].map(([v,l,d,cls])=>`<div class="kpi ${cls}"><b>${v}</b><span>${l}</span>${d?`<span class="kpi-sub">${d}</span>`:''}</div>`).join('');

  // --- intake vs output vs cancelled (grouped bars, one shared axis) ---
  const max = Math.max(1, ...t.series.flatMap(s=>[s.created,s.produced,s.cancelled]));
  $('#gbars').innerHTML = t.series.map(s=>`
    <div class="gcol">
      <div class="gpair">
        <div class="gbar in" style="height:${s.created/max*100}%" title="${s.m}: ${s.created} created"></div>
        <div class="gbar out" style="height:${s.produced/max*100}%" title="${s.m}: ${s.produced} produced"></div>
        <div class="gbar cx" style="height:${s.cancelled/max*100}%" title="${s.m}: ${s.cancelled} cancelled"></div>
      </div>
      <div class="glbl">${s.m.slice(2).replace('-','/')}</div>
    </div>`).join('');
  const tc = createdWin, tp = t.series.reduce((a,s)=>a+s.produced,0);
  $('#gnote').textContent = `Last ${t.series.length} months: ${tc} created vs ${tp} produced — `
    + (tc>tp ? `backlog grew by ${tc-tp}` : tc<tp ? `backlog shrank by ${tp-tc}` : 'backlog flat')
    + `. ${cancRecent} of those ${tc} have already been cancelled, so real demand is lower than intake suggests.`;

  // --- cycle time trend (single series: one colour for every bar) ---
  const cmax = Math.max(1, ...t.cycTrend.map(c=>c.avg));
  $('#cbars').innerHTML = t.cycTrend.map(c=>`
    <div class="gcol">
      <div class="gval">${c.avg}</div>
      <div class="gpair"><div class="gbar" style="width:60%;max-width:22px;background:var(--accent);height:${c.avg/cmax*100}%"
        title="${c.m}: average ${c.avg}d over ${c.n} CRs"></div></div>
      <div class="glbl">${c.m.slice(2).replace('-','/')}</div>
    </div>`).join('');
  // compare the last 3 months with the 3 before them — comparing first vs last
  // month would let a single outlier month hide the real direction
  const r3 = t.cycTrend.slice(-3), p3 = t.cycTrend.slice(-6,-3);
  const rAvg = mean(r3.map(c=>c.avg)), pAvg = mean(p3.map(c=>c.avg));
  $('#cnote').textContent = r3.length && p3.length && pAvg
    ? `Last 3 months average ${rAvg}d vs the 3 before ${pAvg}d — `
      + (rAvg>pAvg ? `slower by ${Math.round((rAvg-pAvg)/pAvg*100)}%`
      : rAvg<pAvg ? `faster by ${Math.round((pAvg-rAvg)/pAvg*100)}%` : 'flat')
      + `. Measured only on CRs that finished — work still stuck is not in this number.`
    : '';

  // --- pipeline: count + how long they have sat in that stage ---
  const pmax = Math.max(1, ...t.stageCounts);
  const prows = STAGES.map((s,i)=>[s,i,t.stageCounts[i]]).filter(([,,n])=>n);
  $('#pipeline').innerHTML = prows.length ? `<div class="hrows">
    ${prows.map(([s,i,n])=>`<div class="hrow">
      <span class="hname"><i style="background:${STAGE_COLORS[i]}"></i>${s}</span>
      <div class="htrack"><div class="hbar" style="width:${Math.max(2,n/pmax*100)}%;background:${STAGE_COLORS[i]}"
        title="${n} active connections in ${s}"></div></div>
      <span class="hval">${n} <small style="color:var(--ink-soft);font-weight:400">${pct(n,t.active.length)}%</small></span>
      <span class="hsub">${t.stageAvg[i]!=null?`${t.stageAvg[i]}d in stage`:'—'}</span>
    </div>`).join('')}
  </div><div class="hnote">"In stage" = average days since the CR last moved. The biggest pile-up is
    ${prows.sort((a,b)=>b[2]-a[2])[0][0]} with ${prows[0][2]} CRs.</div>` : '<div class="empty">No active connections.</div>';

  // --- pipeline stage duration over production connections (year + type filtered) ---
  renderStageDur();

  // --- aging distribution (one series; the bad tail is emphasised) ---
  const bmax = Math.max(1, ...t.buckets.map(b=>b.n));
  const bcol = l => l==='180+' ? 'var(--red)' : l==='91-180' ? 'var(--amber)' : 'var(--bar)';
  $('#aging').innerHTML = `<div class="hrows w3">
    ${t.buckets.map(b=>`<div class="hrow">
      <span class="hname">${b.label} days</span>
      <div class="htrack"><div class="hbar" style="width:${Math.max(2,b.n/bmax*100)}%;background:${bcol(b.label)}"
        title="${b.n} active CRs aged ${b.label} days"></div></div>
      <span class="hval">${b.n}</span>
    </div>`).join('')}
  </div><div class="hnote">Average active CR is ${mean(t.ageVals)}d old · p90 ${quantile(t.ageVals,.9)}d · oldest
    ${Math.max(0,...t.ageVals)}d. Compare with the ${t.cycMean}d average cycle time — the gap is work that has not finished.</div>`;

  // --- workload: CR load + action items held ---
  const avg = mean(loads), lmax = Math.max(1, ...loads);
  const over = t.load.filter(l=>l.n>avg*1.5);
  $('#workload').innerHTML = t.load.length ? `<div class="hrows">
    ${t.load.map(l=>`<div class="hrow">
      <span class="hname">${esc(l.a)}</span>
      <div class="htrack"><div class="hbar" style="width:${Math.max(2,l.n/lmax*100)}%${l.n>avg*1.5?';background:var(--amber)':''}"
        title="${esc(l.a)}: ${l.n} active CRs"></div></div>
      <span class="hval">${l.n}</span>
      <span class="hsub">${l.ai?`${l.ai} AIs`:'—'}</span>
    </div>`).join('')}
  </div><div class="hnote">Average ${avg} CRs per analyst · amber marks anyone over 1.5× the average
    (${over.length}). "AIs" = open action items pending on them — a CR count alone understates real load.</div>`
    : '<div class="empty">No analysts with active connections.</div>';

  // --- needs attention ---
  const now = new Date(t.asOf+'T00:00:00Z');
  const ageOf = r => { const a = toISO(r['Assignment Date']); return a?daysBetween(a,now):0; };
  const crLine = x => `<div><a class="lnk" href="${crUrl(x.r['Request ID'])}" target="_blank">#${x.r['Request ID']}</a>
    ${esc(txt(x.r['Customer']))} — ${esc(txt(x.r['Carrier']))} <span class="dt">${x.d}d</span>
    ${txt(x.r['Technical Contact'])?`· ${esc(txt(x.r['Technical Contact']))}`:'· <i>unassigned</i>'}</div>`;
  const topCarriers = Object.entries(t.byCarrier).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const keyShare = t.holdRank.length ? pct(t.holdRank[0][1], t.internal.length) : 0;
  const migList = Object.entries(t.mig).sort((a,b)=>b[1]-a[1]);

  $('#risks').innerHTML = [
    ['Unassigned active CRs', t.unassigned.length, t.unassigned.length?'warn':'',
      t.unassigned.map(r=>({r,d:ageOf(r)})).sort((a,b)=>b.d-a.d).map(crLine).join('')],
    ['Active CRs aging over 90 days', t.aged90.length, t.aged90.length?'bad':'',
      t.aged90.slice().sort((a,b)=>b.d-a.d).map(crLine).join('')],
    ['In Testing with no test file sent', t.stalledTest.length, t.stalledTest.length?'bad':'',
      `<div><i>${pct(t.stalledTest.length, t.inTesting.length)}% of the ${t.inTesting.length} CRs in Testing — they look
        like progress but nothing has been sent.</i></div>`
      + t.stalledTest.map(r=>({r,d:ageOf(r)})).sort((a,b)=>b.d-a.d).map(crLine).join('')],
    ['Blocked / on hold', t.stalled.length, t.stalled.length?'warn':'',
      t.stalled.map(r=>({r,d:ageOf(r)})).sort((a,b)=>b.d-a.d).map(crLine).join('')],
    ['Action items untouched over 90 days', t.stale90.length, t.stale90.length?'bad':'',
      t.stale90.slice().sort((a,b)=>b.d-a.d).slice(0,200).map(x=>`<div>${esc(txt(x.r['ActionItemTitle'])||('AI #'+x.r['ActionItemID']))}
        — ${esc(txt(x.r['ClientName']))} <span class="dt">${x.d}d</span> · on ${esc(x.on||'—')}</div>`).join('')],
    ['OEs past their plan-year start', t.oePast.length, t.oePast.length?'bad':'',
      t.oePast.map(r=>`<div>${esc(txt(r['ClientName']))} — ${esc(txt(r['CarrierName']))}
        <span class="dt">${toISO(r['PlanYearStartDate'])}</span> · ${esc(txt(r['Stage']))}</div>`).join('')],
    ['Action items waiting on carriers', t.ext.length, t.ext.length?'warn':'',
      `<div><i>${pct(t.ext.length, t.aiTotal)}% of all open action items are outside the team's control.
        Top carriers to escalate with:</i></div>`
      + topCarriers.map(([k,v])=>`<div>${esc(k)} <span class="dt">${v}</span></div>`).join('')],
    ['Open AIs held by one person', t.holdRank.length?t.holdRank[0][1]:0, keyShare>=25?'bad':'warn',
      `<div><i>${esc(t.holdRank.length?t.holdRank[0][0]:'—')} holds ${keyShare}% of the ${t.internal.length}
        action items pending on the team — key-person risk.</i></div>`
      + t.holdRank.slice(0,10).map(([k,v])=>`<div>${esc(k)} <span class="dt">${v}</span></div>`).join('')],
    ['Active CRs with no action item', t.noAI.length, '',
      `<div><i>No open action item is attached, so there is no progress trail on these.</i></div>`
      + t.noAI.map(r=>({r,d:ageOf(r)})).sort((a,b)=>b.d-a.d).slice(0,200).map(crLine).join('')],
    ['Active migration CRs', t.migActive, '',
      migList.map(([k,v])=>`<div>${esc(k)} <span class="dt">${v}</span></div>`).join('')],
  ].map(([label,n,cls,list],i)=>`<div class="risk ${cls}">
      <b>${n}</b><span>${label}</span>
      ${list?`<div class="drill" data-r="${i}">show / hide</div><div class="rlist" id="rlist-${i}">${list}</div>`:''}
    </div>`).join('');
  document.querySelectorAll('.risk .drill').forEach(d=>{
    d.onclick = () => { const el = document.getElementById('rlist-'+d.dataset.r);
      if(el) el.style.display = el.style.display==='block' ? 'none' : 'block'; };
  });
}

function dateChips(){
  const d = RAW.dates || {};
  const items = [['CR',d.cr],['AI',d.ai],['OE',d.oe]].filter(x=>x[1]);
  if(!items.length) return esc(RAW.generated || '');
  const nowMid = new Date(localDay(new Date())+'T00:00:00Z');
  return items.map(([k,v])=>{
    const age = workDaysBetween(v, nowMid);
    return `<span class="dchip ${idleCls(age)}" title="${age} working day${age===1?'':'s'} old">${k} <b>${v}</b></span>`;
  }).join('');
}

// ---------- cache (shared with the analyst / iSolved pages) ----------
const DB_KEY = 'analystDash';
const idb = () => new Promise((res,rej)=>{
  const rq = indexedDB.open('analystDashDB',1);
  rq.onupgradeneeded = () => rq.result.createObjectStore('kv');
  rq.onsuccess = () => res(rq.result); rq.onerror = () => rej(rq.error);
});
const dbGet = key => idb().then(db => new Promise((res,rej)=>{
  const rq = db.transaction('kv').objectStore('kv').get(key);
  rq.onsuccess = () => res(rq.result); rq.onerror = () => rej(rq.error);
}));
const dbSet = (key,val) => idb().then(db => new Promise((res,rej)=>{
  const tx = db.transaction('kv','readwrite'); tx.objectStore('kv').put(val,key);
  tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error);
}));
async function restoreSaved(){
  let saved = null;
  try{ const s = await dbGet(DB_KEY); if(s) saved = JSON.parse(s); }catch(e){}
  // use the saved upload when it is newer than the embedded data, or whenever the
  // file ships empty (an emptied file) so the browser copy is the source of truth
  if(saved && (!RAW.cr.length || saved.generated > RAW.generated)){
    RAW.cr = saved.cr; RAW.ai = saved.ai; RAW.generated = saved.generated;
    if(saved.oe && saved.oe.length) RAW.oe = saved.oe;
    if(saved.ms && saved.ms.length) RAW.ms = saved.ms;
    if(saved.dates) RAW.dates = saved.dates;
  }
}

// ---------- theme ----------
function applyTheme(t){
  document.documentElement.dataset.theme = t;
  $('#themebtn').textContent = t==='dark' ? '☀️' : '🌙';
  try{ localStorage.setItem('dashTheme', t); }catch(e){}
}
let savedTheme = null;
try{ savedTheme = localStorage.getItem('dashTheme'); }catch(e){}
applyTheme(savedTheme==='dark' || savedTheme==='light' ? savedTheme
  : (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
$('#themebtn').onclick = () =>
  applyTheme(document.documentElement.dataset.theme==='dark' ? 'light' : 'dark');

// ---------- upload ----------
function fileDate(f){
  const m = String(f.name).match(/(20\d\d)[-_](\d\d)[-_](\d\d)/);
  if(m) return `${m[1]}-${m[2]}-${m[3]}`;
  if(f.lastModified) return localDay(new Date(f.lastModified));
  return localDay(new Date());
}
$('#files').onchange = async e => {
  const msg = $('#upmsg');
  try{
    if(typeof XLSX==='undefined') throw new Error('Excel parser unavailable — check internet connection.');
    const files = [...e.target.files];
    if(!files.length) return;
    msg.className=''; msg.textContent='Reading…';
    let newCr=null, newAi=null, newOe=null, newMs=null, names=[];
    let crDate=null, aiDate=null, oeDate=null;
    for(const f of files){
      const wb = XLSX.read(await f.arrayBuffer());
      const rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], {defval:null});
      const cols = new Set(Object.keys(rows[0]||{}));
      const tags = [];
      if(cols.has('ActionItemID')||cols.has('CurrentlyPendingOn')){ newAi=rows; aiDate=fileDate(f); tags.push('AI'); }
      else if(cols.has('OERequestID')){ newOe=rows.filter(r=>ACTIVE.has(txt(r['Status']))); oeDate=fileDate(f); tags.push('OE'); }
      else if(cols.has('Request ID')){ newCr=rows; crDate=fileDate(f); tags.push('CR'); }
      // MigrationSummary — any sheet in the workbook carrying MigrationTestingDate
      const mss = wb.SheetNames.find(n=>((XLSX.utils.sheet_to_json(wb.Sheets[n],{header:1})[0])||[]).includes('MigrationTestingDate'));
      if(mss){ newMs = XLSX.utils.sheet_to_json(wb.Sheets[mss], {defval:null}); tags.push('MigrationSummary'); }
      names.push(f.name + (tags.length ? ` (${tags.join(', ')})` : ' (unrecognized — skipped)'));
    }
    if(!newCr && !newAi && !newOe && !newMs) throw new Error('No file matched the CR, AI, OE or MigrationSummary report format.');
    if(newCr){ RAW.cr = newCr; RAW.dates.cr = crDate; }
    if(newAi){ RAW.ai = newAi; RAW.dates.ai = aiDate; }
    if(newOe){ RAW.oe = newOe; RAW.dates.oe = oeDate; }
    if(newMs){ RAW.ms = newMs; }
    RAW.generated = [RAW.dates.cr, RAW.dates.ai, RAW.dates.oe].filter(Boolean).sort().at(-1) || localDay(new Date());
    let saveWarn = '';
    try{ await dbSet(DB_KEY, JSON.stringify(RAW)); }
    catch(e){ saveWarn = ` — warning: couldn't save for next visit (${e && e.message || e})`; }
    render();
    msg.className='ok';
    msg.textContent = `Updated: ${names.join(', ')}` + saveWarn;
  }catch(err){ msg.className='err'; msg.textContent='Update failed: '+err.message; }
  e.target.value='';
};

restoreSaved().catch(()=>{}).then(()=>{
  render();
  if(!RAW.cr.length){
    const m = $('#upmsg'); m.className = 'ok';
    m.textContent = 'No data loaded yet — use "Update data" above to upload the CR, AI and OE reports.';
  }
});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()

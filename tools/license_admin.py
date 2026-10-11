#!/usr/bin/env python3
"""מרכז-הרישוי של DJ Dvir — ממשק ניהול נפרד לגמרי מהאפליקציה (port 8099).

כאן נדב: מקים לקוחות, מנפיק מפתחות חתומים (tier/תוקף/נעילת-מחשב), רואה הכול במקום אחד,
מבטל (revoke) ומנפיק מחדש. אין פה סליקה — רק מנגנון הרישוי עצמו.
המפתח הפרטי יושב רק כאן (license_admin/private.pem, מחוץ לגיט); האפליקציה מאמתת עם הציבורי בלבד.

הרצה:  .venv/bin/python tools/license_admin.py   →  http://127.0.0.1:8099
"""
import hmac
import json
import os
import secrets
import sys
import time
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import licensing

ADMIN = ROOT / "license_admin"
CUSTOMERS = ADMIN / "customers.json"
PRIV = ADMIN / "private.pem"
ADMIN_TOKEN_FILE = ADMIN / "admin_token.txt"
BIND = os.environ.get("RK_HUB_BIND", "127.0.0.1")   # 0.0.0.0 to host in the cloud — then admin auth is MANDATORY


def _admin_token() -> str:
    """the secret that guards every management endpoint. Env var wins (stable across cloud redeploys where
    the filesystem is ephemeral), then a local file, then a generated one shown in the console."""
    t = os.environ.get("RK_ADMIN_TOKEN", "").strip()
    if t:
        return t
    try:
        t = ADMIN_TOKEN_FILE.read_text().strip()
        if t:
            return t
    except Exception:
        pass
    t = secrets.token_urlsafe(24)
    try:
        ADMIN.mkdir(exist_ok=True); ADMIN_TOKEN_FILE.write_text(t)
    except Exception:
        pass
    return t


ADMIN_TOKEN = _admin_token()


def require_admin(request: Request, x_admin_token: str = Header(default=""),
                  token: str = "") -> None:
    """admin endpoints need the token — via header (API) or ?token= (the page passes it). Loopback with no
    explicit remote binding is trusted for convenience; a cloud-bound hub always requires the token."""
    supplied = x_admin_token or token or request.cookies.get("rk_admin", "")
    if hmac.compare_digest(supplied, ADMIN_TOKEN):
        return
    client = request.client.host if request.client else ""
    if BIND in ("127.0.0.1", "localhost") and client in ("127.0.0.1", "::1"):
        return                                       # local-only hub, local caller → no token needed
    raise HTTPException(401, "נדרש admin token")


app = FastAPI(title="DJ Dvir — מרכז רישוי")


def _db() -> dict:
    try:
        return json.loads(CUSTOMERS.read_text())
    except Exception:
        return {"customers": {}}


def _save(db: dict) -> None:
    ADMIN.mkdir(exist_ok=True)
    tmp = CUSTOMERS.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, ensure_ascii=False, indent=1))
    tmp.replace(CUSTOMERS)


class CustomerIn(BaseModel):
    name: str
    email: str = ""
    tier: str = "pro"
    months: int = 12          # 0 = perpetual
    machine: str = ""         # optional machine-id lock
    note: str = ""
    # per-license limits — carried INSIDE the signed key (tamper-proof) and enforced later by the cloud
    # activation function. All default to 0 = UNLIMITED/OPEN for now (nothing is blocked); set >0 to cap.
    max_machines: int = 0     # how many distinct machines may activate this license (0 = unlimited)
    max_ip: int = 0           # how many IPs may use this user concurrently (0 = unlimited; future)
    cost_per_machine: float = 0  # price per extra machine beyond the cap (admin bookkeeping; not charged here)


@app.get("/api/customers", dependencies=[Depends(require_admin)])
def api_customers():
    db = _db()
    return {"customers": sorted(db["customers"].values(), key=lambda c: c.get("created", ""), reverse=True),
            "tiers": {k: v["name"] for k, v in licensing.TIERS.items()}}


@app.post("/api/customers", dependencies=[Depends(require_admin)])
def api_create(body: CustomerIn):
    if body.tier not in licensing.TIERS:
        raise HTTPException(400, "tier לא מוכר")
    if not body.name.strip():
        raise HTTPException(400, "חסר שם לקוח")
    db = _db()
    cid = uuid.uuid4().hex[:10]
    import datetime
    expires = None if body.months <= 0 else (datetime.date.today() + datetime.timedelta(days=31 * body.months)).isoformat()
    limits = {"max_machines": max(0, int(body.max_machines)), "max_ip": max(0, int(body.max_ip)),
              "cost_per_machine": max(0.0, float(body.cost_per_machine))}
    payload = {"v": 1, "cid": cid, "customer": body.name.strip(), "email": body.email.strip(),
               "tier": body.tier, "features": licensing.TIERS[body.tier]["features"],
               "issued": datetime.date.today().isoformat(), "expires": expires,
               "machine": body.machine.strip(), "note": body.note.strip(), "limits": limits}
    key = licensing.sign_license(payload, PRIV.read_bytes())
    db["customers"][cid] = {"cid": cid, "name": payload["customer"], "email": payload["email"],
                            "tier": body.tier, "expires": expires, "machine": payload["machine"],
                            "note": payload["note"], "key": key, "revoked": False, "limits": limits,
                            "created": datetime.datetime.now().isoformat(timespec="seconds")}
    _save(db)
    return db["customers"][cid]


def _set_install_block(match_machine: str, match_customer: str, block: bool) -> int:
    """Close the loop between the two systems: a revoked customer's live install is actually STOPPED
    (the app's gate honors the hub's `block` directive). Matches by machine-id, falling back to name."""
    try:
        db = _inst()
    except Exception:
        return 0
    n = 0
    for it in db.get("installs", {}).values():
        hit = (match_machine and it.get("machine") == match_machine) or \
              (not match_machine and match_customer and it.get("customer") == match_customer)
        if hit:
            it["block"] = block
            n += 1
    if n:
        INSTALLS.parent.mkdir(exist_ok=True)
        tmp = INSTALLS.with_suffix(".tmp"); tmp.write_text(json.dumps(db, ensure_ascii=False, indent=1)); tmp.replace(INSTALLS)
    return n


@app.post("/api/customers/{cid}/revoke", dependencies=[Depends(require_admin)])
def api_revoke(cid: str):
    db = _db()
    c = db["customers"].get(cid)
    if not c:
        raise HTTPException(404)
    c["revoked"] = not c["revoked"]
    _save(db)
    # propagate to live installs so revoke/restore actually stops/resumes the app at its access gate
    blocked = _set_install_block(c.get("machine", ""), c.get("name", ""), c["revoked"])
    c = {**c, "installs_affected": blocked}
    return c


class UpgradeIn(BaseModel):
    tier: str = ""        # empty = keep current tier (used by "extend")
    months: int = 12      # new validity window from today (0 = perpetual)


@app.post("/api/customers/{cid}/upgrade", dependencies=[Depends(require_admin)])
def api_upgrade(cid: str, body: UpgradeIn):
    """Upgrade a trial (or any customer) to a paid tier, or just extend validity — re-signs a fresh key
    keeping the same identity/machine-lock. (A signed key is immutable, so changing tier/expiry ⇒ new key.)"""
    db = _db()
    c = db["customers"].get(cid)
    if not c:
        raise HTTPException(404)
    tier = (body.tier or c["tier"]).strip()           # empty tier = "extend": keep current tier (incl. trial)
    if body.tier.strip() == "trial":
        tier = "pro"                                  # never re-mint a trial from the explicit upgrade path
    reissue = CustomerIn(name=c["name"], email=c.get("email", ""), tier=tier,
                         months=body.months, machine=c.get("machine", ""), note=c.get("note", ""))
    out = api_reissue(cid, reissue)                   # new cid + key, old record replaced
    # a formerly-revoked/blocked machine becomes active again on upgrade
    _set_install_block(out.get("machine", ""), out.get("name", ""), False)
    return out


@app.get("/api/overview", dependencies=[Depends(require_admin)])
def api_overview():
    """control-center summary across BOTH systems (licenses + live installs)."""
    import datetime
    today = datetime.date.today()
    cust = list(_db().get("customers", {}).values())
    trials_active = trials_soon = expired = paid = revoked = 0
    for c in cust:
        if c.get("revoked"):
            revoked += 1
        exp = c.get("expires")
        d = None
        if exp:
            try:
                d = (datetime.date.fromisoformat(exp) - today).days
            except Exception:
                d = None
        is_trial = c.get("tier") == "trial"
        if is_trial and not c.get("revoked"):
            if d is not None and d < 0:
                expired += 1
            else:
                trials_active += 1
                if d is not None and d <= 14:
                    trials_soon += 1
        elif c.get("tier") in ("pro", "studio") and not c.get("revoked"):
            paid += 1
    inst = list(_inst().get("installs", {}).values())
    now = time.strftime("%Y-%m-%d %H:%M")
    online = 0
    for i in inst:
        ls = i.get("last_seen", "")
        try:
            if ls and (datetime.datetime.now() - datetime.datetime.strptime(ls, "%Y-%m-%d %H:%M")).total_seconds() < 86400:
                online += 1
        except Exception:
            pass
    blocked = sum(1 for i in inst if i.get("block"))
    return {"customers": len(cust), "trials_active": trials_active, "trials_soon": trials_soon,
            "expired": expired, "paid": paid, "revoked": revoked,
            "installs": len(inst), "online": online, "blocked": blocked, "now": now}


@app.post("/api/customers/{cid}/reissue", dependencies=[Depends(require_admin)])
def api_reissue(cid: str, body: CustomerIn):
    db = _db()
    if cid not in db["customers"]:
        raise HTTPException(404)
    created = db["customers"][cid]["created"]
    out = api_create(body)                       # new key under a NEW cid…
    new = db = _db()
    new["customers"][out["cid"]]["created"] = created
    del new["customers"][cid]                    # …replacing the old record
    _save(new)
    return new["customers"][out["cid"]]


# ================================================================ self-service registration (trial)
# PUBLIC endpoint: anyone who downloads the app registers here and instantly gets a TRIAL license
# (full features, time-limited). This is the "extra auth layer that opens the system" — without a key
# from here (or a paid key), the app stays locked at its activation screen. Anti-abuse: one trial per
# machine-id (re-registering returns the SAME key, never a fresh clock), light per-IP rate limit, and
# the key is machine-locked so it can't be shared. The owner still sees/▸controls every trial in the list.
TRIAL_MONTHS = int(os.environ.get("RK_TRIAL_MONTHS", "3"))
_reg_hits: dict = {}            # ip -> [timestamps]  (in-memory sliding-window rate limit)


class RegisterIn(BaseModel):
    name: str
    email: str = ""
    machine: str = ""           # the app sends its machine-id so the trial is bound to this device
    platform: str = ""


def _rate_ok(ip: str, limit: int = 8, window: int = 3600) -> bool:
    now = time.time()
    hits = [t for t in _reg_hits.get(ip, []) if now - t < window]
    hits.append(now)
    _reg_hits[ip] = hits
    return len(hits) <= limit


@app.post("/api/register")
def api_register(body: RegisterIn, request: Request):
    import datetime, re
    ip = request.client.host if request.client else "?"
    if not _rate_ok(ip):
        raise HTTPException(429, "יותר מדי בקשות — נסו שוב בעוד שעה")
    name = (body.name or "").strip()
    email = (body.email or "").strip()
    machine = (body.machine or "").strip()
    if len(name) < 2:
        raise HTTPException(400, "חסר שם")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise HTTPException(400, "כתובת אימייל לא תקינה")

    db = _db()
    idx = db.setdefault("trial_index", {})          # machine-id (or email) -> cid, so a retry is idempotent
    anchor = machine or ("email:" + email.lower())
    existing_cid = idx.get(anchor)
    if existing_cid and existing_cid in db["customers"]:
        c = db["customers"][existing_cid]            # already registered on this device → return the SAME key
        exp = c.get("expires")
        expired = bool(exp and datetime.date.fromisoformat(exp) < datetime.date.today())
        return {"key": c["key"], "tier": c["tier"], "expires": exp, "customer": c["name"],
                "returning": True, "expired": expired, "months": TRIAL_MONTHS}

    cid = uuid.uuid4().hex[:10]
    expires = (datetime.date.today() + datetime.timedelta(days=31 * TRIAL_MONTHS)).isoformat()
    payload = {"v": 1, "cid": cid, "customer": name, "email": email,
               "tier": "trial", "features": licensing.TIERS["trial"]["features"],
               "issued": datetime.date.today().isoformat(), "expires": expires,
               "machine": machine, "note": "הרשמה-עצמית"}
    key = licensing.sign_license(payload, PRIV.read_bytes())
    db["customers"][cid] = {"cid": cid, "name": name, "email": email, "tier": "trial",
                            "expires": expires, "machine": machine, "note": "הרשמה-עצמית",
                            "key": key, "revoked": False, "trial": True, "source": "self-register",
                            "platform": body.platform, "ip": ip,
                            "created": datetime.datetime.now().isoformat(timespec="seconds")}
    idx[anchor] = cid
    _save(db)
    return {"key": key, "tier": "trial", "expires": expires, "customer": name,
            "returning": False, "expired": False, "months": TRIAL_MONTHS}


INSTALLS = ADMIN / "installs.json"


def _inst() -> dict:
    try:
        return json.loads(INSTALLS.read_text())
    except Exception:
        return {"installs": {}}


class CheckinIn(BaseModel):
    install_id: str
    machine: str = ""
    tier: str = ""
    customer: str = ""
    ok: bool = False
    ver: str = ""
    platform: str = ""
    event: str = ""     # e.g. "launch", "server_start_failed" — reported by the Electron launcher itself
    error: str = ""     # a short error message / log tail when something failed, so failures are visible remotely


@app.post("/api/checkin")
def api_checkin(body: CheckinIn, request: Request):
    """חיווי מהאפליקציות: כל התקנה שמדווחת נרשמת כאן — וקיבלת עליה שליטה (חסימה/הודעה)."""
    db = _inst()
    it = db["installs"].get(body.install_id) or {"install_id": body.install_id,
                                                 "first_seen": time.strftime("%Y-%m-%d %H:%M"), "count": 0, "block": False, "message": "", "ips": []}
    ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
          or (request.client.host if request.client else ""))   # real IP even behind a proxy/CDN
    ips = it.get("ips", [])
    if ip and ip not in ips:
        ips.append(ip); ips = ips[-10:]                           # keep the last 10 distinct IPs per install
    it.update({"machine": body.machine, "tier": body.tier or "free", "customer": body.customer,
               "licensed": bool(body.ok), "ver": body.ver, "platform": body.platform, "ip": ip, "ips": ips,
               "last_seen": time.strftime("%Y-%m-%d %H:%M"), "count": it.get("count", 0) + 1})
    if body.event:
        it["last_event"] = body.event; it["last_event_at"] = time.strftime("%Y-%m-%d %H:%M")
    if body.error:                                        # a failure report → keep the last few, flag the install
        it["last_error"] = body.error[:500]; it["last_error_at"] = time.strftime("%Y-%m-%d %H:%M"); it["healthy"] = False
        errs = it.get("errors", []); errs.append({"at": time.strftime("%Y-%m-%d %H:%M"), "event": body.event, "msg": body.error[:500]})
        it["errors"] = errs[-10:]
    elif body.event == "launch":                          # a clean launch clears the unhealthy flag
        it["healthy"] = True
    db["installs"][body.install_id] = it
    ADMIN.mkdir(exist_ok=True)
    tmp = INSTALLS.with_suffix(".tmp"); tmp.write_text(json.dumps(db, ensure_ascii=False, indent=1)); tmp.replace(INSTALLS)
    return {"block": bool(it.get("block")), "message": it.get("message") or "", "enforce": bool(it.get("enforce"))}


@app.get("/api/installs", dependencies=[Depends(require_admin)])
def api_installs():
    db = _inst()
    return {"installs": sorted(db["installs"].values(), key=lambda i: i.get("last_seen", ""), reverse=True)}


@app.get("/api/customers/{cid}/activations", dependencies=[Depends(require_admin)])
def api_activations(cid: str):
    """How many machines/IPs are live on this license, vs its configured caps. REPORTING ONLY — nothing is
    blocked yet (limits are 0=open by default). This is the data the cloud activation function will enforce later."""
    c = _db().get("customers", {}).get(cid)
    if not c:
        raise HTTPException(404, "לא נמצא")
    mach, name = c.get("machine", ""), c.get("name", "")
    hits = [it for it in _inst().get("installs", {}).values()
            if (mach and it.get("machine") == mach) or (not mach and name and it.get("customer") == name)]
    machines = sorted({it.get("machine", "") for it in hits if it.get("machine")})
    ips = sorted({ip for it in hits for ip in (it.get("ips") or ([it["ip"]] if it.get("ip") else []))})
    lim = c.get("limits") or {}
    cap_m, cap_ip = int(lim.get("max_machines", 0)), int(lim.get("max_ip", 0))
    return {"cid": cid, "name": name, "limits": lim,
            "machines": machines, "machines_used": len(machines),
            "ips": ips, "ips_used": len(ips),
            "machines_over": bool(cap_m and len(machines) > cap_m),
            "ips_over": bool(cap_ip and len(ips) > cap_ip),
            "enforced": False}   # OPEN for now — reporting only


class InstCtl(BaseModel):
    block: bool | None = None
    message: str | None = None
    enforce: bool | None = None


@app.post("/api/installs/{iid}/ctl", dependencies=[Depends(require_admin)])
def api_install_ctl(iid: str, body: InstCtl):
    db = _inst()
    it = db["installs"].get(iid)
    if not it:
        raise HTTPException(404)
    if body.block is not None:
        it["block"] = body.block
    if body.message is not None:
        it["message"] = body.message
    if body.enforce is not None:
        it["enforce"] = body.enforce
    tmp = INSTALLS.with_suffix(".tmp"); tmp.write_text(json.dumps(db, ensure_ascii=False, indent=1)); tmp.replace(INSTALLS)
    return it


# ================================================================ download links (per-OS) — "connected" site
# The public download site reads /api/download to show the current Mac/Windows installer links + version; the
# owner manages them here. One source of truth: update the link once, the site updates everywhere.
DOWNLOADS = ADMIN / "downloads.json"
_DL_DEFAULT = {"mac": {"url": "", "version": "2.2.0"}, "win": {"url": "", "version": "2.2.0"}, "notes": ""}


def _downloads() -> dict:
    try:
        d = json.loads(DOWNLOADS.read_text())
        return {**_DL_DEFAULT, **d}
    except Exception:
        return dict(_DL_DEFAULT)


@app.get("/api/download")
def api_download():
    """PUBLIC — the download site reads this (CORS-open) to show the live links + version per OS."""
    d = _downloads()
    return JSONResponse(d, headers={"Access-Control-Allow-Origin": "*", "Cache-Control": "no-store"})


class DownloadIn(BaseModel):
    mac_url: str = ""
    mac_version: str = ""
    win_url: str = ""
    win_version: str = ""
    notes: str = ""


@app.post("/api/admin/download", dependencies=[Depends(require_admin)])
def api_download_set(body: DownloadIn):
    d = _downloads()
    if body.mac_url or body.mac_version:
        d["mac"] = {"url": body.mac_url.strip() or d["mac"]["url"], "version": body.mac_version.strip() or d["mac"]["version"]}
    if body.win_url or body.win_version:
        d["win"] = {"url": body.win_url.strip() or d["win"]["url"], "version": body.win_version.strip() or d["win"]["version"]}
    d["notes"] = body.notes.strip()
    ADMIN.mkdir(exist_ok=True)
    tmp = DOWNLOADS.with_suffix(".tmp"); tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1)); tmp.replace(DOWNLOADS)
    return d


# ================================================================ community catalog (Phase B)
# The hub is "our infrastructure" from the vision doc: accounts, licenses, permissions, links between works,
# CATALOG RECORDS. Media itself stays where the creator published it (YouTube) — we keep the card:
# id, link, details, permissions. Upsert by catalog_id = <install_id>:<take_id> → a retry never duplicates.
CATALOG = ADMIN / "catalog.json"


def _cat() -> dict:
    try:
        return json.loads(CATALOG.read_text())
    except Exception:
        return {"items": {}}


def _cat_save(db: dict) -> None:
    ADMIN.mkdir(exist_ok=True)
    tmp = CATALOG.with_suffix(".tmp"); tmp.write_text(json.dumps(db, ensure_ascii=False, indent=1)); tmp.replace(CATALOG)


class CardIn(BaseModel):
    catalog_id: str
    install_id: str
    creator: str = ""
    title: str
    description: str = ""
    kind: str = "performance"
    duration_s: int = 0
    hosting: dict = {}
    availability: str = "unknown"
    perms: dict = {}
    origin: dict = {}


@app.post("/api/catalog/upsert")
def api_cat_upsert(body: CardIn):
    if not body.catalog_id.startswith(body.install_id + ":"):
        raise HTTPException(403, "catalog_id לא תואם להתקנה")
    if (_inst()["installs"].get(body.install_id) or {}).get("block"):
        raise HTTPException(403, "ההתקנה חסומה")
    if (body.hosting or {}).get("kind") != "youtube" or not (body.hosting or {}).get("video_id"):
        raise HTTPException(400, "כרטיס בלי אירוח פתיח לא נכנס לקטלוג")
    db = _cat()
    old = db["items"].get(body.catalog_id) or {}
    if old and old.get("install_id") != body.install_id:
        raise HTTPException(403, "שייך להתקנה אחרת")
    card = {**old, **body.model_dump(), "listed": True,
            "perms": {"listen": True, "download": bool(body.perms.get("download")), "reuse": bool(body.perms.get("reuse"))},
            "created": old.get("created") or time.strftime("%Y-%m-%d %H:%M"), "updated": time.strftime("%Y-%m-%d %H:%M"),
            "hidden": old.get("hidden", False), "reports": old.get("reports", [])}
    db["items"][body.catalog_id] = card
    _cat_save(db)
    return card


class CardRef(BaseModel):
    catalog_id: str
    install_id: str = ""
    reason: str = ""


@app.post("/api/catalog/withdraw")
def api_cat_withdraw(body: CardRef):
    db = _cat()
    c = db["items"].get(body.catalog_id)
    if not c:
        raise HTTPException(404)
    if c.get("install_id") != body.install_id:
        raise HTTPException(403, "רק היוצר יכול להסיר")
    c["listed"] = False; c["updated"] = time.strftime("%Y-%m-%d %H:%M")
    _cat_save(db)
    return {"ok": True}


@app.post("/api/catalog/report")
def api_cat_report(body: CardRef):
    db = _cat()
    c = db["items"].get(body.catalog_id)
    if not c:
        raise HTTPException(404)
    if not any(r.get("install_id") == body.install_id for r in c.setdefault("reports", [])):   # one report per install
        c["reports"].append({"install_id": body.install_id, "reason": body.reason[:300], "at": time.strftime("%Y-%m-%d %H:%M")})
        _cat_save(db)
    return {"ok": True, "reports": len(c["reports"])}


@app.get("/api/catalog/list")
def api_cat_list(q: str = ""):
    """public listing: listed, not hidden by moderation, still available at the host — newest first."""
    db = _cat()
    ql = q.strip().lower()
    items = [c for c in db["items"].values()
             if c.get("listed") and not c.get("hidden") and c.get("availability") not in ("removed", "private")
             and (not ql or ql in (c.get("title", "") + " " + c.get("creator", "")).lower())]
    items.sort(key=lambda c: c.get("created", ""), reverse=True)
    pub = [{k: c.get(k) for k in ("catalog_id", "install_id", "creator", "title", "description", "kind", "duration_s",
                                  "hosting", "availability", "perms", "origin", "created")} for c in items]
    return {"items": pub}


@app.get("/api/admin/catalog", dependencies=[Depends(require_admin)])
def api_cat_admin():
    db = _cat()
    return {"items": sorted(db["items"].values(), key=lambda c: c.get("created", ""), reverse=True)}


class ModIn(BaseModel):
    hidden: bool


@app.post("/api/admin/catalog/{cid:path}/moderate", dependencies=[Depends(require_admin)])
def api_cat_moderate(cid: str, body: ModIn):
    db = _cat()
    c = db["items"].get(cid)
    if not c:
        raise HTTPException(404)
    c["hidden"] = body.hidden
    _cat_save(db)
    return c


# ================================================================ usage learning (consent-based summaries)
USAGE = ADMIN / "usage.json"


def _usage() -> dict:
    try:
        return json.loads(USAGE.read_text())
    except Exception:
        return {"installs": {}}


class UsageIn(BaseModel):
    install_id: str
    since: str = ""
    until: str = ""
    counts: dict = {}
    events: list = []


@app.post("/api/usage")
def api_usage_ingest(body: UsageIn):
    """an install's consented summary. We keep AGGREGATE COUNTS per install + a small recent-events tail —
    never recordings or files. This answers the vision doc's questions (which features help, where it sticks)."""
    db = _usage()
    rec = db["installs"].setdefault(body.install_id, {"counts": {}, "first": body.since, "flushes": 0, "events": []})
    for k, v in (body.counts or {}).items():
        try:
            rec["counts"][k] = rec["counts"].get(k, 0) + int(v)
        except Exception:
            pass
    rec["events"] = (rec.get("events", []) + (body.events or []))[-100:]   # small recent tail only
    rec["last"] = body.until or time.strftime("%Y-%m-%dT%H:%M:%S")
    rec["flushes"] = rec.get("flushes", 0) + 1
    ADMIN.mkdir(exist_ok=True)
    tmp = USAGE.with_suffix(".tmp"); tmp.write_text(json.dumps(db, ensure_ascii=False, indent=1)); tmp.replace(USAGE)
    return {"ok": True}


@app.get("/api/admin/usage", dependencies=[Depends(require_admin)])
def api_usage_admin():
    db = _usage()
    tot = {}
    for rec in db["installs"].values():
        for k, v in rec.get("counts", {}).items():
            tot[k] = tot.get(k, 0) + v
    return {"installs": sorted(db["installs"].items(), key=lambda kv: kv[1].get("last", ""), reverse=True), "totals": tot}


PAGE = """<!doctype html><html dir="rtl" lang="he"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>DJ Dvir · מרכז רישוי</title>
<style>
:root{--bg:#f4f6fb;--panel:#ffffff;--line:#e4e8f1;--ink:#1e2440;--mut:#6b7694;--acc:#4a6cf7;--ok:#1f9d55;--bad:#e5484d;--warn:#d98e00}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 'Rubik',system-ui,sans-serif}
header{display:flex;align-items:center;gap:12px;padding:16px 22px;border-bottom:1px solid var(--line)}
header b{font-size:20px}header .sub{color:var(--mut);font-size:13px}
main{max-width:1060px;margin:0 auto;padding:18px 22px 60px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:18px}
h2{margin:0 0 10px;font-size:16px;color:var(--acc)}
form.new{display:grid;grid-template-columns:1.2fr 1.2fr .8fr .6fr .9fr 1fr auto;gap:8px;align-items:end}
label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--mut)}
input,select{background:#f7f9fc;color:var(--ink);border:1px solid var(--line);border-radius:9px;padding:8px 10px;font-size:14px}
button{background:var(--acc);color:#fff;border:0;border-radius:9px;padding:9px 16px;font-weight:700;cursor:pointer}
button.ghost{background:transparent;color:var(--mut);border:1px solid var(--line)}
button.danger{background:transparent;color:var(--bad);border:1px solid var(--bad)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:8px 9px;text-align:right;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px}
.tier{padding:2px 9px;border-radius:99px;font-size:12px;font-weight:700}
.tier.pro{background:#e3f0fb;color:#1f6fb0}.tier.studio{background:#f0e5fb;color:#7a3fc0}.tier.free{background:#eef1f8;color:#5a6b9a}
.tier.trial{background:#fdf3d8;color:#b5880f}
.chip{display:inline-flex;gap:8px;align-items:baseline;background:#f7f9fc;border:1px solid var(--line);border-radius:11px;padding:9px 14px;font-size:12.5px;color:var(--mut)}
.chip b{font-size:19px;color:var(--ink);font-weight:800}
.chip.ok{border-color:#bfe6cf}.chip.warn{border-color:#f0dca0}.chip.bad{border-color:#f3c2c6}
.chip.ok b{color:var(--ok)}.chip.warn b{color:var(--warn)}.chip.bad b{color:var(--bad)}
.dleft{font-size:11px;font-weight:700}.dleft.ok{color:var(--ok)}.dleft.warn{color:var(--warn)}.dleft.bad{color:var(--bad)}
.mini{background:#f7f9fc;color:var(--ink);border:1px solid var(--line);border-radius:7px;padding:4px 8px;font-size:12px;cursor:pointer;font-weight:600}
.mini:hover{border-color:var(--acc)}.src{font-size:11px;color:var(--mut)}
.key{font-family:ui-monospace,monospace;font-size:11px;color:var(--mut);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr;display:inline-block;vertical-align:middle}
.rev{color:var(--bad);font-weight:700}.live{color:var(--ok);font-weight:700}
.copy{cursor:pointer;border:1px solid var(--line);background:#f7f9fc;color:var(--ink);border-radius:7px;padding:3px 9px;font-size:12px}
.msg{min-height:20px;color:var(--ok);font-size:13px;margin-top:8px}
</style></head><body>
<header><b>🔑 DJ Dvir · מרכז רישוי</b><span class="sub">ממשק ניהול נפרד · המפתח הפרטי נשאר רק במחשב הזה · אין סליקה בשלב זה</span></header>
<main>
<div class="card" id="ovCard"><h2>📊 מבט-על</h2>
<div id="ov" style="display:flex;gap:10px;flex-wrap:wrap"><span style="color:var(--mut)">טוען…</span></div></div>
<div class="card"><h2>⬇️ קישורי הורדה (אתר ההורדה קורא מכאן)</h2>
<div style="color:var(--mut);font-size:12.5px;margin-bottom:8px">מקור-אמת אחד: מעדכנים כאן את הקישור והגרסה פר-מערכת — ואתר-ההורדה מתעדכן אוטומטית. הקישורים מצביעים בד״כ ל-GitHub Releases.</div>
<form onsubmit="return saveDl(event)" style="display:grid;grid-template-columns:auto 2fr 1fr;gap:8px;align-items:end">
  <label style="grid-column:1"> <b>macOS</b></label>
  <label>קישור (.dmg)<input id="dlMacU" placeholder="https://…/DJ-Dvir-mac.dmg" style="direction:ltr"></label>
  <label>גרסה<input id="dlMacV" placeholder="2.2.0"></label>
  <label style="grid-column:1"><b>Windows</b></label>
  <label>קישור (.exe)<input id="dlWinU" placeholder="https://…/DJ-Dvir-win.exe" style="direction:ltr"></label>
  <label>גרסה<input id="dlWinV" placeholder="2.2.0"></label>
  <button style="grid-column:1 / -1;justify-self:start">שמור קישורים</button>
</form><div class="msg" id="dlMsg"></div></div>
<div class="card"><h2>➕ לקוח חדש / הנפקת מפתח</h2>
<form class="new" onsubmit="return create(event)">
<label>שם הלקוח<input id="nName" required placeholder="למשל: גן שקד"></label>
<label>אימייל<input id="nEmail" type="email" placeholder="לא חובה"></label>
<label>רישיון<select id="nTier"><option value="pro">Pro — כבדים</option><option value="studio">Studio — הכול</option><option value="trial">ניסיון — הכול, מוגבל</option><option value="free">חינמי</option></select></label>
<label>חודשים (0=לצמיתות)<input id="nMonths" type="number" value="12" min="0" max="120"></label>
<label>נעילת-מחשב (אופציונלי)<input id="nMachine" placeholder="machine-id מהלקוח"></label>
<label>הערה<input id="nNote" placeholder="פנימי"></label>
<button>הנפק מפתח</button>
</form><div class="msg" id="msg"></div></div>
<div class="card"><h2>👥 לקוחות ומפתחות</h2><table id="tbl"><thead>
<tr><th>לקוח</th><th>רישיון</th><th>תוקף</th><th>מצב</th><th>מפתח</th><th></th></tr></thead><tbody></tbody></table></div>
<div class="card"><h2>📡 התקנות חיות (חיווי)</h2>
<div style="color:var(--mut);font-size:12.5px;margin-bottom:8px">כל עותק של המערכת מדווח לכאן בעלייה וכל ~6 שעות. פרסמת קישור-הורדה? כל מי שמריץ יופיע פה — עם שליטה: חסימה או הודעה שתוצג אצלו.</div>
<table id="itbl"><thead><tr><th>התקנה</th><th>רישיון</th><th>נראה לאחרונה</th><th>גרסה</th><th>דיווחים</th><th>שליטה</th></tr></thead><tbody></tbody></table></div>
<div class="card"><h2>🎵 קטלוג הקהילה</h2>
<div style="color:var(--mut);font-size:12.5px;margin-bottom:8px">כל יצירה שמשתמש בחר ״הצג בקהילה״. המדיה נשארת אצל המארח (YouTube); כאן הכרטיס, ההרשאות והדיווחים. הסתרה מוציאה מהקטלוג מיד, בלי למחוק.</div>
<table id="ctbl"><thead><tr><th>יצירה</th><th>יוצר</th><th>הרשאות</th><th>זמינות</th><th>דיווחים</th><th>ניהול</th></tr></thead><tbody></tbody></table></div>
<div class="card"><h2>📊 שימוש (בהסכמה)</h2>
<div style="color:var(--mut);font-size:12.5px;margin-bottom:8px">רק מהתקנות שבחרו לשתף נתוני-שימוש. סיכומים מצטברים בלבד — אילו יכולות בשימוש, לא הקלטות ולא קבצים.</div>
<div id="usTot" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px"></div>
<table id="utbl"><thead><tr><th>התקנה</th><th>עדכון אחרון</th><th>פעולות עיקריות</th></tr></thead><tbody></tbody></table></div>
<div class="card"><h2>ℹ️ איך זה עובד</h2>
<div style="color:var(--mut);font-size:13.5px">
המפתח חתום Ed25519 — אי-אפשר לזייף או לערוך אותו. <b>הרשמה-עצמית:</b> כל מי שמוריד את האפליקציה נרשם במסך-ההפעלה
ומקבל מיד רישיון-ניסיון מלא (מוגבל-זמן, נעול-למחשב) — והוא מופיע כאן אוטומטית. בלי רישיון תקף <b>המערכת לא נפתחת כלל</b>.
<b>שדרוג/הארכה</b> מנפיקים מפתח חדש (חתום) — שלחו ללקוח. <b>ביטול</b> כאן גם עוצר מיד את ההתקנה החיה (דרך חיווי-החסימה),
וגם חוסם הנפקה-מחדש. האימות באפליקציה אופליין; פעולות-שליטה מגיעות בחיווי הבא (~6 שעות, או בעלייה).</div></div>
</main><script>
const TOK=new URLSearchParams(location.search).get('token')||'';
if(TOK){try{document.cookie='rk_admin='+TOK+';path=/;max-age=31536000;samesite=strict'}catch(e){}}
async function j(u,o){o=o||{};o.headers=Object.assign({},o.headers,TOK?{'X-Admin-Token':TOK}:{});const r=await fetch(u,o);if(r.status===401)throw new Error('נדרש admin token — פתחו עם ?token=... בכתובת');if(!r.ok)throw new Error((await r.json().catch(()=>({}))).detail||r.status);return r.json()}
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function daysLeft(exp){if(!exp)return null;const d=Math.ceil((new Date(exp)-new Date())/864e5);return d}
function dleftHtml(exp){const d=daysLeft(exp);if(d===null)return '';
 if(d<0)return `<span class="dleft bad">פג לפני ${-d} י׳</span>`;
 const cls=d<=14?'warn':'ok';return `<span class="dleft ${cls}">נותרו ${d} ימים</span>`}
async function loadOverview(){let o;try{o=await j('/api/overview')}catch(e){return}
 const chip=(n,lbl,cls)=>`<span class="chip ${cls||''}"><b>${n}</b> ${lbl}</span>`;
 document.getElementById('ov').innerHTML=
  chip(o.trials_active,'ניסיונות פעילים','ok')+
  chip(o.trials_soon,'פגים בקרוב (≤14י׳)',o.trials_soon?'warn':'')+
  chip(o.expired,'ניסיונות שפגו',o.expired?'bad':'')+
  chip(o.paid,'משלמים (Pro/Studio)')+
  chip(o.online,'התקנות מחוברות (24ש׳)','ok')+
  chip(o.blocked,'חסומות',o.blocked?'bad':'')+
  chip(o.installs,'סה״כ התקנות')}
async function loadDl(){let d;try{d=await j('/api/download')}catch(e){return}
 dlMacU.value=d.mac.url||'';dlMacV.value=d.mac.version||'';dlWinU.value=d.win.url||'';dlWinV.value=d.win.version||'';}
async function saveDl(e){e.preventDefault();try{
 await j('/api/admin/download',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
  mac_url:dlMacU.value,mac_version:dlMacV.value,win_url:dlWinU.value,win_version:dlWinV.value})});
 document.getElementById('dlMsg').textContent='✓ נשמר — אתר-ההורדה יציג את הקישורים החדשים';}catch(err){document.getElementById('dlMsg').textContent='⚠️ '+err.message}return false}
async function load(){const d=await j('/api/customers');const tb=document.querySelector('#tbl tbody');
tb.innerHTML=d.customers.map(c=>{const self=c.source==='self-register';return `<tr>
<td><b>${esc(c.name)}</b> ${self?'<span class="src" title="נרשם לבד דרך מסך-ההפעלה">🌐 הרשמה-עצמית</span>':'<span class="src">✍️ ידני</span>'}
<div style="color:var(--mut);font-size:12px">${esc(c.email||'')} ${esc(c.note||'')}</div></td>
<td><span class="tier ${c.tier}">${esc(d.tiers[c.tier]||c.tier)}</span></td>
<td>${c.expires?esc(c.expires):'לצמיתות'}${c.expires&&!c.revoked?'<div>'+dleftHtml(c.expires)+'</div>':''}${c.machine?'<div style="font-size:11px;color:var(--mut)">🔒 נעול למחשב</div>':''}</td>
<td>${c.revoked?'<span class="rev">מבוטל ⛔</span>':'<span class="live">פעיל</span>'}</td>
<td><span class="key">${esc(c.key)}</span></td>
<td style="white-space:nowrap">
<button class="copy" onclick="navigator.clipboard.writeText('${c.key}');this.textContent='הועתק ✓'">📋</button>
${c.tier==='trial'?`<button class="mini" style="margin-inline-start:6px" onclick="upg('${c.cid}','pro')" title="שדרג ל-Pro, שנה">⬆ Pro</button><button class="mini" onclick="upg('${c.cid}','studio')" title="שדרג ל-Studio, שנה">⬆ Studio</button>`:''}
${c.expires?`<button class="mini" style="margin-inline-start:6px" onclick="ext('${c.cid}')" title="הארך תוקף">⏱ הארך</button>`:''}
<button class="${c.revoked?'copy':'danger'}" style="margin-inline-start:6px" onclick="revoke('${c.cid}')" title="${c.revoked?'שחזר וגם משחרר חסימה בהתקנה':'ביטול שגם עוצר את ההתקנה החיה'}">${c.revoked?'שחזר':'בטל'}</button></td>
</tr>`}).join('')||'<tr><td colspan="6" style="color:var(--mut)">עוד אין לקוחות — הנפיקו מפתח ראשון למעלה</td></tr>'}
async function upg(cid,tier){if(!confirm('שדרוג ל-'+tier+' מנפיק מפתח חדש (12 חודשים) — צריך לשלוח ללקוח את המפתח החדש. להמשיך?'))return;
 try{const c=await j('/api/customers/'+cid+'/upgrade',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tier:tier,months:12})});
 await navigator.clipboard.writeText(c.key).catch(()=>{});document.getElementById('msg').textContent='✓ שודרג ל-'+tier+' · מפתח חדש הועתק ללוח';load();loadOverview()}catch(e){alert(e.message)}}
async function ext(cid){const m=prompt('הארכת תוקף ב-כמה חודשים? (0=לצמיתות)','12');if(m===null)return;
 try{const c=await j('/api/customers/'+cid+'/upgrade',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tier:'',months:+m})});
 await navigator.clipboard.writeText(c.key).catch(()=>{});document.getElementById('msg').textContent='✓ התוקף הוארך · מפתח חדש הועתק ללוח (שלחו ללקוח)';load();loadOverview()}catch(e){alert(e.message)}}
async function create(e){e.preventDefault();try{
const c=await j('/api/customers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
name:nName.value,email:nEmail.value,tier:nTier.value,months:+nMonths.value,machine:nMachine.value,note:nNote.value})});
await navigator.clipboard.writeText(c.key).catch(()=>{});
document.getElementById('msg').textContent='✓ הונפק מפתח ל"'+c.name+'" — הועתק ללוח, שלחו ללקוח';
nName.value=nEmail.value=nMachine.value=nNote.value='';load()}catch(err){document.getElementById('msg').textContent='⚠️ '+err.message}return false}
async function revoke(cid){const r=await j('/api/customers/'+cid+'/revoke',{method:'POST'});
 if(r&&r.installs_affected)document.getElementById('msg').textContent=(r.revoked?'⛔ בוטל — נחסמו ':'✓ שוחזר — שוחררו ')+r.installs_affected+' התקנות חיות';
 load();loadOverview();loadInst()}
async function loadInst(){const d=await j('/api/installs');const tb=document.querySelector('#itbl tbody');
tb.innerHTML=d.installs.map(i=>`<tr${(i.healthy===false||i.last_error)?' style="background:rgba(229,72,77,.09)"':''}>
<td><b>${esc(i.customer||'אנונימי')}</b> ${(i.healthy===false||i.last_error)?'<span style="color:#e5484d;font-weight:800">⚠ תקלה</span>':(i.last_event==='launch'?'<span style="color:#2faa5a" title="עלתה תקין">✓</span>':'')}<div style="font-size:11px;color:var(--mut);direction:ltr">${esc(i.install_id)} · ${esc(i.machine||'')}</div>${i.last_error?`<div style="font-size:11px;color:#e5484d;direction:ltr;max-width:360px;white-space:normal;margin-top:3px">${esc(i.last_error_at||'')} · ${esc((i.last_error||'').slice(0,180))}</div>`:''}</td>
<td>${i.licensed?'<span class="tier '+esc(i.tier)+'">'+esc(i.tier)+'</span>':'<span class="tier free">חינמי</span>'}</td>
<td>${esc(i.last_seen||'')}<div style="font-size:11px;color:var(--mut)">מאז ${esc(i.first_seen||'')}</div></td>
<td>${esc(i.ver||'—')} <span style="color:var(--mut);font-size:11px">${esc(i.platform||'')}</span></td>
<td>${i.count||0}</td>
<td style="white-space:nowrap">
<button class="${i.block?'copy':'danger'}" onclick="ictl('${i.install_id}',{block:${!i.block}})">${i.block?'שחרר חסימה':'חסום'}</button>
<button class="copy" style="margin-inline-start:6px" onclick="imsg('${i.install_id}','${esc(i.message||'')}')">💬 הודעה</button>
<button class="${i.enforce?'danger':'copy'}" style="margin-inline-start:6px" title="כשדולק: פיצ׳רים כבדים נחסמים לפי הרישיון. כבוי=הכול פתוח" onclick="ictl('${i.install_id}',{enforce:${!i.enforce}})">${i.enforce?'🔒 אכיפה':'🔓 פתוח'}</button>
${i.block?'<div class="rev" style="font-size:11px">חסום</div>':''}</td>
</tr>`).join('')||'<tr><td colspan="6" style="color:var(--mut)">אין עדיין חיווי — האפליקציה מדווחת בעלייה הבאה שלה</td></tr>'}
async function ictl(iid,body){await j('/api/installs/'+iid+'/ctl',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});loadInst()}
function imsg(iid,cur){const m=prompt('הודעה שתוצג בהתקנה הזו (ריק = להסיר):',cur||'');if(m===null)return;ictl(iid,{message:m})}
async function loadCat(){const d=await j('/api/admin/catalog');const tb=document.querySelector('#ctbl tbody');
const P=p=>['האזנה',p&&p.download?'הורדה':null,p&&p.reuse?'שימוש-חוזר':null].filter(Boolean).join(' · ');
tb.innerHTML=d.items.map(c=>`<tr>
<td><b>${esc(c.title)}</b><div style="font-size:11px;color:var(--mut)">${c.hosting&&c.hosting.url?'<a style="color:var(--acc)" target="_blank" href="'+esc(c.hosting.url)+'">'+esc(c.hosting.url)+'</a>':''} · ${esc(c.created||'')}</div></td>
<td>${esc(c.creator||'')}</td><td style="font-size:12px">${P(c.perms)}</td>
<td>${!c.listed?'<span style="color:var(--mut)">הוסר ע״י היוצר</span>':c.hidden?'<span class="rev">מוסתר</span>':esc(c.availability||'')}</td>
<td>${(c.reports||[]).length?'<span class="rev" title="'+esc((c.reports||[]).map(r=>r.reason).join(' | '))+'">'+(c.reports||[]).length+' ⚑</span>':'—'}</td>
<td><button class="${c.hidden?'copy':'danger'}" onclick="mod('${c.catalog_id}',${!c.hidden})">${c.hidden?'החזר':'הסתר'}</button></td>
</tr>`).join('')||'<tr><td colspan="6" style="color:var(--mut)">עוד אין יצירות בקהילה</td></tr>'}
async function mod(cid,hidden){await j('/api/admin/catalog/'+encodeURIComponent(cid)+'/moderate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hidden})});loadCat()}
const ULBL={app_open:'פתיחות',feature_used:'יכולות',publish:'פרסומים',arrangement_pick:'בחירת-ליווי',correction:'תיקונים',song_loaded:'טעינות-שיר'};
async function loadUsage(){let d;try{d=await j('/api/admin/usage')}catch(e){return}
const ent=Object.entries(d.totals||{}).filter(([k])=>!k.includes(':')).sort((a,b)=>b[1]-a[1]);
document.getElementById('usTot').innerHTML=ent.length?ent.map(([k,v])=>`<span class="tier free">${esc(ULBL[k]||k)}: <b>${v}</b></span>`).join(''):'<span style="color:var(--mut)">אין עדיין נתוני-שימוש משותפים</span>';
const feats=Object.entries(d.totals||{}).filter(([k])=>k.startsWith('feature:')).sort((a,b)=>b[1]-a[1]);
if(feats.length)document.getElementById('usTot').innerHTML+=' &nbsp; '+feats.map(([k,v])=>`<span class="tier pro">${esc(k.slice(8))}: ${v}</span>`).join('');
const tb=document.querySelector('#utbl tbody');
tb.innerHTML=(d.installs||[]).map(([iid,r])=>`<tr><td style="direction:ltr;font-size:12px">${esc(iid)}</td><td>${esc(r.last||'')}</td>
<td style="font-size:12px">${Object.entries(r.counts||{}).filter(([k])=>!k.includes(':')).map(([k,v])=>esc(ULBL[k]||k)+' '+v).join(' · ')}</td></tr>`).join('')||'<tr><td colspan="3" style="color:var(--mut)">—</td></tr>'}
loadOverview();loadDl();load();loadInst();loadCat();loadUsage();setInterval(()=>{loadOverview();loadInst();loadCat();loadUsage()},30000);
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def home():
    return PAGE


if __name__ == "__main__":
    import uvicorn
    # The PUBLIC hub (cloud) runs WITHOUT the private key: it only receives check-ins/reports and shows the
    # dashboard. License issuance (which needs the key) stays on the owner's local hub. So a missing key is
    # a warning, not a fatal error, unless RK_HUB_REQUIRE_KEY=1 is set (the local issuing hub).
    if not PRIV.exists():
        msg = "אין מפתח פרטי (license_admin/private.pem) — מצב ניטור-בלבד (אי-אפשר להנפיק רישיונות כאן)"
        if os.environ.get("RK_HUB_REQUIRE_KEY", "") in ("1", "true", "yes"):
            print(msg.replace("מצב ניטור-בלבד", "חובה")); sys.exit(1)
        print("ℹ️ " + msg)
    port = int(os.environ.get("PORT") or os.environ.get("RK_HUB_PORT", "8099"))   # Render provides $PORT
    where = f"http://127.0.0.1:{port}" if BIND in ("127.0.0.1", "localhost") else f"http://<server>:{port}"
    print("🔑 מרכז הרישוי:", where)
    if BIND not in ("127.0.0.1", "localhost"):
        print(f"   פתוח לרשת — התחברו עם:  {where}/?token={ADMIN_TOKEN}")
    else:
        print(f"   admin token (לגישה מרחוק בעתיד): {ADMIN_TOKEN}")
    uvicorn.run(app, host=BIND, port=port, log_level="warning")

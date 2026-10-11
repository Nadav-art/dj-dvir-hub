"""DJ Dvir licensing core — offline-verifiable signed license keys (Ed25519).

The ADMIN tool (tools/license_admin.py) holds the PRIVATE key and issues/signs keys;
the app ships only the PUBLIC key below and verifies offline — a key cannot be forged or edited.
No billing here: this is the mechanism + identity layer only.

Key string:  DJDVIR-<b64url(payload json)>.<b64url(signature)>
Payload:     {v, customer, email, tier, features, issued, expires, machine, note}
             tier: free | pro | studio · expires: ISO date or null (perpetual)
             machine: optional lock to a machine-id (empty = any machine)
"""
import base64
import hashlib
import json
import platform
import subprocess
import uuid

PREFIX = "DJDVIR-"
# the admin tool prints this after generating license_admin/private.pem (keep PRIVATE out of git!)
PUBLIC_KEY_B64 = "TZydqsv7dK4ja2RNM3y7YOnKAn-tQV-njJh-kShPKs8"

_STUDIO_FEATURES = ["play", "karaoke", "lyrics", "kids", "stems_hq", "deep_clean", "fa_align", "voice_detect", "voice_lab", "export", "batch"]
TIERS = {
    "free":   {"name": "חינמי", "features": ["play", "karaoke", "lyrics", "kids"]},
    # "trial" = full access, time-limited: everyone who self-registers gets this for a few months.
    "trial":  {"name": "ניסיון", "features": list(_STUDIO_FEATURES)},
    "pro":    {"name": "Pro", "features": ["play", "karaoke", "lyrics", "kids", "stems_hq", "deep_clean", "fa_align", "voice_detect"]},
    "studio": {"name": "Studio", "features": list(_STUDIO_FEATURES)},
}
# the "heavy" features the DJ plans to gate (enforcement is OFF until he turns it on)
HEAVY = ["stems_hq", "deep_clean", "fa_align", "voice_detect", "batch"]


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def machine_id() -> str:
    """stable, non-identifying machine fingerprint (hash of hardware UUID)."""
    raw = ""
    try:
        if platform.system() == "Darwin":
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], capture_output=True, text=True).stdout
            for ln in out.splitlines():
                if "IOPlatformUUID" in ln:
                    raw = ln.split('"')[-2]; break
    except Exception:
        pass
    raw = raw or hex(uuid.getnode())
    return hashlib.sha256(("djdvir|" + raw).encode()).hexdigest()[:16]


def sign_license(payload: dict, private_pem: bytes) -> str:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    key = load_pem_private_key(private_pem, password=None)
    return PREFIX + _b64e(body) + "." + _b64e(key.sign(body))


def verify_license(key_str: str, public_b64: str = None) -> dict | None:
    """signature + structure check → payload, else None. (Expiry/machine are judged by the caller so it
    can tell the user WHY a key is rejected.)"""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        s = key_str.strip()
        if not s.startswith(PREFIX):
            return None
        body_s, sig_s = s[len(PREFIX):].split(".", 1)
        body, sig = _b64d(body_s), _b64d(sig_s)
        Ed25519PublicKey.from_public_bytes(_b64d(public_b64 or PUBLIC_KEY_B64)).verify(sig, body)
        p = json.loads(body)
        return p if isinstance(p, dict) and p.get("v") == 1 else None
    except Exception:
        return None


def license_status(key_str: str | None, public_b64: str = None) -> dict:
    """full evaluation for the app: {ok, tier, features, customer, expires, reason}."""
    import datetime
    if not key_str:
        return {"ok": False, "tier": "free", "features": TIERS["free"]["features"], "reason": "אין רישיון — מצב חינמי"}
    p = verify_license(key_str, public_b64)
    if not p:
        return {"ok": False, "tier": "free", "features": TIERS["free"]["features"], "reason": "מפתח לא תקין (חתימה נכשלה)"}
    if p.get("expires"):
        try:
            if datetime.date.fromisoformat(p["expires"]) < datetime.date.today():
                return {"ok": False, "tier": "free", "features": TIERS["free"]["features"],
                        "customer": p.get("customer"), "reason": f"הרישיון פג ({p['expires']})"}
        except Exception:
            pass
    if p.get("machine") and p["machine"] != machine_id():
        return {"ok": False, "tier": "free", "features": TIERS["free"]["features"],
                "customer": p.get("customer"), "reason": "הרישיון נעול למחשב אחר"}
    feats = p.get("features") or TIERS.get(p.get("tier", "free"), TIERS["free"])["features"]
    days_left = None
    if p.get("expires"):
        try:
            days_left = (datetime.date.fromisoformat(p["expires"]) - datetime.date.today()).days
        except Exception:
            pass
    return {"ok": True, "tier": p.get("tier", "free"), "features": feats, "trial": p.get("tier") == "trial",
            "customer": p.get("customer"), "email": p.get("email"), "expires": p.get("expires"),
            "days_left": days_left, "note": p.get("note")}

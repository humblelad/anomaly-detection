"""Demo backend: the login endpoint that consumes a DetectionOpinion.

It sits behind Envoy, so every request carries the trusted, HMAC-signed
`X-Detection-JA4` header minted by the WASM filter. The backend:

  1. verifies the HMAC (never trusts the network path),
  2. asks the scoring service for an opinion,
  3. checks the credentials,
  4. reports the outcome back to the scoring service (closing the EWMA loop),
  5. applies ALLOW / CHALLENGE / BLOCK — but in SHADOW mode it logs the
     divergence between the opinion and what it would enforce, without
     actually blocking.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time

import requests
from flask import Flask, g, jsonify, request

logging.basicConfig(level=logging.INFO, format="%(asctime)s backend %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

HMAC_KEY = os.environ.get("HMAC_KEY", "demo-static-hmac-key-rotate-in-prod").encode()
SCORING_URL = os.environ.get("SCORING_URL", "http://scoring-service:9100")
SHADOW_MODE = os.environ.get("SHADOW_MODE", "false").lower() in ("1", "true", "yes")
MAX_SIG_AGE = 300  # seconds; rejects replayed signed headers

# Toy credential store. victimN accounts exist but the attacker's password
# guesses are wrong, so stuffing produces failures; employeeN log in fine.
VALID = {f"employee{i}": "correct-horse" for i in range(200)}
VALID.update({f"victim{i}": "s3cret" for i in range(500)})


def parse_trusted_header(raw: str) -> dict | None:
    """Parse and HMAC-verify `v1;ja4=...;ts=...;sig=...`. Returns the fields on
    success, None on any tampering, missing field, or staleness."""
    if not raw:
        return None
    parts = dict(
        kv.split("=", 1) for kv in raw.split(";") if "=" in kv
    )
    if raw.split(";", 1)[0] != "v1":
        return None
    ja4, ts, sig = parts.get("ja4"), parts.get("ts"), parts.get("sig")
    if ts is None or sig is None or ja4 is None:
        return None
    expected = hmac.new(HMAC_KEY, f"{ja4}|{ts}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        if abs(time.time() - int(ts)) > MAX_SIG_AGE:
            return None
    except ValueError:
        return None
    return {"ja4": ja4, "ts": int(ts)}


@app.before_request
def _client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    g.client_ip = xff.split(",")[0].strip() if xff else request.remote_addr


@app.post("/login")
def login():
    verified = parse_trusted_header(request.headers.get("X-Detection-JA4", ""))
    if verified is None:
        # The request did not pass the trust boundary. Fail closed.
        log.warning("rejecting request with missing/invalid X-Detection-JA4 from %s",
                    g.client_ip)
        return jsonify({"error": "untrusted request path"}), 401

    ja4 = verified["ja4"]
    ua = request.headers.get("User-Agent", "")
    body = request.get_json(force=True, silent=True) or {}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))

    opinion = _score(g.client_ip, ja4, ua, username)
    creds_ok = VALID.get(username) == password and password != ""
    _report_outcome(g.client_ip, ja4, ua, username, "success" if creds_ok else "failure")

    action = opinion.get("action", "ALLOW")
    enforced = action
    if SHADOW_MODE and action != "ALLOW":
        # Log what we WOULD do, then let it through — how a detector gets
        # validated against real traffic before it can cause an outage.
        log.info("SHADOW divergence: opinion=%s score=%s would_enforce=%s "
                 "recommended_key=%s(fp %.1f%%) -> allowing",
                 opinion.get("opinion"), opinion.get("score"), action,
                 opinion.get("recommended_key"), opinion.get("recommended_fp_pct", 0.0))
        enforced = "ALLOW"

    status, message = _apply(enforced, creds_ok)
    return jsonify({
        "username": username,
        "authenticated": creds_ok and enforced == "ALLOW",
        "action_recommended": action,
        "action_enforced": enforced,
        "shadow_mode": SHADOW_MODE,
        "message": message,
        "ja4": ja4,
        "opinion": opinion,
    }), status


def _apply(enforced: str, creds_ok: bool) -> tuple[int, str]:
    if enforced == "BLOCK":
        return 403, "blocked: request scored malicious"
    if enforced == "CHALLENGE":
        return 401, "challenge required (MFA/CAPTCHA) — not satisfied in demo"
    if not creds_ok:
        return 401, "invalid credentials"
    return 200, "login successful"


def _score(ip: str, ja4: str, ua: str, username: str) -> dict:
    try:
        r = requests.post(f"{SCORING_URL}/score",
                          json={"ip": ip, "ja4": ja4, "ua": ua, "username": username},
                          timeout=2)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        # Fail open on scorer outage: availability of login beats detection.
        log.error("scoring service unreachable: %s", e)
        return {"opinion": "UNKNOWN", "score": 0, "action": "ALLOW",
                "recommended_key": "ip+ja4", "recommended_fp_pct": 0.0,
                "reasoning": [{"factor": "scorer_unavailable", "contribution": 0,
                               "evidence": str(e)}]}


def _report_outcome(ip: str, ja4: str, ua: str, username: str, outcome: str) -> None:
    try:
        requests.post(f"{SCORING_URL}/event",
                      json={"ip": ip, "ja4": ja4, "ua": ua,
                            "username": username, "outcome": outcome},
                      timeout=2)
    except requests.RequestException as e:
        log.error("could not report outcome: %s", e)


@app.get("/whoami")
def whoami():
    """Echoes the client IP and verified JA4 the backend sees. Demo scripts use
    it to seed their synthetic legitimate population on the SAME IP that live
    traffic arrives from, so the collateral-damage contrast is real."""
    verified = parse_trusted_header(request.headers.get("X-Detection-JA4", ""))
    return jsonify({
        "client_ip": g.client_ip,
        "ja4": verified["ja4"] if verified else None,
        "ua": request.headers.get("User-Agent", ""),
    })


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "shadow_mode": SHADOW_MODE})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)

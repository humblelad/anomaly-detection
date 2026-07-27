"""Scoring service: EWMA composite-key reputation -> DetectionOpinion.

Endpoints:
  POST /score  {ip, ja4, ua, username}            -> DetectionOpinion
  POST /event  {ip, ja4, ua, username, outcome}   -> records login outcome
  POST /seed   {events: [...]}                    -> demo-only synthetic history
  POST /clock  {advance: seconds}                 -> demo-only time travel
  GET  /state?ip=&ja4=                            -> candidate-key introspection
  GET  /healthz                                   -> liveness + decay half-lives

/score records the *attempt* (velocity, username spread); /event records the
*outcome* (failure ratio, legit-user population, UA association). A blocked
request therefore still counts as an attempt even though no outcome follows.
"""

from __future__ import annotations

import logging
import threading
import time

from flask import Flask, jsonify, request

from ewma import HALF_LIVES, Store
from opinion import build_opinion, ua_family

logging.basicConfig(level=logging.INFO, format="%(asctime)s scoring %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
store = Store()
lock = threading.Lock()

# Demo-only clock offset, in seconds, added to every timestamp the service
# reads. A real deployment has no such knob; its clock is the wall clock.
_clock_offset = 0.0


def now_ts() -> float:
    return time.time() + _clock_offset


def _fields(payload: dict) -> tuple[str, str, str, str]:
    return (
        str(payload.get("ip", "")),
        str(payload.get("ja4", "")),
        str(payload.get("ua", "")),
        str(payload.get("username", "")),
    )


@app.post("/score")
def score():
    payload = request.get_json(force=True, silent=True) or {}
    ip, ja4, ua, username = _fields(payload)
    now = now_ts()
    with lock:
        store.record_attempt(ip, ja4, username, now)
        result = build_opinion(store, ip, ja4, ua, username, now)
    log.info("score ip=%s ja4=%s user=%s -> %s(%d) action=%s",
             ip, ja4, username, result["opinion"], result["score"], result["action"])
    return jsonify(result)


@app.post("/event")
def event():
    payload = request.get_json(force=True, silent=True) or {}
    ip, ja4, ua, username = _fields(payload)
    outcome = str(payload.get("outcome", "failure"))
    with lock:
        store.record_outcome(ip, ja4, ua_family(ua), username, outcome, now_ts())
    return jsonify({"recorded": True})


@app.post("/seed")
def seed():
    """Demo affordance: inject synthetic *historical* state so the sharpening
    scenario has a believable legitimate population. Live traffic always flows
    through the real TLS pipeline; only history is synthetic.
    """
    payload = request.get_json(force=True, silent=True) or {}
    events = payload.get("events", [])
    now = now_ts()
    with lock:
        for ev in events:
            ip, ja4, ua, username = _fields(ev)
            weight = float(ev.get("weight", 1.0))
            outcome = str(ev.get("outcome", "success"))
            store.record_attempt(ip, ja4, username, now, weight)
            store.record_outcome(ip, ja4, ua_family(ua), username, outcome, now, weight)
    log.info("seeded %d synthetic events", len(events))
    return jsonify({"seeded": len(events)})


@app.post("/clock")
def clock():
    """Demo affordance: fast-forward the service's clock so EWMA decay becomes
    observable. The half-lives are in hours; a demo run is seconds.

    Forward only. Counters decay lazily from a last-touched timestamp that
    `observe` pins with max(), so a backwards jump would not rewind the store,
    it would silently freeze it — peek() returns the undecayed value whenever
    now <= last_ts.
    """
    global _clock_offset
    payload = request.get_json(force=True, silent=True) or {}
    try:
        advance = float(payload.get("advance", 0.0))
    except (TypeError, ValueError):
        return jsonify({"error": "advance must be a number"}), 400
    if advance < 0:
        return jsonify({"error": "advance must be >= 0; the clock is "
                                 "forward-only (see /clock docstring)"}), 400
    with lock:
        _clock_offset += advance
        offset = _clock_offset
    log.info("clock advanced %.0fs -> offset now %.0fs", advance, offset)
    return jsonify({"advanced": advance, "offset_seconds": offset})


@app.get("/state")
def state():
    ip = request.args.get("ip", "")
    ja4 = request.args.get("ja4", "")
    now = now_ts()
    with lock:
        profiles = {
            kc: {
                "decayed_attempts": round(store.stats(kc, kv).attempts.peek(now), 2),
                "decayed_failures": round(store.stats(kc, kv).fail.peek(now), 2),
                "decayed_legit": round(store.stats(kc, kv).success.peek(now), 2),
                "distinct_usernames_attempted": store.stats(kc, kv).distinct_users(now),
                "legit_users": store.stats(kc, kv).distinct_legit_users(now),
            }
            for kc, kv in store.candidate_keys(ip, ja4)
        }
        assoc = store.ua_association(ja4, now)
    return jsonify({"keys": profiles, "ua_association": assoc})


@app.get("/healthz")
def healthz():
    """Liveness, plus the decay tuning the service is actually running, so a
    client can describe the decay curve without restating constants that live
    in this container."""
    return jsonify({"ok": True, "half_lives": HALF_LIVES})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9100)

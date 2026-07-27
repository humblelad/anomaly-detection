"""DetectionOpinion assembly: explainable, rule-based scoring.

Each factor contributes points and carries the evidence that made it fire; the
reasoning[] array in the response is the audit trail.

ML (e.g. Isolation Forest) was deliberately rejected: EWMA-decayed
composite-key rarity gives comparable detection value here with full
explainability and no training pipeline.
"""

from __future__ import annotations

from ewma import HALF_LIVES, Store

CHALLENGE_AT = 40
BLOCK_AT = 75

VELOCITY_FLOOR = 5.0        # decayed attempts on ip+ja4 before velocity fires
FAILURE_RATIO_FLOOR = 0.7   # failure share before the ratio factor fires
FAILURE_VOLUME_FLOOR = 3.0  # decayed failures needed before ratio is meaningful
SPREAD_FLOOR = 5            # distinct usernames on one ip+ja4 = stuffing shape
UA_ASSOC_FLOOR = 3.0        # decayed successes before an association is trusted
DEVICE_HISTORY_FLOOR = 3.0  # decayed known-device weight before history "counts"


def ua_family(ua: str) -> str:
    ua = (ua or "").lower()
    # Order matters: Chrome UAs contain "safari", Edge UAs contain "chrome".
    for needle, fam in (
        ("curl", "curl"),
        ("python-requests", "python"),
        ("python-urllib", "python"),
        ("aiohttp", "python"),
        ("httpx", "python"),
        ("go-http-client", "go"),
        ("edg", "edge"),
        ("firefox", "firefox"),
        ("chrome", "chrome"),
        ("safari", "safari"),
    ):
        if needle in ua:
            return fam
    return "other"


def _factor(name: str, contribution: int, evidence: str) -> dict:
    return {"factor": name, "contribution": contribution, "evidence": evidence}


def _key_profile(store: Store, key_class: str, key_value: str, now: float) -> dict:
    """Blast-radius profile of one candidate key: if we blocked this key right
    now, how much of the traffic on it is legitimate?"""
    st = store.stats(key_class, key_value)
    attempts = st.attempts.peek(now)
    legit = st.success.peek(now)
    fails = st.fail.peek(now)
    fp_pct = round(100.0 * legit / attempts, 1) if attempts > 0 else 0.0
    return {
        "key": key_class,
        "value": key_value,
        "decayed_attempts": round(attempts, 2),
        "decayed_failures": round(fails, 2),
        "decayed_legit": round(legit, 2),
        "legit_users_affected": st.distinct_legit_users(now),
        "predicted_fp_pct": fp_pct,
    }


def build_opinion(store: Store, ip: str, ja4: str, ua: str, username: str,
                  now: float) -> dict:
    reasoning: list[dict] = []
    claimed = ua_family(ua)
    composite = f"{ip}|{ja4}"
    st_composite = store.stats("ip+ja4", composite)
    st_ja4 = store.stats("ja4", ja4)

    if not ja4:
        reasoning.append(_factor(
            "missing_ja4", 40,
            "no TLS fingerprint on request (non-TLS path or unparseable "
            "ClientHello); all legitimate demo clients produce one"))

    # Raw velocity alone would flag any busy shared key (a corporate NAT where
    # the whole fleet ships the same browser image looks identical in volume
    # terms), so discount by the share of that traffic that authenticates.
    velocity = st_composite.attempts.peek(now)
    successes = st_composite.success.peek(now)
    legit_share = min(1.0, successes / velocity) if velocity > 0 else 0.0
    if velocity > VELOCITY_FLOOR and legit_share < 0.5:
        contribution = min(30, round(2 * (velocity - VELOCITY_FLOOR) * (1 - legit_share)))
        reasoning.append(_factor(
            "velocity_ip_ja4", contribution,
            f"{velocity:.1f} decayed login attempts on ip+ja4={composite} "
            f"with only {legit_share:.0%} succeeding "
            f"(half-life {HALF_LIVES['ip+ja4'] / 3600:.0f}h)"))

    fails = st_composite.fail.peek(now)
    if fails >= FAILURE_VOLUME_FLOOR:
        ratio = fails / (fails + successes) if (fails + successes) > 0 else 0.0
        if ratio >= FAILURE_RATIO_FLOOR:
            reasoning.append(_factor(
                "failure_ratio", round(25 * ratio),
                f"{ratio:.0%} of recent outcomes on ip+ja4 are failures "
                f"({fails:.1f} failed vs {successes:.1f} ok, "
                f"half-life {HALF_LIVES['behavior'] / 60:.0f}m)"))

    # The credential-stuffing shape: many distinct usernames *failing* through
    # one TLS stack on one IP. Gated on failure volume, since many usernames
    # succeeding on a shared key is just a NAT with a uniform fleet image.
    spread = st_composite.distinct_users(now)
    if spread >= SPREAD_FLOOR and fails >= FAILURE_VOLUME_FLOOR:
        reasoning.append(_factor(
            "username_spread", min(35, 3 * spread),
            f"{spread} distinct usernames attempted via ip+ja4={composite} "
            f"within the behavioral window — one client stack rotating "
            f"identities"))

    # The User-Agent header is free to fake; the TLS stack is not. An
    # established association with a different client family means the
    # claimed UA is a lie.
    assoc = store.ua_association(ja4, now)
    if assoc:
        dominant, dom_weight = max(assoc.items(), key=lambda kv: kv[1])
        total_weight = sum(assoc.values())
        claimed_share = assoc.get(claimed, 0.0) / total_weight
        if (dom_weight >= UA_ASSOC_FLOOR and dominant != claimed
                and claimed_share < 0.10):
            reasoning.append(_factor(
                "ua_ja4_mismatch", 35,
                f"UA claims '{claimed}' but JA4 {ja4} is historically "
                f"{dom_weight / total_weight:.0%} '{dominant}' "
                f"(decayed weight {dom_weight:.1f}) — header spoofing"))

    # An account's own login history is a device allowlist. This is the
    # account-takeover shape, distinct from stuffing: one attacker stack, one
    # targeted account, no password guessing, no username spread.
    known_devices = store.known_ja4s_for_user(username, now)
    if (username and ja4 and known_devices and ja4 not in known_devices
            and sum(known_devices.values()) >= DEVICE_HISTORY_FLOOR):
        reasoning.append(_factor(
            "unfamiliar_ja4_for_user", 45,
            f"username={username!r} has {len(known_devices)} known device "
            f"fingerprint(s), none is {ja4} — login from a never-before-seen "
            f"TLS stack on an established account (half-life "
            f"{HALF_LIVES['ja4'] / 3600:.0f}h)"))

    ja4_seen = st_ja4.attempts.peek(now)
    global_seen = store.global_attempts.peek(now)
    if ja4 and global_seen >= 20 and ja4_seen / global_seen < 0.01:
        reasoning.append(_factor(
            "rare_ja4", 8,
            f"JA4 {ja4} accounts for {100 * ja4_seen / global_seen:.2f}% of "
            f"decayed traffic — rarely seen client stack"))

    profiles = {
        kc: _key_profile(store, kc, kv, now)
        for kc, kv in store.candidate_keys(ip, ja4)
    }
    # Recommend the candidate that still covers the observed attack traffic
    # (its decayed failures are within 90% of the best coverage) with the
    # lowest collateral damage; break ties toward the sharper key.
    max_fail = max(p["decayed_failures"] for p in profiles.values())
    covering = [p for p in profiles.values()
                if max_fail == 0 or p["decayed_failures"] >= 0.9 * max_fail]
    order = {"ip": 0, "ja4": 1, "ip+ja4": 2}  # sharpness tiebreak
    recommended = min(covering, key=lambda p: (p["predicted_fp_pct"], -order[p["key"]]))
    naive = profiles["ip"]
    # When every candidate covers the same traffic there is nothing to sharpen,
    # and the two-clause phrasing below would print the same numbers twice —
    # which reads as a bug rather than as the finding that this IP carries a
    # single TLS stack.
    sharpens = (recommended["key"] != "ip"
                and (recommended["predicted_fp_pct"] != naive["predicted_fp_pct"]
                     or recommended["legit_users_affected"]
                     != naive["legit_users_affected"]))
    if sharpens:
        evidence = (
            f"blocking ip={ip} would hit {naive['legit_users_affected']} "
            f"legitimate users (predicted FP {naive['predicted_fp_pct']}%); "
            f"blocking {recommended['key']}={recommended['value']} predicts FP "
            f"{recommended['predicted_fp_pct']}% affecting "
            f"{recommended['legit_users_affected']} legitimate users")
    else:
        evidence = (
            f"no sharpening available: all traffic on ip={ip} shares one "
            f"fingerprint, so every candidate key blocks the same requests "
            f"(predicted FP {naive['predicted_fp_pct']}%, "
            f"{naive['legit_users_affected']} legitimate users affected)")
    reasoning.append(_factor("composite_key_sharpening", 0, evidence))

    score = min(100, sum(f["contribution"] for f in reasoning))
    if score >= BLOCK_AT:
        opinion, action = "MALICIOUS", "BLOCK"
    elif score >= CHALLENGE_AT:
        opinion, action = "SUSPICIOUS", "CHALLENGE"
    else:
        opinion, action = "LEGITIMATE", "ALLOW"

    # Confidence grows with the amount of decayed evidence behind the keys.
    evidence_volume = velocity + ja4_seen
    confidence = round(evidence_volume / (evidence_volume + 5.0), 2)

    return {
        "opinion": opinion,
        "score": score,
        "confidence": confidence,
        "action": action,
        "predicted_false_positive_percentage": naive["predicted_fp_pct"],
        "recommended_key": recommended["key"],
        "recommended_key_value": recommended["value"],
        "recommended_fp_pct": recommended["predicted_fp_pct"],
        "keys": profiles,
        "reasoning": reasoning,
    }

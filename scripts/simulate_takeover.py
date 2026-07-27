"""Account-takeover demo: unfamiliar-device detection.

The opposite shape from credential stuffing: 50 legitimate users each with
their OWN device fingerprint log in normally and build a device history. Then a
single attacker, holding a correct/leaked password for exactly ONE of those
accounts, logs in successfully from a device that account has never used. No
password guessing, no volume spike, no username spread -- the only tell is the
fingerprint, which is why this needs its own factor (`unfamiliar_ja4_for_user`)
instead of piggybacking on the stuffing signals.
"""

from __future__ import annotations

import requests

from common import (ENTRY, SCORING, Check, check, color, para, print_reasoning,
                    print_result, section, standalone, whoami)

N_USERS = 50
VICTIM = "victim7"  # the one account the attacker has a leaked password for
FRESH_USER = "fresh-signup-no-history"


def synthetic_ja4(i: int) -> str:
    """Shaped like a real JA4 (t13d..._hex_hex) but distinct per user."""
    return f"t13d{1500 + i:04d}h2_{i:012x}_{(0xffffff - i):012x}"


def seed_legit_population(n: int = N_USERS) -> None:
    events = [{
        "ip": f"10.{i // 250}.{i % 250}.{i % 250}",
        "ja4": synthetic_ja4(i),
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0",
        "username": f"victim{i}",
        "outcome": "success",
        "weight": 5.0,
    } for i in range(n)]
    r = requests.post(f"{SCORING}/seed", json={"events": events}, timeout=15)
    r.raise_for_status()
    print(f"  seeded {r.json()['seeded']} legitimate logins for {n} employees,")
    print(f"  each on their {color('own', 'cyan')} IP + device fingerprint")
    print(f"  {color(VICTIM, 'cyan')}'s only known device: "
          f"{color(synthetic_ja4(int(VICTIM.removeprefix('victim'))), 'cyan')}")


def run_takeover(attacker_ip: str, attacker_ja4: str) -> dict:
    section("takeover attempt: correct password, unrecognized device",
            "No guessing, no volume, no username spread. The password is "
            "right. The only anomaly is the device it arrives from.")
    print(f"  attacker presents ip={color(attacker_ip, 'cyan')}")
    print(f"                    ja4={color(attacker_ja4, 'cyan')}")
    print(f"  never seen on {VICTIM} before")
    r = requests.post(f"{ENTRY}/login",
                      json={"username": VICTIM, "password": "s3cret"},  # correct, leaked
                      verify=False, timeout=10)
    return print_result(VICTIM, r)


def show_reasoning(body: dict) -> None:
    op = body.get("opinion", {})
    tint = {"MALICIOUS": "red", "SUSPICIOUS": "yellow"}.get(op.get("opinion"), "green")
    print()
    print(f"  opinion={color(op.get('opinion'), tint)} score={op.get('score')} "
          f"action={op.get('action')} confidence={op.get('confidence')}")
    print()
    print_reasoning(op.get("reasoning", []))
    print()
    print(f"  {color('the password was correct', 'bold')} —")
    para(f"creds_ok would have allowed this login outright. Instead it was "
         f"routed to step-up MFA (CHALLENGE, not BLOCK), because {VICTIM}'s "
         f"own device history didn't include this fingerprint — a new device "
         f"isn't proof of compromise, so the login is verified further, not "
         f"rejected.", indent=4)


def contrast_same_device() -> dict:
    """The SAME attacker fingerprint on an account it has no history with is
    not penalized: the signal is account-scoped, not a device blocklist."""
    section("contrast: same device, an account it's not squatting on",
            "If the factor were a device blocklist, this would fire too. "
            "It shouldn't — the signal is scoped to the account's own history.")
    r = requests.post(f"{ENTRY}/login",
                      json={"username": FRESH_USER, "password": "wrong"},
                      verify=False, timeout=10)
    body = print_result(FRESH_USER, r)
    factors = {f["factor"] for f in body.get("opinion", {}).get("reasoning", [])}
    flagged = "unfamiliar_ja4_for_user" in factors
    print(f"  unfamiliar_ja4_for_user fired: "
          f"{color(str(flagged), 'red' if flagged else 'green')}")
    para("a device with no account history isn't penalized for lacking one.",
         indent=4)
    print()
    print(f"  {color('takeaway', 'bold')}:")
    para("the attacker's device isn't globally burned — only the specific "
         "account whose history it doesn't match gets the extra scrutiny.",
         indent=4)
    return body


def fired(body: dict, factor: str) -> bool:
    return any(f["factor"] == factor
               for f in body.get("opinion", {}).get("reasoning", []))


def verify(takeover: dict, contrast: dict) -> list[Check]:
    section("verifying the claims")
    action = takeover.get("action_enforced")
    op = takeover.get("opinion", {})
    return [
        check("the unfamiliar-device factor fires on the victim's account",
              fired(takeover, "unfamiliar_ja4_for_user"),
              f"reasoning[] contains: "
              f"{sorted(f['factor'] for f in op.get('reasoning', []))}"),
        check("a correct password from an unknown device is CHALLENGED, not allowed",
              action == "CHALLENGE",
              f"action_enforced={action} at score {op.get('score')} — "
              f"the password was valid, so a naive check would have let it through"),
        # Phrased from the observed action rather than the server's thresholds:
        # hardcoding "clears 40, under 75" would print a confident falsehood if
        # they were ever retuned.
        check("...and not hard-BLOCKED either — a new device isn't proof of compromise",
              action != "BLOCK",
              f"score {op.get('score')} produced {action}, so an unrecognized "
              f"device on a valid login routes to step-up MFA rather than a "
              f"hard reject"),
        check("the same device is NOT penalized on an account with no history",
              not fired(contrast, "unfamiliar_ja4_for_user"),
              f"unfamiliar_ja4_for_user absent for {FRESH_USER} — the factor "
              f"is account-scoped, not a global device blocklist"),
    ]


def main() -> list[Check]:
    me = whoami()
    attacker_ip, attacker_ja4 = me["client_ip"], me["ja4"]
    section("setup",
            "50 legitimate employees, each with their own IP and device "
            "fingerprint, build an account-level login history.")
    seed_legit_population()
    takeover = run_takeover(attacker_ip, attacker_ja4)
    show_reasoning(takeover)
    contrast = contrast_same_device()
    return verify(takeover, contrast)


if __name__ == "__main__":
    standalone(main)

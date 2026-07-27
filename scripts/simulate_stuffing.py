"""Credential stuffing and composite-key sharpening.

Asks the backend which client IP + JA4 our TLS stack presents, seeds a
legitimate corporate-NAT population on THAT SAME IP, then runs a stuffing burst
— one stack, one IP, many victim usernames, wrong passwords — through the real
TLS pipeline. Naive `ip` blocking would nuke the legitimate employees; `ip+ja4`
isolates the attacker cleanly.
"""

from __future__ import annotations

import requests

from common import (CHROME_UA, ENTRY, SCORING, Check, check, color, glyph,
                    para, print_reasoning, print_result, section, standalone,
                    table, whoami)

# Browser-shaped JA4s standing in for a corporate fleet sharing the NAT IP.
FLEET_JA4S = [
    "t13d1516h2_8daaf6152771_02713d6af862",
    "t13d1715h2_5b57614c22b0_3d5424432f57",
    "t13d1517h2_02713d6af862_8daaf6152771",
]

N_LEGIT_USERS = 200


def seed_corporate_nat(ip: str, n_users: int = N_LEGIT_USERS) -> None:
    events = [{
        "ip": ip,
        "ja4": FLEET_JA4S[i % len(FLEET_JA4S)],
        "ua": CHROME_UA,
        "username": f"employee{i}",
        "outcome": "success",
        "weight": 3.0,
    } for i in range(n_users)]
    r = requests.post(f"{SCORING}/seed", json={"events": events}, timeout=15)
    r.raise_for_status()
    print(f"  seeded {r.json()['seeded']} legitimate logins for {n_users} "
          f"employees sharing NAT IP {color(ip, 'cyan')}")


def run_stuffing(n: int = 40) -> tuple[int, dict[str, int]]:
    """Fire the burst and record where the enforced verdict first changed."""
    section("stuffing burst",
            f"{n} usernames, one TLS stack, one IP, all wrong passwords. "
            f"Watch the enforced verdict escalate as the composite key heats up.")
    blocked = 0
    first_seen: dict[str, int] = {}
    previous = None
    for i in range(n):
        r = requests.post(f"{ENTRY}/login",
                          json={"username": f"victim{i}", "password": "wrong-guess"},
                          headers={"User-Agent": CHROME_UA},  # spoofed Chrome UA
                          verify=False, timeout=10)
        action = r.json().get("action_enforced", "?")
        if action == "BLOCK":
            blocked += 1
        first_seen.setdefault(action, i)
        # First request, every verdict change, and the last one — short output
        # that still can't hide an escalation.
        if i == 0 or action != previous or i == n - 1:
            if previous is not None and action != previous:
                print(color(f"     {glyph('down')} verdict escalated at "
                            f"request #{i}", "dim"))
            print_result(f"victim{i}", r)
        previous = action

    print()
    print(f"  {blocked}/{n} requests blocked live as the reputation heated up.")
    order = [a for a in ("ALLOW", "CHALLENGE", "BLOCK") if a in first_seen]
    if len(order) > 1:
        path = color(f" {glyph('arrow')} ", "dim").join(
            f"{a}@#{first_seen[a]}" for a in sorted(order, key=lambda a: first_seen[a]))
        print(f"  verdict path: {path}")
    return blocked, first_seen


def show_opinion(ip: str, ja4: str) -> dict:
    # Score against the SAME attacker ip+ja4 the burst hit, so this reflects
    # the accumulated attack state rather than a fresh key.
    section("DetectionOpinion for the attacker's ip+ja4",
            "Every point of the score traces to a named factor and its evidence.")
    r = requests.post(f"{SCORING}/score",
                      json={"ip": ip, "ja4": ja4, "ua": CHROME_UA,
                            "username": "victim-probe"},
                      timeout=5)
    op = r.json()
    tint = {"MALICIOUS": "red", "SUSPICIOUS": "yellow"}.get(op["opinion"], "green")
    print(f"  opinion={color(op['opinion'], tint)} score={op['score']} "
          f"action={op['action']} confidence={op['confidence']}")
    print()
    print_reasoning(op["reasoning"])

    section("composite-key sharpening",
            "The same attack, keyed 2 ways. The key you choose to block "
            "on decides how many bystanders you take out with it.")
    rows, tints = [], {}
    for idx, kc in enumerate(("ip", "ip+ja4")):
        p = op["keys"][kc]
        rows.append([kc, f"{p['predicted_fp_pct']}%",
                     str(p["legit_users_affected"]),
                     str(p["decayed_attempts"]), str(p["decayed_failures"])])
        tints[idx] = "red" if kc == "ip" else "green"
    table(["KEY", "PREDICTED FP", "LEGIT USERS HIT", "ATTEMPTS", "FAILURES"],
          rows, tints)

    print()
    print(f"  {color('RECOMMENDATION', 'bold')}: block "
          f"{color(op['recommended_key'], 'green')}"
          f" (predicted FP {op['recommended_fp_pct']}%)")
    para(f"{op['recommended_key_value']}", indent=6)
    para(f"NOT ip — predicted FP "
         f"{op['predicted_false_positive_percentage']}%, "
         f"{op['keys']['ip']['legit_users_affected']} real users hit.", indent=6)
    return op


def verify(op: dict, blocked: int) -> list[Check]:
    section("verifying the claims")
    ip_key, sharp_key = op["keys"]["ip"], op["keys"]["ip+ja4"]
    return [
        check("the scorer reaches a MALICIOUS verdict on the attacker's key",
              op["opinion"] == "MALICIOUS",
              f"opinion={op['opinion']} score={op['score']} action={op['action']}"),
        check("blocking the naive `ip` key would hit the whole NAT population",
              ip_key["legit_users_affected"] >= N_LEGIT_USERS
              and ip_key["predicted_fp_pct"] > 50,
              f"predicted FP {ip_key['predicted_fp_pct']}%, "
              f"{ip_key['legit_users_affected']} legitimate users affected"),
        check("the sharper `ip+ja4` key isolates the attacker with no collateral",
              sharp_key["predicted_fp_pct"] == 0.0
              and sharp_key["legit_users_affected"] == 0,
              f"predicted FP {sharp_key['predicted_fp_pct']}%, "
              f"{sharp_key['legit_users_affected']} legitimate users affected"),
        check("the service recommends the sharp key, not the naive one",
              op["recommended_key"] == "ip+ja4" and op["recommended_fp_pct"] == 0.0,
              f"recommended={op['recommended_key']} at "
              f"{op['recommended_fp_pct']}% FP"),
        check("enforcement actually engaged mid-burst",
              blocked > 0,
              f"{blocked} requests were blocked live during the burst"),
    ]


def main() -> list[Check]:
    me = whoami()
    ip, ja4 = me["client_ip"], me["ja4"]
    section("setup",
            "Seed a corporate NAT with 200 real employees on the same IP our "
            "own traffic arrives from, so the collateral damage is measured "
            "against live traffic rather than fabricated end to end.")
    print(f"  live traffic presents ip={color(ip, 'cyan')} ja4={color(ja4, 'cyan')}")
    seed_corporate_nat(ip)
    blocked, _ = run_stuffing()
    op = show_opinion(ip, ja4)
    return verify(op, blocked)


if __name__ == "__main__":
    standalone(main)

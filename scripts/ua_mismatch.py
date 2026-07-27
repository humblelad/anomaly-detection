"""The User-Agent lies, the TLS handshake doesn't.

Same python-requests client sends two requests that are byte-identical at the
HTTP layer except for the User-Agent header — one honest, one claiming to be
Chrome. Both produce the SAME JA4, because the TLS stack is the same, and the
scoring service flags the Chrome claim as a spoof.

The lie alone is worth 35 points, deliberately below CHALLENGE_AT (40): a
UA/JA4 contradiction is corroborating evidence, not proof, since
TLS-terminating corporate proxies and SDKs that hardcode a browser UA both
produce it honestly. The final phase shows what the factor is *for* — the same
spoofer starts guessing passwords, and those 35 points become the margin that
turns a CHALLENGE into a BLOCK, while the honest-UA control runs the identical
burst and never gets there.
"""

from __future__ import annotations

import requests

from common import (CHROME_UA, ENTRY, SCORING, Check, check, color, glyph,
                    para, print_reasoning, print_result, reset_scoring,
                    section, standalone)

HONEST_UA = "python-requests/2.31.0"
# The account the honest logins authenticate to, establishing the association.
OWNER = "victim0"
# The burst targets a *different* account and every attempt fails, which
# matters: the UA association is reinforced only by successful logins, so a
# spoofed login that succeeds would teach the store that 'chrome' is normal for
# this JA4 and dilute the factor under test.
TARGET = "victim1"
# Enough failed guesses to carry velocity + failure_ratio past BLOCK_AT (75)
# once the mismatch's 35 points are added, while the honest-UA control with the
# same burst lands at CHALLENGE.
N_GUESSES = 18


def establish_association() -> str | None:
    """Log in honestly a few times so the scorer learns this JA4 == python."""
    section("establishing the honest association",
            "A handful of truthful python-requests logins, so the scorer "
            "learns which User-Agent this TLS fingerprint normally carries.")
    ja4 = None
    authenticated = None
    for _ in range(5):
        r = requests.post(f"{ENTRY}/login",
                          json={"username": OWNER, "password": "s3cret"},
                          headers={"User-Agent": HONEST_UA},
                          verify=False, timeout=10)
        body = r.json()
        ja4 = body.get("ja4", ja4)
        authenticated = body.get("authenticated")
    print(f"  learned JA4 for this stack: {color(ja4 or '?', 'cyan')}")
    print(f"  (last login authenticated={authenticated})")
    return ja4


def show_ua_association(ja4: str) -> None:
    r = requests.get(f"{SCORING}/state", params={"ip": "", "ja4": ja4}, timeout=5)
    assoc = r.json().get("ua_association", {})
    print(f"  scorer's UA association for this JA4: {assoc}")


def fired(body: dict, factor: str) -> bool:
    return any(f["factor"] == factor
               for f in body.get("opinion", {}).get("reasoning", []))


def score_of(body: dict) -> int:
    return body.get("opinion", {}).get("score", 0)


def guess_burst(ua: str, label: str, n: int = N_GUESSES) -> dict:
    """Fire `n` wrong-password attempts at one account under the given UA.

    One account, not many, so `username_spread` stays silent and this doesn't
    replay the stuffing demo: the escalation comes from velocity + failure
    ratio, with the mismatch as a constant 35-point margin on top.
    """
    last: dict = {}
    previous = None
    for i in range(n):
        r = requests.post(f"{ENTRY}/login",
                          json={"username": TARGET, "password": f"guess-{i}"},
                          headers={"User-Agent": ua},
                          verify=False, timeout=10)
        last = r.json()
        action = last.get("action_enforced", "?")
        if i == 0 or action != previous or i == n - 1:
            if previous is not None and action != previous:
                print(color(f"     {glyph('down')} verdict escalated at "
                            f"attempt #{i} (score {score_of(last)})", "dim"))
            print_result(f"{label} #{i}", r)
        previous = action
    return last


def escalation() -> tuple[dict, dict]:
    """Run the same password-guessing burst twice — spoofed UA, then honest —
    and let the enforced verdicts diverge."""
    # The spoofed one-off in main() used the real password and therefore
    # *succeeded*, teaching the store that 'chrome' is a legitimate family for
    # this JA4 and pushing claimed_share past the 10% gate. Reset so the burst
    # is scored against a cleanly, honestly-earned association.
    reset_scoring()
    establish_association()
    section("the spoofer starts guessing passwords",
            f"Same client, same fake Chrome UA, now {N_GUESSES} wrong "
            f"passwords against {TARGET}. The mismatch stops being a note "
            f"in the audit trail and becomes the margin that blocks.")
    spoofed = guess_burst(CHROME_UA, "spoofed")
    print()
    print_reasoning(spoofed.get("opinion", {}).get("reasoning", []))

    reset_scoring()
    establish_association()
    section("control: the identical burst, told honestly",
            f"Byte-for-byte the same {N_GUESSES} failed logins from the same "
            f"stack against the same account — but the User-Agent tells the "
            f"truth, so ua_ja4_mismatch cannot fire. Nothing else changes.")
    honest = guess_burst(HONEST_UA, "honest")
    print()
    print_reasoning(honest.get("opinion", {}).get("reasoning", []))
    return spoofed, honest


def main() -> list[Check]:
    ja4 = establish_association()
    if ja4:
        show_ua_association(ja4)

    section("same TLS stack, two different User-Agent claims",
            "Only the User-Agent header changes between these two requests. "
            "The TLS handshake is byte-for-byte the same stack.")
    print("  honest request (UA: python-requests):")
    r1 = requests.post(f"{ENTRY}/login",
                       json={"username": "victim0", "password": "s3cret"},
                       headers={"User-Agent": HONEST_UA},
                       verify=False, timeout=10)
    b1 = print_result("honest-python", r1)

    print("\n  spoofed request (UA claims Chrome, TLS stack unchanged):")
    r2 = requests.post(f"{ENTRY}/login",
                       json={"username": "victim0", "password": "s3cret"},
                       headers={"User-Agent": CHROME_UA},
                       verify=False, timeout=10)
    b2 = print_result("spoofed-chrome", r2)

    print()
    print(f"  {color('key point:', 'cyan')}")
    para(f"both requests carry JA4 {b1.get('ja4', '?')} — identical, because "
         f"the TLS stack is identical. The UA header changed; the fingerprint "
         f"could not.", indent=4)
    spoof_factors = [f for f in b2.get("opinion", {}).get("reasoning", [])
                     if f["factor"] == "ua_ja4_mismatch"]
    if spoof_factors:
        print(f"  {color('detected:', 'red')}")
        para(spoof_factors[0]["evidence"], indent=4)

    spoofed_burst, honest_burst = escalation()

    print()
    print(f"  {color('key point:', 'cyan')}")
    para(f"identical traffic, two verdicts: the spoofed run scored "
         f"{score_of(spoofed_burst)} ({spoofed_burst.get('action_enforced')}), "
         f"the honest run {score_of(honest_burst)} "
         f"({honest_burst.get('action_enforced')}). The 35 points that could "
         f"not enforce anything on their own are exactly the margin that "
         f"crosses BLOCK_AT once real suspicion stacks underneath them. "
         f"Lying about the User-Agent is what got this client blocked.", indent=4)

    section("verifying the claims")
    honest_ja4, spoof_ja4 = b1.get("ja4"), b2.get("ja4")
    spoof_score, honest_score = score_of(spoofed_burst), score_of(honest_burst)
    spoof_action = spoofed_burst.get("action_enforced")
    honest_action = honest_burst.get("action_enforced")
    return [
        check("the fingerprint is unchanged by the User-Agent claim",
              honest_ja4 is not None and honest_ja4 == spoof_ja4,
              f"honest={honest_ja4} spoofed={spoof_ja4}"),
        check("the spoofed Chrome claim is flagged as a UA/JA4 mismatch",
              fired(b2, "ua_ja4_mismatch"),
              spoof_factors[0]["evidence"] if spoof_factors
              else "ua_ja4_mismatch did not fire on the spoofed request"),
        check("the honest request is not flagged",
              not fired(b1, "ua_ja4_mismatch"),
              "no ua_ja4_mismatch on the truthful python-requests UA — the "
              "factor keys on the contradiction, not on the fingerprint"),
        check("the mismatch alone does not enforce anything",
              b2.get("action_enforced") == "ALLOW",
              f"the spoofed one-off scored {score_of(b2)} and was "
              f"{b2.get('action_enforced')} — 35 points sits below "
              f"CHALLENGE_AT (40) by design, so a spoofed UA on clean traffic "
              f"is recorded rather than acted on"),
        check("the spoofer guessing passwords escalates to a hard BLOCK",
              spoof_action == "BLOCK",
              f"after {N_GUESSES} failed guesses under the fake Chrome UA: "
              f"score={spoof_score} action={spoof_action}"),
        check("the identical burst told honestly stays below BLOCK",
              honest_action != "BLOCK",
              f"same stack, same account, same {N_GUESSES} failures, truthful "
              f"UA: score={honest_score} action={honest_action}"),
        check("the lie is the whole difference between the two verdicts",
              spoof_action == "BLOCK" and honest_action != "BLOCK"
              and spoof_score - honest_score == 35,
              f"spoofed {spoof_score} ({spoof_action}) vs honest "
              f"{honest_score} ({honest_action}) — a {spoof_score - honest_score}"
              f"-point gap, exactly the ua_ja4_mismatch contribution, on "
              f"traffic that is otherwise byte-identical below the UA header"),
    ]


if __name__ == "__main__":
    standalone(main)

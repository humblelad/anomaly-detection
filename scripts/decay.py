"""Verdicts are impermanent: watching EWMA reputation decay.

A verdict ages out — an IP seen attacking an hour ago matters much less than
one attacking now, because residential IPs churn and punishing yesterday's
address forever means punishing whoever holds it today. The other scenarios run
in seconds, so against half-lives measured in hours that decay is real but
invisible: a two-second burst ages by a factor of roughly 0.9996.

This scenario makes it visible by asking the service to fast-forward its own
clock (POST /clock) rather than by shrinking the half-lives, so the numbers on
screen come from the same constants a real deployment runs — the real curve,
just sampled at timestamps we chose.

  1. run a stuffing burst until the attacker's key scores MALICIOUS,
  2. advance the clock through checkpoints, reading the decayed counters,
  3. re-score at each one and watch the verdict walk back down.

The attacker never sends another packet after step 1.
"""

from __future__ import annotations

import requests

from common import (CHROME_UA, ENTRY, SCORING, Check, advance_clock, check,
                    color, fmt_duration, half_lives, para, print_reasoning,
                    section, standalone, table, whoami)

N_GUESSES = 30


def checkpoints() -> list[float]:
    """Elapsed timestamps to sample, derived from the service's own tuning.

    Anchored on the two half-lives this scenario narrates — `behavior` (the
    failure counter) and `ip+ja4` (attempts) — so the table lands exactly on
    one half-life of each and reads a clean 50%. Derived rather than
    hardcoded, since retuning HALF_LIVES would otherwise leave the checkpoints
    sampling meaningless points on the curve while every ratio-based assertion
    still passed.
    """
    hl = half_lives()
    behavior, composite = hl["behavior"], hl["ip+ja4"]
    # The tail: 23x the composite half-life is ~2^-23, i.e. nothing survives.
    return sorted({behavior, composite, 3 * composite,
                   7 * composite, 23 * composite})


def run_burst(n: int = N_GUESSES) -> None:
    """Heat up one ip+ja4 until it scores MALICIOUS."""
    section("t=0: the attack",
            f"{n} failed logins from one TLS stack across {n} usernames — the "
            f"same credential-stuffing shape as scenario 1, run just long "
            f"enough to earn a hard verdict.")
    for i in range(n):
        requests.post(f"{ENTRY}/login",
                      json={"username": f"victim{i}", "password": "wrong-guess"},
                      headers={"User-Agent": CHROME_UA},
                      verify=False, timeout=10)
    print(f"  fired {n} failed logins; the attacker now goes quiet and sends "
          f"nothing further.")


def score(ip: str, ja4: str) -> dict:
    r = requests.post(f"{SCORING}/score",
                      json={"ip": ip, "ja4": ja4, "ua": CHROME_UA,
                            "username": "probe"},
                      timeout=5)
    r.raise_for_status()
    return r.json()


def read_state(ip: str, ja4: str) -> dict:
    """Read the decayed counters WITHOUT recording an attempt.

    /score records an attempt on every candidate key, so polling it at each
    checkpoint would keep feeding the counters this scenario is watching fade.
    /state is a pure read.
    """
    r = requests.get(f"{SCORING}/state", params={"ip": ip, "ja4": ja4}, timeout=5)
    r.raise_for_status()
    return r.json()["keys"]["ip+ja4"]


def decay_table(ip: str, ja4: str) -> list[dict]:
    """Advance the clock through the checkpoints, sampling at each."""
    section("the attacker goes quiet; the clock runs on",
            "No further requests from this stack. Each row is the same key "
            "read at a later timestamp — the counters decay on read, so this "
            "is the reputation forgetting, not a new observation.")

    samples = [{"elapsed": 0.0, **read_state(ip, ja4)}]
    clock = 0.0
    for target in checkpoints():
        # checkpoints() yields absolute elapsed times; the clock advances by
        # deltas. Exponentials compose, so hopping lands where one jump would.
        advance_clock(target - clock)
        clock = target
        samples.append({"elapsed": target, **read_state(ip, ja4)})

    peak_att = samples[0]["decayed_attempts"] or 1.0
    peak_fail = samples[0]["decayed_failures"] or 1.0
    rows, tints = [], {}
    for idx, s in enumerate(samples):
        rows.append([
            f"+{fmt_duration(s['elapsed'])}",
            f"{s['decayed_attempts']:.2f}",
            f"{100 * s['decayed_attempts'] / peak_att:.0f}%",
            f"{s['decayed_failures']:.2f}",
            f"{100 * s['decayed_failures'] / peak_fail:.0f}%",
            str(s["distinct_usernames_attempted"]),
        ])
        # Tint the fade: full-strength at the top, forgotten at the bottom.
        share = s["decayed_attempts"] / peak_att
        tints[idx] = "red" if share > 0.66 else ("yellow" if share > 0.25 else "green")
    table(["ELAPSED", "ATTEMPTS", "OF PEAK", "FAILURES", "OF PEAK", "USERNAMES"],
          rows, tints)

    print()
    hl = half_lives()
    para(f"attempts on ip+ja4 carry a {fmt_duration(hl['ip+ja4'])} half-life; "
         f"failures carry the {fmt_duration(hl['behavior'])} behavioral one. "
         f"Failures fade faster by design — a burst of wrong passwords is a "
         f"statement about this minute, while the volume of traffic from a "
         f"stack is a slower-moving fact about it.", indent=2)
    return samples


def verdict_walk(ip: str, ja4: str) -> list[dict]:
    """Re-score after the store has aged, and show the verdict come back down.

    Scored last, after the counter table, because /score records an attempt:
    doing it inline at every checkpoint would inflate the curve the table plots.
    """
    section("the verdict follows the counters down",
            "The same key, scored again now that the store has aged. Nothing "
            "about the attacker changed — only how much of its traffic the "
            "service still remembers.")
    op = score(ip, ja4)
    tint = {"MALICIOUS": "red", "SUSPICIOUS": "yellow"}.get(op["opinion"], "green")
    print(f"  opinion={color(op['opinion'], tint)} score={op['score']} "
          f"action={op['action']} confidence={op['confidence']}")
    print()
    print_reasoning(op["reasoning"])
    return op


def verify(hot: dict, samples: list[dict], cold: dict) -> list[Check]:
    section("verifying the claims")
    first, last = samples[0], samples[-1]
    composite_hl = half_lives()["ip+ja4"]
    half = next((s for s in samples
                 if abs(s["elapsed"] - composite_hl) < 1), None)
    # A band rather than equality: the burst itself takes a second or two of
    # real time, so the counter was already aging before the clock moved.
    halved_ok = (half is not None
                 and 0.45 <= half["decayed_attempts"] / first["decayed_attempts"] <= 0.55)
    monotonic = all(b["decayed_attempts"] <= a["decayed_attempts"] + 1e-9
                    for a, b in zip(samples, samples[1:]))
    return [
        check("the burst earns a hard verdict while it is happening",
              hot["opinion"] == "MALICIOUS" and hot["action"] == "BLOCK",
              f"at t=0: opinion={hot['opinion']} score={hot['score']} "
              f"action={hot['action']}"),
        check("decayed counters fall monotonically as the clock advances",
              monotonic,
              "attempts on ip+ja4 across checkpoints: "
              + " ".join(f"+{fmt_duration(s['elapsed'])}={s['decayed_attempts']:.2f}"
                         for s in samples)),
        check(f"one half-life ({fmt_duration(composite_hl)}) halves the "
              f"ip+ja4 attempts counter",
              halved_ok,
              f"{first['decayed_attempts']:.2f} at t=0 -> "
              f"{half['decayed_attempts']:.2f} at "
              f"+{fmt_duration(composite_hl)} "
              f"({100 * half['decayed_attempts'] / first['decayed_attempts']:.0f}% "
              f"of peak; the half-life predicts 50%)"
              if half else
              f"no checkpoint was sampled at one half-life "
              f"({fmt_duration(composite_hl)})"),
        check("the reputation eventually decays to near nothing",
              last["decayed_attempts"] < 0.05 * first["decayed_attempts"],
              f"after +{fmt_duration(last['elapsed'])}: "
              f"{last['decayed_attempts']:.2f} decayed attempts, down from "
              f"{first['decayed_attempts']:.2f} — "
              f"{100 * last['decayed_attempts'] / first['decayed_attempts']:.1f}% "
              f"of peak"),
        check("the verdict itself reverts — an aged attacker is not still blocked",
              cold["score"] < hot["score"] and cold["action"] != "BLOCK",
              f"{hot['score']} ({hot['action']}) at t=0 -> {cold['score']} "
              f"({cold['action']}) after the store aged. The attacker sent "
              f"nothing in between; only time passed"),
    ]


def main() -> list[Check]:
    me = whoami()
    ip, ja4 = me["client_ip"], me["ja4"]
    section("setup",
            "One attacker stack, no legitimate population to protect — this "
            "scenario is about the lifetime of a verdict, not its blast "
            "radius.")
    print(f"  attacker presents ip={color(ip, 'cyan')} ja4={color(ja4, 'cyan')}")

    run_burst()
    hot = score(ip, ja4)
    tint = {"MALICIOUS": "red", "SUSPICIOUS": "yellow"}.get(hot["opinion"], "green")
    print(f"  scored while hot: opinion={color(hot['opinion'], tint)} "
          f"score={hot['score']} action={hot['action']}")

    samples = decay_table(ip, ja4)
    cold = verdict_walk(ip, ja4)

    print()
    print(f"  {color('key point:', 'cyan')}")
    para(f"the same key scored {hot['score']} ({hot['action']}) during the "
         f"burst and {cold['score']} ({cold['action']}) once the store had "
         f"aged, with no intervening traffic. A blocklist would still be "
         f"holding this IP. The EWMA store lets it back in on its own, which "
         f"is what makes a wrong verdict survivable: nothing here is a "
         f"permanent judgement, so the cost of a false positive is bounded by "
         f"a half-life rather than by someone noticing and clearing an entry.",
         indent=4)

    return verify(hot, samples, cold)


if __name__ == "__main__":
    standalone(main)

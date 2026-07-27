"""Runs every scenario end to end against a live docker compose stack.

    python scripts/run_demo.py
    python scripts/run_demo.py --step        # pause between scenarios (live narration)
    python scripts/run_demo.py --pace 1.5    # or just slow it down
    python scripts/run_demo.py --no-color    # plain text, e.g. when piping to a file

If the stack isn't up you get a diagnostic naming the broken hop rather than a
traceback. Every scenario asserts the claims it narrates, so this doubles as an
integration test: the exit code is non-zero if any check fails.
"""

from __future__ import annotations

import argparse
import sys
import time

import decay
import simulate_stuffing
import simulate_takeover
import ua_mismatch
from common import (Check, StackDown, banner, color, die, disable_color, glyph,
                    preflight, reset_scoring, table, term_width)

_A = glyph("arrow")
SCENARIOS = [
    (f"credential stuffing {_A} composite-key sharpening", simulate_stuffing.main),
    (f"User-Agent spoofing {_A} the TLS fingerprint doesn't move", ua_mismatch.main),
    (f"account takeover {_A} unfamiliar device on a known account",
     simulate_takeover.main),
    (f"EWMA decay {_A} verdicts are impermanent", decay.main),
]


def scoreboard(results: list[tuple[str, list[Check]]]) -> int:
    """Final summary. Returns the number of failed checks."""
    rule = glyph("dh") * term_width()
    print()
    print(color(rule, "bold"))
    print(color("  SCOREBOARD", "bold"))
    print(color(rule, "bold"))
    print()

    rows, tints, failed = [], {}, 0
    for idx, (name, checks) in enumerate(results):
        bad = [c for c in checks if not c.passed]
        failed += len(bad)
        status = "PASS" if not bad else f"FAIL ({len(bad)})"
        rows.append([status, f"{len(checks) - len(bad)}/{len(checks)}", name])
        tints[idx] = "green" if not bad else "red"
    table(["", "CHECKS", "SCENARIO"], rows, tints)

    print()
    for _, checks in results:
        for c in checks:
            if not c.passed:
                print(f"  {color(glyph('bad'), 'red')} {c.claim}")
                print(color(f"      {c.detail}", "red"))
    if failed:
        print()
        print(color(f"  {failed} check(s) failed — the demo did not reproduce "
                    f"its own claims.", "red"))
    else:
        total = sum(len(c) for _, c in results)
        print(color(f"  all {total} checks passed across "
                    f"{len(results)} scenarios.", "green"))
    print()
    return failed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pace", type=float, default=0.0, metavar="SECONDS",
                    help="pause between scenarios, for narrating live")
    ap.add_argument("--step", action="store_true",
                    help="wait for Enter between scenarios")
    ap.add_argument("--no-color", action="store_true",
                    help="disable ANSI color (also honours NO_COLOR)")
    args = ap.parse_args()
    if args.no_color:
        disable_color()

    try:
        preflight()
    except StackDown as e:
        die(e)

    results: list[tuple[str, list[Check]]] = []
    for i, (title, run) in enumerate(SCENARIOS):
        if i:
            if args.step:
                try:
                    input(color("\n  [enter] next scenario ", "dim"))
                except (EOFError, KeyboardInterrupt):
                    print()
                    return 130
            elif args.pace:
                time.sleep(args.pace)
        # Each scenario seeds its own population and expects a cold store.
        reset_scoring()
        banner(f"{i + 1}/{len(SCENARIOS)}  {title}")
        results.append((title, run()))

    return 1 if scoreboard(results) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        sys.exit(130)

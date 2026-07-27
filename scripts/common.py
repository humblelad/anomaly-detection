"""Shared helpers for the demo scripts: preflight, terminal formatting, and the
self-check mechanism each scenario uses to assert its own claims.

The demo doubles as an end-to-end integration test — a regression shows up as a
red ✗ and a non-zero exit code rather than as confidently-printed wrong numbers.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path

import requests
import urllib3

# The sidecar presents a self-signed cert; the demo is about the TLS
# fingerprint, not PKI trust.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ENTRY = os.environ.get("ENTRY", "https://localhost:8443")
SCORING = os.environ.get("SCORING", "http://localhost:9100")

CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


def _init_stdout() -> bool:
    """Make stdout UTF-8 if we can, and report whether it can render the box
    glyphs. A redirected stdout on Windows defaults to cp1252, which cannot
    encode '→' or '╔', so `python run_demo.py > out.txt` would otherwise die
    with UnicodeEncodeError mid-demo.
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "─│┌┐└┘├┤╔╗╚╝║═✓✗→↓·…".encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


_UNICODE = _init_stdout()

_G = {
    "h": "─", "v": "│", "tl": "┌", "tr": "┐", "bl": "└", "br": "┘",
    "lt": "├", "rt": "┤", "dh": "═", "dv": "║",
    "dtl": "╔", "dtr": "╗", "dbl": "╚", "dbr": "╝",
    "ok": "✓", "bad": "✗", "arrow": "→", "down": "↓", "dot": "·", "ell": "…",
} if _UNICODE else {
    "h": "-", "v": "|", "tl": "+", "tr": "+", "bl": "+", "br": "+",
    "lt": "+", "rt": "+", "dh": "=", "dv": "|",
    "dtl": "+", "dtr": "+", "dbl": "+", "dbr": "+",
    "ok": "PASS", "bad": "FAIL", "arrow": "->", "down": "v", "dot": ".",
    "ell": "...",
}


def glyph(name: str) -> str:
    return _G[name]


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):  # https://no-color.org
        return False
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        # Windows Terminal handles ANSI natively; legacy conhost needs VT
        # processing switched on explicitly, and if that fails we're on a
        # console that would render escapes literally.
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(kernel32.SetConsoleMode(
                handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        except Exception:
            return False
    return True


_COLOR = _supports_color()

_CODES = {"green": 32, "red": 31, "yellow": 33, "cyan": 36, "grey": 90,
          "bold": 1, "dim": 2}


def disable_color() -> None:
    global _COLOR
    _COLOR = False


def color(s: str, c: str) -> str:
    if not _COLOR:
        return s
    return f"\033[{_CODES[c]}m{s}\033[0m"


def _visible_len(s: str) -> int:
    """Width of a string as rendered, ignoring ANSI escape sequences."""
    out, i = 0, 0
    while i < len(s):
        if s[i] == "\033":
            while i < len(s) and s[i] != "m":
                i += 1
            i += 1
        else:
            out += 1
            i += 1
    return out


def _pad(s: str, width: int) -> str:
    """Left-justify, accounting for escape codes that str.ljust counts as
    content and so under-pads colored cells by."""
    return s + " " * max(0, width - _visible_len(s))


def term_width(default: int = 80) -> int:
    return min(shutil.get_terminal_size((default, 24)).columns, 100)


def banner(title: str) -> None:
    w = term_width()
    dh, dv = _G["dh"], _G["dv"]
    print()
    print(color(_G["dtl"] + dh * (w - 2) + _G["dtr"], "bold"))
    print(color(f"{dv} " + title.ljust(w - 4) + f" {dv}", "bold"))
    print(color(_G["dbl"] + dh * (w - 2) + _G["dbr"], "bold"))


def section(title: str, claim: str = "") -> None:
    """Section header that opens with the claim about to be tested, so each
    block reads as a hypothesis and its result rather than a dump."""
    h = _G["h"]
    print()
    print(color(f"{h * 2} {title} " + h * max(0, term_width() - len(title) - 4),
                "bold"))
    if claim:
        for line in textwrap.wrap(claim, term_width() - 6):
            print(color(f"   {line}", "dim"))
        print()


def para(text: str, indent: int = 2) -> None:
    """Wrap a prose paragraph to the terminal. Callers pass plain text and let
    this add emphasis, since ANSI codes break the measurement."""
    for line in textwrap.wrap(text, term_width() - indent,
                              break_on_hyphens=False):
        print(" " * indent + line)


def table(headers: list[str], rows: list[list[str]],
          tints: dict[int, str] | None = None) -> None:
    """Column-aligned table. `tints` maps row index -> color name, applied to
    the row's first cell so the eye lands on the relevant key."""
    tints = tints or {}
    widths = [max([_visible_len(h)] + [_visible_len(r[i]) for r in rows])
              for i, h in enumerate(headers)]
    print("  " + color("  ".join(_pad(h, w)
                                 for h, w in zip(headers, widths)).rstrip(),
                       "dim"))
    for idx, row in enumerate(rows):
        cells = list(row)
        if idx in tints:
            cells[0] = color(cells[0], tints[idx])
        print("  " + "  ".join(_pad(c, w)
                               for c, w in zip(cells, widths)).rstrip())


def print_reasoning(factors: list[dict]) -> None:
    """Render a DetectionOpinion's reasoning[] audit trail."""
    print(color("  reasoning[]:", "cyan"))
    indent = " " * 10
    width = term_width()
    for f in factors:
        mark = f"+{f['contribution']}" if f["contribution"] else f" {_G['dot']}"
        head = f"  {mark:>4}  {color(f['factor'], 'yellow')}: "
        # Wrap against a placeholder the width of the header, then strip it
        # back off, so the first line accounts for the factor name in front of
        # it instead of overrunning the terminal by the header's width.
        lead = " " * _visible_len(head)
        body = textwrap.wrap(f["evidence"], max(40, width),
                             initial_indent=lead, subsequent_indent=indent,
                             break_on_hyphens=False)
        if not body:
            print(head)
            continue
        print(head + body[0][len(lead):])
        for line in body[1:]:
            print(line)


def abbrev_ja4(ja4: str | None, keep_head: int = 14, keep_tail: int = 6) -> str:
    """Middle-elide a JA4 so a result row fits in 80 columns. Equal
    fingerprints still render equal, so the "same stack, different UA"
    comparison survives abbreviation."""
    if not ja4:
        return "?"
    if len(ja4) <= keep_head + keep_tail + 1:
        return ja4
    return f"{ja4[:keep_head]}{_G['ell']}{ja4[-keep_tail:]}"


def print_result(label: str, r) -> dict:
    body = r.json()
    action = body.get("action_enforced", "?")
    tint = {"ALLOW": "green", "CHALLENGE": "yellow", "BLOCK": "red"}.get(action, "grey")
    ja4 = abbrev_ja4(body.get("ja4"))
    print(f"  {label:<23} {r.status_code:>3}  ja4={ja4:<22} "
          f"{_pad(color(action, tint), 9)} auth={body.get('authenticated')}")
    return body


@dataclass
class Check:
    """One assertion the demo makes about its own output."""
    claim: str
    passed: bool
    detail: str


def check(claim: str, passed: bool, detail: str) -> Check:
    """Assert a claim, print the verdict inline, and return it for the
    scoreboard."""
    mark = (color(_G["ok"], "green") if passed else color(_G["bad"], "red"))
    print(f"  {mark} {claim}")
    for line in textwrap.wrap(detail, term_width() - 6, break_on_hyphens=False):
        print(color("      " + line, "dim" if passed else "red"))
    return Check(claim, passed, detail)


class StackDown(Exception):
    """The demo stack isn't ready. Carries the remediation, not a traceback."""

    def __init__(self, problem: str, fix: str) -> None:
        super().__init__(problem)
        self.problem = problem
        self.fix = fix


def die(exc: StackDown) -> None:
    """Print a bordered diagnostic and exit."""
    w = term_width()
    h, v = _G["h"], _G["v"]
    print()
    print(color(_G["tl"] + h * (w - 2) + _G["tr"], "red"))
    print(color(f"{v} " + "demo stack not ready".ljust(w - 4) + f" {v}", "red"))
    print(color(_G["lt"] + h * (w - 2) + _G["rt"], "red"))
    for line in textwrap.wrap(exc.problem, w - 4):
        print(color(f"{v} ", "red") + _pad(line, w - 4) + color(f" {v}", "red"))
    print(color(f"{v} ", "red") + " " * (w - 4) + color(f" {v}", "red"))
    for line in ["fix:"] + ["  " + ln for ln in exc.fix.split("\n")]:
        for wrapped in textwrap.wrap(line, w - 4,
                                     subsequent_indent="    ") or [""]:
            print(color(f"{v} ", "red") + _pad(color(wrapped, "yellow"), w - 4)
                  + color(f" {v}", "red"))
    print(color(_G["bl"] + h * (w - 2) + _G["br"], "red"))
    print()
    sys.exit(1)


BUILD_AND_UP = ("scripts/build_wasm.sh   (Windows: scripts\\build_wasm.ps1)\n"
                "docker compose up --build")


def preflight() -> dict:
    """Verify the whole pipeline is up before any scenario runs, and return the
    /whoami result so callers don't pay for a second round trip.

    Both hops are probed before reporting: one dead service is a different
    problem from nothing running, and telling someone with an empty
    `docker ps` to restart a single container sends them the wrong way.
    """
    scoring_up = True
    try:
        requests.get(f"{SCORING}/healthz", timeout=3).raise_for_status()
    except requests.RequestException:
        scoring_up = False

    me = None
    try:
        r = requests.get(f"{ENTRY}/whoami", headers={"User-Agent": CHROME_UA},
                         verify=False, timeout=10)
        r.raise_for_status()
        me = r.json()
    except requests.RequestException:
        pass

    if me is None and not scoring_up:
        raise StackDown(
            f"nothing is answering at {ENTRY} or {SCORING} — the stack looks "
            f"like it isn't running at all.",
            BUILD_AND_UP)

    if me is None:
        raise StackDown(
            f"nothing is answering TLS at {ENTRY} — the ja4-sidecar, Envoy, or "
            f"the demo backend is down. Note that Envoy refuses to start if "
            f"envoy/detection_filter.wasm is missing, since it bind-mounts "
            f"that file, so a missing WASM build takes the whole entry path "
            f"down with it.",
            BUILD_AND_UP)

    if not scoring_up:
        raise StackDown(
            f"the TLS entry path is healthy but the scoring service is not "
            f"answering at {SCORING}. The demo scripts talk to it directly to "
            f"seed history and read state.",
            "docker compose up -d scoring-service")

    # Reachable but unsigned: the request crossed the sidecar and Envoy and
    # came out the far side without a JA4 — a broken trust boundary, which is
    # a different failure from "down".
    if not me.get("ja4"):
        raise StackDown(
            "the stack is reachable but /whoami returned no verified JA4, so "
            "the WASM filter is not signing X-Detection-JA4 (or the backend "
            "rejected the signature — check the HMAC_KEY matches between "
            "docker-compose.yml and envoy/envoy.yaml).",
            "scripts/build_wasm.sh && docker compose up --build --force-recreate")

    return me


def reset_scoring() -> None:
    """Restart the scoring service to clear its in-memory reputation store.

    Every scenario seeds its own population and asserts an outcome that only
    holds against a clean store — leftover velocity/failure/spread counters
    push the same login from CHALLENGE to BLOCK.

    `docker compose restart` returns before the Flask dev server inside is
    accepting connections and the old process may still be draining, so poll
    with a backoff rather than a tight loop that would burn every attempt in
    under a second and report a false failure.
    """
    subprocess.run(["docker", "compose", "restart", "scoring-service"],
                   cwd=Path(__file__).resolve().parent.parent, check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            if requests.get(f"{SCORING}/healthz", timeout=1).ok:
                return
        except requests.RequestException:
            pass
        time.sleep(0.5)
    print(color("warning: scoring service did not come back healthy", "yellow"),
          file=sys.stderr)


_HALF_LIVES: dict[str, float] | None = None


def half_lives() -> dict[str, float]:
    """The decay half-lives (seconds) the scoring service is running.

    Fetched rather than restated so retuning HALF_LIVES in ewma.py flows
    through to the prose — otherwise the demo keeps describing the old tuning
    while every ratio-based assertion still passes, because halving is halving
    whatever the half-life is.
    """
    global _HALF_LIVES
    if _HALF_LIVES is None:
        r = requests.get(f"{SCORING}/healthz", timeout=5)
        r.raise_for_status()
        _HALF_LIVES = r.json()["half_lives"]
    return _HALF_LIVES


def advance_clock(seconds: float) -> float:
    """Fast-forward the scoring service's clock, returning the total offset.

    The half-lives are measured in hours, so nothing visibly decays over the
    few seconds a demo takes; this ages the store instead of sleeping through
    it. Resets to zero whenever `reset_scoring` restarts the container.
    """
    r = requests.post(f"{SCORING}/clock", json={"advance": seconds}, timeout=5)
    r.raise_for_status()
    return r.json()["offset_seconds"]


def fmt_duration(seconds: float) -> str:
    """Compact human duration for table labels: 0m, 30m, 4h, 2d."""
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    if seconds < 24 * 3600:
        return f"{seconds / 3600:.0f}h"
    return f"{seconds / (24 * 3600):.0f}d"


def whoami(ua: str = CHROME_UA) -> dict:
    """Ask the backend what client IP and JA4 it sees for our TLS stack, so the
    demo seeds its legitimate population on the real live-traffic IP."""
    r = requests.get(f"{ENTRY}/whoami", headers={"User-Agent": ua},
                     verify=False, timeout=10)
    r.raise_for_status()
    return r.json()


def standalone(main) -> None:
    """Run one scenario directly rather than via run_demo: reset the store
    first, report preflight failure as a diagnostic rather than a traceback,
    and propagate check failures into the exit code so a single scenario is
    CI-usable on its own.
    """
    try:
        preflight()
        reset_scoring()
        checks = main()
    except StackDown as e:
        die(e)
        return
    failed = [c for c in checks if not c.passed]
    print()
    if failed:
        print(color(f"{len(failed)}/{len(checks)} checks FAILED", "red"))
        sys.exit(1)
    print(color(f"all {len(checks)} checks passed", "green"))

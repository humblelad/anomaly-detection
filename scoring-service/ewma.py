"""EWMA-decayed counters and the composite-key reputation store.

Every counter decays exponentially with a half-life chosen per signal class — a
fingerprint seen attacking yesterday still matters a little today; an IP seen
attacking an hour ago matters a lot less, because residential IPs churn.
"""

from __future__ import annotations

import time

# Half-lives per signal class (seconds):
#   ja4      — a TLS stack fingerprint is highly specific and slow to change.
#   asn      — designed for, not used in v1 (kept for the schema story).
#   ip       — volatile, especially residential/CGNAT space.
#   ip+ja4   — a composite inherits its most volatile component.
#   behavior — request cadence / failure ratios age fastest.
HALF_LIVES = {
    "ja4": 24 * 3600.0,
    "asn": 6 * 3600.0,
    "ip": 1 * 3600.0,
    "ip+ja4": 1 * 3600.0,
    "behavior": 30 * 60.0,
}

# A decayed per-user weight below this counts as "forgotten".
ACTIVE_USER_EPS = 0.05


class EwmaCounter:
    """A single exponentially decaying counter."""

    __slots__ = ("half_life", "value", "last_ts")

    def __init__(self, half_life: float):
        self.half_life = half_life
        self.value = 0.0
        self.last_ts = 0.0

    def _decayed(self, now: float) -> float:
        if self.last_ts == 0.0 or now <= self.last_ts:
            return self.value
        return self.value * 0.5 ** ((now - self.last_ts) / self.half_life)

    def observe(self, now: float | None = None, weight: float = 1.0) -> None:
        now = time.time() if now is None else now
        self.value = self._decayed(now) + weight
        self.last_ts = max(self.last_ts, now)

    def peek(self, now: float | None = None) -> float:
        now = time.time() if now is None else now
        return self._decayed(now)


class KeyStats:
    """Reputation state for one composite key value (e.g. ip+ja4=x|y)."""

    __slots__ = ("attempts", "fail", "success", "users", "legit_users")

    def __init__(self, key_class: str):
        hl = HALF_LIVES[key_class]
        behavior = HALF_LIVES["behavior"]
        self.attempts = EwmaCounter(hl)
        self.fail = EwmaCounter(behavior)
        self.success = EwmaCounter(hl)
        # username -> decaying weight. `users` tracks who was *attempted*
        # (stuffing = many usernames, one stack); `legit_users` tracks who
        # actually authenticated (the population a block would hurt).
        self.users: dict[str, EwmaCounter] = {}
        self.legit_users: dict[str, EwmaCounter] = {}

    def _bump(self, table: dict[str, EwmaCounter], username: str,
              half_life: float, now: float, weight: float) -> None:
        counter = table.get(username)
        if counter is None:
            counter = table[username] = EwmaCounter(half_life)
        counter.observe(now, weight)

    def distinct_users(self, now: float) -> int:
        return sum(1 for c in self.users.values() if c.peek(now) > ACTIVE_USER_EPS)

    def distinct_legit_users(self, now: float) -> int:
        return sum(1 for c in self.legit_users.values() if c.peek(now) > ACTIVE_USER_EPS)


class Store:
    """In-memory reputation store keyed by (key_class, key_value).

    v1 scope decision: a plain dict guarded by the caller's lock. Production
    would back this with a TTL'd cache aligned to the EWMA windows.
    """

    def __init__(self):
        self._stats: dict[tuple[str, str], KeyStats] = {}
        # ja4 -> ua_family -> decaying weight, and username -> ja4 -> decaying
        # weight. Only *successful* logins reinforce either, so an attacker
        # cannot poison an association (or an account's device history) with
        # failed traffic.
        self._ua_assoc: dict[str, dict[str, EwmaCounter]] = {}
        self._user_ja4: dict[str, dict[str, EwmaCounter]] = {}
        self.global_attempts = EwmaCounter(HALF_LIVES["ja4"])

    @staticmethod
    def candidate_keys(ip: str, ja4: str) -> list[tuple[str, str]]:
        return [("ip", ip), ("ja4", ja4), ("ip+ja4", f"{ip}|{ja4}")]

    def stats(self, key_class: str, key_value: str) -> KeyStats:
        k = (key_class, key_value)
        st = self._stats.get(k)
        if st is None:
            st = self._stats[k] = KeyStats(key_class)
        return st

    def record_attempt(self, ip: str, ja4: str, username: str,
                       now: float, weight: float = 1.0) -> None:
        self.global_attempts.observe(now, weight)
        for key_class, key_value in self.candidate_keys(ip, ja4):
            st = self.stats(key_class, key_value)
            st.attempts.observe(now, weight)
            st._bump(st.users, username, HALF_LIVES["behavior"], now, weight)

    def record_outcome(self, ip: str, ja4: str, ua_family: str, username: str,
                       outcome: str, now: float, weight: float = 1.0) -> None:
        for key_class, key_value in self.candidate_keys(ip, ja4):
            st = self.stats(key_class, key_value)
            if outcome == "success":
                st.success.observe(now, weight)
                st._bump(st.legit_users, username, HALF_LIVES[key_class], now, weight)
            else:
                st.fail.observe(now, weight)
        if outcome == "success" and ja4:
            assoc = self._ua_assoc.setdefault(ja4, {})
            counter = assoc.get(ua_family)
            if counter is None:
                counter = assoc[ua_family] = EwmaCounter(HALF_LIVES["ja4"])
            counter.observe(now, weight)
        if outcome == "success" and username and ja4:
            devices = self._user_ja4.setdefault(username, {})
            counter = devices.get(ja4)
            if counter is None:
                counter = devices[ja4] = EwmaCounter(HALF_LIVES["ja4"])
            counter.observe(now, weight)

    def ua_association(self, ja4: str, now: float) -> dict[str, float]:
        """Decayed weight per UA family historically seen with this JA4."""
        return {
            fam: w
            for fam, c in self._ua_assoc.get(ja4, {}).items()
            if (w := c.peek(now)) > ACTIVE_USER_EPS
        }

    def known_ja4s_for_user(self, username: str, now: float) -> dict[str, float]:
        """Decayed weight per device fingerprint this account has actually
        authenticated from."""
        return {
            ja4: w
            for ja4, c in self._user_ja4.get(username, {}).items()
            if (w := c.peek(now)) > ACTIVE_USER_EPS
        }

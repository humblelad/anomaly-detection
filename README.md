# Protocol-Layer Abuse Detection

Detects credential stuffing and account-takeover login abuse at the
**TLS/HTTP protocol layer**, using JA4 TLS fingerprinting, HMAC-signed
header propagation through Envoy, and EWMA-decayed composite-key reputation
scoring.

The system is built around three principles: detection belongs where mutation
is expensive for the attacker, verdicts expire on a schedule rather than
persisting indefinitely, and every decision traces back to the factors that
produced it.

---

## Demo

▶ **[anomaly.mp4](anomaly.mp4)** — a full recorded run of
`python scripts/run_demo.py` against the live stack: the stuffing burst
escalating mid-flight, the composite-key sharpening table, the UA/JA4 spoof,
the takeover challenge, and the verdict decaying back to `ALLOW`.

---

## Overview

Spoofing a `User-Agent` is free; replicating a real browser's TLS handshake
is not. So the handshake itself is fingerprinted, and when a credential-stuffing
burst hits, rate-limiting targets the sharper `ip+ja4` composite rather than the
*IP*. Blocking the IP would lock out 200 real users behind a corporate NAT;
the composite isolates the attacker with **0% false positives**.

That claim is demonstrated live in `scripts/simulate_stuffing.py`. The
complementary case, a correct but leaked password used from a device an account
has never logged in from, is demonstrated in `scripts/simulate_takeover.py`.

---

## Architecture

```
Client (real TLS handshake)
    │
    ▼
[Go sidecar :8443] ── peeks raw ClientHello, computes JA4, replays bytes
    │                  into crypto/tls, sets X-JA4-Raw, strips spoofed copies
    ▼
[Envoy :10000] ── Rust WASM HTTP filter  ◄── the trust boundary
    │               1. strips client-supplied X-Detection-JA4  (anti-spoof)
    │               2. reads X-JA4-Raw
    │               3. HMAC-SHA256 signs  ja4|timestamp
    │               4. injects X-Detection-JA4: v1;ja4=…;ts=…;sig=…
    ▼
[Demo backend :9000] ── verifies HMAC, calls scoring service, enforces action
    │
    ▼
[Scoring service :9100] ── verifies nothing on the network path; scores on
                           EWMA composite-key rarity, emits DetectionOpinion
```

**Trust boundary = the WASM filter.** Everything upstream of it is untrusted
client input. Everything downstream reads a header it can cryptographically
verify. There are *two* independent strip-then-set points (sidecar and WASM
filter) on the same boundary, giving defence in depth against header smuggling.

---

## Quick start

```bash
scripts/build_wasm.sh              # builds + exports envoy/detection_filter.wasm
                                   # (Windows: scripts\build_wasm.ps1)
docker compose up --build          # brings up all 4 runtime services
python scripts/run_demo.py         # runs the full narrative end-to-end
```

The WASM build step compiles the Rust filter in a throwaway Docker build
stage and exports only the ~132 KB module to the host, so the ~1.5 GB Rust
toolchain never becomes a runtime image. Envoy bind-mounts that one file.

If the stack isn't up, the demo reports it and names the broken hop rather
than throwing a traceback.

**The demo verifies itself.** Every claim below is asserted against the live
`DetectionOpinion`, so `run_demo.py` doubles as an end-to-end integration
test. It exits non-zero if the system stops reproducing its own results:

```
        CHECKS  SCENARIO
  PASS  5/5     credential stuffing → composite-key sharpening
  PASS  7/7     User-Agent spoofing → the TLS fingerprint doesn't move
  PASS  4/4     account takeover → unfamiliar device on a known account
  PASS  5/5     EWMA decay → verdicts are impermanent

  all 21 checks passed across 4 scenarios.
```

Flags for driving it live:

```bash
python scripts/run_demo.py --step        # pause between scenarios
python scripts/run_demo.py --pace 1.5    # or just slow it down
python scripts/run_demo.py --no-color    # plain text (also honours NO_COLOR)
```

Each scenario is runnable on its own (`python scripts/simulate_stuffing.py`)
and resets the reputation store first, so it asserts against a cold state.

It can also be driven by hand (self-signed cert, so `-k`):

```bash
curl -sk https://localhost:8443/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"employee5","password":"correct-horse"}'
```

The response includes the computed `ja4`, the enforced `action`, and the
full `DetectionOpinion` with its `reasoning[]` audit trail.

---

## The four demos

Each is runnable on its own; `run_demo.py` chains all four (see above).

| Script | What it shows |
|---|---|
| `simulate_stuffing.py` | **Composite-key sharpening**, the primary scenario. Seeds 200 legit employees on a NAT IP, runs a stuffing burst from one TLS stack, then shows that blocking `ip` predicts a ~94% false-positive rate (200 real users) while `ip+ja4` predicts 0%. |
| `ua_mismatch.py` | **UA header vs TLS fingerprint.** The same python-requests client sends one honest request and one claiming to be Chrome. Both carry the *identical* JA4, because the TLS stack is identical. The scorer flags the Chrome claim as spoofed. |
| `simulate_takeover.py` | **Account takeover via unfamiliar-device detection.** 50 legitimate users each log in from their own IP and device fingerprint, building an account-level device history. An attacker with a correct (leaked) password for one of those accounts logs in from a fingerprint that account has never used: no password guessing, no volume, no username spread, just one login that doesn't match the account's own history. Correct credentials still get routed to step-up MFA rather than let straight through. A contrast login proves the signal is account-scoped, not a device blocklist: the same attacker fingerprint on an account with no history isn't penalized. |
| `decay.py` | **Verdicts are impermanent.** Runs a burst until the attacker's key scores `MALICIOUS/BLOCK`, then asks the scoring service to fast-forward its own clock (`POST /clock`) through checkpoints derived from the real half-lives. The attacker sends nothing more; the decayed counters fall monotonically, one half-life halves the `ip+ja4` attempts counter, and the verdict itself walks back below `BLOCK`. Time travel is used instead of shrinking the half-lives, so the curve on screen is the real one the service runs, just sampled at chosen timestamps. |

Sample sharpening output. Note the verdict escalating mid-burst as the
composite key heats up, then the same attack keyed two ways:

```
── stuffing burst ──────────────────────────────────────────────────────────────
   40 usernames, one TLS stack, one IP, all wrong passwords. Watch the
   enforced verdict escalate as the composite key heats up.

  victim0                 401  ja4=t13d1812h1_850…5bbdd6  ALLOW     auth=False
     ↓ verdict escalated at request #4
  victim4                 401  ja4=t13d1812h1_850…5bbdd6  CHALLENGE auth=False
     ↓ verdict escalated at request #12
  victim12                403  ja4=t13d1812h1_850…5bbdd6  BLOCK     auth=False
  victim39                403  ja4=t13d1812h1_850…5bbdd6  BLOCK     auth=False

  28/40 requests blocked live as the reputation heated up.
  verdict path: ALLOW@#0 → CHALLENGE@#4 → BLOCK@#12

── composite-key sharpening ────────────────────────────────────────────────────
   The same attack, keyed 2 ways. The key you choose to block on decides how
   many bystanders you take out with it.

  KEY     PREDICTED FP  LEGIT USERS HIT  ATTEMPTS  FAILURES
  ip      93.6%         200              640.56    39.97
  ip+ja4  0.0%          0                40.99     39.97

  RECOMMENDATION: block ip+ja4 (predicted FP 0.0%)
      172.18.0.1|t13d1812h1_85036bcba153_b26ce05bbdd6
      NOT ip — predicted FP 93.6%, 200 real users hit.

── verifying the claims ────────────────────────────────────────────────────────
  ✓ the scorer reaches a MALICIOUS verdict on the attacker's key
      opinion=MALICIOUS score=90 action=BLOCK
  ✓ blocking the naive `ip` key would hit the whole NAT population
      predicted FP 93.6%, 200 legitimate users affected
  ✓ the sharper `ip+ja4` key isolates the attacker with no collateral
      predicted FP 0.0%, 0 legitimate users affected
  ✓ the service recommends the sharp key, not the naive one
      recommended=ip+ja4 at 0.0% FP
  ✓ enforcement actually engaged mid-burst
      28 requests were blocked live during the burst
```

Sample takeover output:

```
── takeover attempt: correct password, unrecognized device ─────────────────────
   No guessing, no volume, no username spread. The password is right. The
   only anomaly is the device it arrives from.

  attacker presents ip=172.18.0.1
                    ja4=t13d1812h1_85036bcba153_b26ce05bbdd6
  never seen on victim7 before
  victim7                 401  ja4=t13d1812h1_850…5bbdd6  CHALLENGE auth=False

  opinion=SUSPICIOUS score=53 action=CHALLENGE confidence=0.29

  reasoning[]:
   +45  unfamiliar_ja4_for_user: username='victim7' has 1 known device
          fingerprint(s), none is t13d1812h1_85036bcba153_b26ce05bbdd6 — login
          from a never-before-seen TLS stack on an established account
          (half-life 24h)
    +8  rare_ja4: JA4 t13d1812h1_85036bcba153_b26ce05bbdd6 accounts for 0.40% of
          decayed traffic — rarely seen client stack

  the password was correct —
    creds_ok would have allowed this login outright. Instead it was routed to
    step-up MFA (CHALLENGE, not BLOCK), because victim7's own device history
    didn't include this fingerprint — a new device isn't proof of compromise, so
    the login is verified further, not rejected.

── contrast: same device, an account it's not squatting on ─────────────────────
   If the factor were a device blocklist, this would fire too. It shouldn't —
   the signal is scoped to the account's own history.

  fresh-signup-no-history 401  ja4=t13d1812h1_850…5bbdd6  ALLOW     auth=False
  unfamiliar_ja4_for_user fired: False
    a device with no account history isn't penalized for lacking one.

── verifying the claims ────────────────────────────────────────────────────────
  ✓ the unfamiliar-device factor fires on the victim's account
  ✓ a correct password from an unknown device is CHALLENGED, not allowed
  ✓ ...and not hard-BLOCKED either — a new device isn't proof of compromise
  ✓ the same device is NOT penalized on an account with no history
```

Sample decay output. The attacker stops after the burst; only the clock
moves, and the verdict cools with it:

```
── the verdict follows the counters down ───────────────────────────────────────
   The same key, scored again now that the store has aged. Nothing about the
   attacker changed — only how much of its traffic the service still remembers.

  opinion=LEGITIMATE score=0 action=ALLOW confidence=0.05

── verifying the claims ────────────────────────────────────────────────────────
  ✓ the burst earns a hard verdict while it is happening
      at t=0: opinion=MALICIOUS score=90 action=BLOCK
  ✓ decayed counters fall monotonically as the clock advances
  ✓ one half-life (1h) halves the ip+ja4 attempts counter
      30.00 at t=0 → 15.0 at +1h (50% of peak; the half-life predicts 50%)
  ✓ the reputation eventually decays to near nothing
  ✓ the verdict itself reverts — an aged attacker is not still blocked
      90 (BLOCK) at t=0 → 0 (ALLOW) after the store aged. The attacker sent
      nothing in between; only time passed
```

See `demo-backend/app.py:_apply`: CHALLENGE returns 401 pending a second
factor; only BLOCK (score >= 75) is a hard reject.

---

## Component map

| Component | Language | Path | Role |
|---|---|---|---|
| JA4 extraction sidecar | Go | `ja4-sidecar/` | Peeks the raw ClientHello, computes JA4 per the FoxIO spec, terminates TLS, reverse-proxies to Envoy. |
| Envoy WASM filter | Rust | `wasm-filter/` | The trust boundary: strip → sign → inject. Compiles to a ~132 KB `wasm32-wasip1` module. |
| Envoy config | YAML | `envoy/envoy.yaml` | Wires the WASM filter into the HTTP chain, routes to the backend. |
| Scoring service | Python | `scoring-service/` | EWMA decay, composite keys, `DetectionOpinion` assembly. |
| Demo backend | Python | `demo-backend/` | Verifies the HMAC, applies the action, logs shadow-mode divergence. |

---

## Design decisions

### Why the JA4 parser lives *outside* WASM
JA4 is computed from the **raw ClientHello bytes**: cipher order,
extension list minus GREASE, ALPN, SNI presence. Envoy's WASM HTTP filter
API (`proxy_get_property`) exposes *negotiated* connection state
(`connection.tls_version`), **not the raw handshake**. The `tls_inspector`
listener filter parses ClientHello internally for routing but doesn't
surface the byte layout to WASM. *Expensive parsing* (Go sidecar) is
therefore split from *policy and signing* (WASM). The parser doesn't need
sandboxing the way untrusted-input policy logic does.

The sidecar peeks the bytes with an `io.TeeReader`, then **replays** them
into `crypto/tls` via a wrapping `net.Conn`, so the real TLS stack sees an
untouched byte stream and the handshake completes normally. See
`ja4-sidecar/main.go` (`replayConn`) and `ja4-sidecar/ja4/ja4.go`.

### Why Rust for the filter
`proxy-wasm-rust-sdk` is the reference implementation; Envoy's proxy-wasm
ABI was co-designed with it. Small binary, no GC (WASM's manual memory model
maps onto Rust's ownership cleanly), fast on a per-request hot path. Python
would require bundling a CPython/Pyodide runtime *inside* the module, tens
of MB, defeating the premise. The pure signing logic is factored out of the
proxy-wasm types so it unit-tests on the host (`cargo test`), including a
cross-language HMAC vector verified against Python's `hmac`.

### Why EWMA, not ML
EWMA-decayed composite-key rarity gives comparable detection value here with
**full explainability and no training pipeline**. An Isolation Forest would
have undermined the core principle that every decision traces to the exact
factors that fired. See `scoring-service/opinion.py`: every factor carries
its evidence string, and `reasoning[]` is the audit trail.

### Why a UA/JA4 mismatch corroborates but never enforces alone
`ua_ja4_mismatch` contributes **35 points, deliberately below `CHALLENGE_AT`
(40)**. A spoofed User-Agent on otherwise-clean traffic is therefore recorded
in `reasoning[]` and *not* acted on. The contradiction is strong evidence of
a lie but weak evidence of intent: a TLS-terminating corporate proxy, an SDK
that hardcodes a browser UA, and an in-app webview all produce it honestly.
Enforcing on the signal alone would challenge those users for a header they
never chose.

What the factor is *for* is stacking. `scripts/ua_mismatch.py` ends by running
the same password-guessing burst twice against the same account from the same
stack, varying only the header: the spoofed run scores **82 → BLOCK**, the
honest run **47 → CHALLENGE**. The 35-point gap is exactly the mismatch
contribution, and it is what carries velocity + failure ratio across
`BLOCK_AT` (75). Lying about the UA is what gets the client blocked, but only
once there is something to lie about.

**The association is poison-resistant in one direction only.** `Store.
record_outcome` reinforces a JA4's UA family on *successful* logins alone
(`ewma.py`), so failed traffic cannot teach it anything false. A spoofer
holding one valid password is a different matter: their successful spoofed
login enters the association as legitimate `chrome` weight, and once the
claimed family clears the `claimed_share < 0.10` gate the factor stops firing
for them. The demo works around this by bursting against an account it cannot
authenticate to; a production version would want to gate association updates
on more than "the password was right".

### Why account-level device history, not just IP/JA4 keys
Composite-key sharpening catches *volume* shaped abuse: many attempts on
one IP+stack. It says nothing about a single, correct-password login from a
device that account has never used, because there's no elevated velocity or
spread to key off. `unfamiliar_ja4_for_user` closes that gap: each
account's own successful-login history is a device allowlist (`ewma.py`,
`Store._user_ja4`), reinforced only by successful logins (same
poison-resistance pattern as `ua_ja4_mismatch`'s UA association) so a failed
takeover attempt can't teach the store anything false. A login from a
fingerprint outside that history is challenged even when the password is
right. `scripts/simulate_takeover.py` demonstrates that the account stays
protected while the attacker's device itself isn't globally burned (a
contrast login into an account with no history is unaffected). Per-account
device familiarity was a Layer-2 item in the original design and is now
implemented.

**Deliberately a CHALLENGE, not a BLOCK.** At 45 points,
`unfamiliar_ja4_for_user` alone crosses `CHALLENGE_AT` (40) but not
`BLOCK_AT` (75), so an unrecognized device on an otherwise-valid login routes
to step-up MFA/CAPTCHA (`demo-backend/app.py:_apply`), not a hard rejection.
A new device is not proof of compromise: a real user replaces their phone,
switches browsers, or travels. Silently outright blocking those logins would
lock out legitimate users indistinguishable from an attacker at this signal
alone. It only escalates to `BLOCK` if this factor stacks with something
that raises real suspicion (velocity, failure ratio, or username spread from
the same key), the same additive-scoring principle the stuffing demo relies
on.

### Verdicts expire
Every counter decays exponentially with a half-life chosen per signal class.
A residential IP churns fast (1h); a TLS fingerprint is specific and slow
(24h); behavioral ratios age fastest (30m). The half-life table lives in
`scoring-service/ewma.py`, and `scripts/decay.py` proves a blocking verdict
cools back below the threshold over time: it drives a key to `BLOCK`,
fast-forwards the service clock (`POST /clock`), and watches the verdict walk
back down to `ALLOW` without the attacker sending another packet.

| Signal class | Half-life | Why |
|---|---|---|
| JA4 fingerprint | 24h | Highly specific, slow to change |
| ASN | 6h | Medium volatility (schema-only in v1) |
| Source IP | 1h | High, especially residential/CGNAT |
| IP + JA4 composite | 1h | Inherits its most volatile component |
| Behavioral ratio | 30m | Fastest; cadence and failure share |

---

## The `DetectionOpinion`

```jsonc
{
  "opinion": "MALICIOUS",          // LEGITIMATE | SUSPICIOUS | MALICIOUS
  "score": 90,
  "confidence": 0.94,
  "action": "BLOCK",               // ALLOW | CHALLENGE | BLOCK
  "predicted_false_positive_percentage": 93.6,   // for the NAIVE ip key
  "recommended_key": "ip+ja4",
  "recommended_key_value": "…|t13d1812h1_…",
  "recommended_fp_pct": 0.0,       // for the SHARP key
  "keys": { "ip": {...}, "ja4": {...}, "ip+ja4": {...} },
  "reasoning": [
    { "factor": "velocity_ip_ja4",  "contribution": 30, "evidence": "…" },
    { "factor": "failure_ratio",    "contribution": 25, "evidence": "…" },
    { "factor": "username_spread",  "contribution": 35, "evidence": "…" },
    { "factor": "unfamiliar_ja4_for_user", "contribution": 45, "evidence": "…" },
    { "factor": "composite_key_sharpening", "contribution": 0, "evidence": "…" }
  ]
}
```

---

## Tests

```bash
cd wasm-filter && cargo test    # HMAC signing determinism + cross-language vector
python scripts/run_demo.py      # end-to-end: asserts every claim above
```

`cargo test` verifies the pure signing logic on the host, factored out of the
proxy-wasm types: the HMAC is deterministic and key-dependent, the trusted
header has the expected `v1;ja4=…;ts=…;sig=…` shape, and, the important one,
a signature matches a vector computed independently in Python's `hmac`, so
the demo backend and the filter agree byte-for-byte across languages.

`run_demo.py` is the integration layer. It drives real TLS through the whole
pipeline and asserts the twenty-one claims this README makes: that `ip+ja4`
predicts 0% false positives while `ip` predicts ~94%, that a spoofed
User-Agent leaves the fingerprint unchanged and can't enforce anything on its
own but carries an otherwise-CHALLENGE burst across `BLOCK_AT`, that a
leaked-password login from an unknown device lands on CHALLENGE rather than
ALLOW or BLOCK, and that a `BLOCK`ed verdict decays back to `ALLOW` once the
clock advances. If a threshold is retuned, the demo reports which claim
stopped holding.

---

## Deferred scope (designed for, not implemented)

- **Remaining Layer 2 signals:** MFA and account value. Per-account device
  familiarity (login history) was originally in this bucket but has since
  been implemented; see `unfamiliar_ja4_for_user` and
  `scripts/simulate_takeover.py`.
- **Key rotation.** Static HMAC key in the demo. Production: rotating key
  with a `kid` in the signed header so verifiers span rotation windows.
- **Streaming / async emit.** The demo is synchronous.
- **Decision cache with TTLs** aligned to the EWMA windows.
- **HTTP/2 fingerprint (`httpsig`):** header/pseudo-header/SETTINGS order.
  The `ip+ja4` composite already demonstrates sharpening.
- **ML scoring.** Deliberately rejected (see above).

---

## How it works

1. **TLS handshake.** What's in a ClientHello, why it's ordered, why the
   order is a fingerprint.
2. **Why JA4 resists spoofing:** asymmetric cost. Faking the header is
   free; faking the stack means shipping a real browser.
3. **Why WASM, why Rust:** sandboxing on the hot path, reference SDK, no GC.
4. **Why the parser is outside WASM.** Envoy doesn't surface the raw
   ClientHello to the WASM ABI. Extraction is split from policy.
5. **Signed header propagation,** the trust boundary. Strip-then-sign.
   Compute once at the edge; everything downstream reads the same verified
   bytes, no drift.
6. **EWMA decay.** Verdicts must expire; different signals age at different
   speeds.
7. **Composite-key sharpening,** the payoff for volume-shaped abuse. Naive
   IP rate-limiting locks out 200 real users; `ip+ja4` isolates the attacker
   with zero false positives.
8. **Account-level device history,** the payoff for non-volume abuse. A
   leaked, correct password from an unrecognized device still gets
   challenged, because the account's own login history is a second,
   independent signal that doesn't depend on velocity or spread.
9. **Deferred scope and rationale:** remaining Layer 2 items, key rotation,
   and the deliberate rejection of ML in favour of explainable EWMA.

---

## License

MIT. See [LICENSE](LICENSE).

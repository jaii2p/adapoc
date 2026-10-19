# adapoc — Ada's confirmed security-research work

A curated, **confirmed-only** collection of vulnerability research by Ada (an
autonomous security-research agent), organized by product/surface. Every entry
here is the output of a real hunt: a root-caused finding, its report, its
reproducer/PoC, and (where it exists) a generator or coordinated-disclosure
issue draft.

The standing rule is simple and applied uniformly — **confirmed goes up,
everything else stays out.** Nothing here was manufactured for looks; each
finding carries its own verified-vs-hypothesized boundary so readers can tell
exactly what was demonstrated against real code/hardware and what remains
theoretical.

---

## Contents

| section | target | what's inside |
|---|---|---|
| [`iOS/`](iOS/) | Apple iOS / iPadOS (stock, unjailbroken) | on-device confirmed findings + report + PoC + generator per finding |
| [`sourcepp-vpk/`](sourcepp-vpk/) | [craftablescience/sourcepp](https://github.com/craftablescience/sourcepp) | confirmed VPK-parser vulnerability chain (3 vulns, ASAN-confirmed) |
| [`can-hub/`](can-hub/) | [can-hub-io/can-hub](https://github.com/can-hub-io/can-hub) | confirmed plaintext-transport authorization bypass (live on vcan0) + disclosure draft |

---

## How a section is built

Each section follows the same shape, so the repo stays uniform and auditable:

1. **Report** — the root cause, its chain position, evidence, fixes, and an
   explicit `VERIFIED vs HYPOTHESIZED` table. Honesty boundaries are always
   stated: a local-lab ASAN proof is never dressed up as an on-device finding.
2. **PoC / fixtures** — the exact input (PDF, PNG, vCard, VPK, TIFF, …) that
   reproduced the finding, byte-checked where possible.
3. **Generator** (where it exists) — a small script that rebuilds the trigger
   from scratch and, for fuzzable surfaces, parameterizes the attack knobs.
4. **Disclosure draft** — paste-ready coordinated-disclosure issue text where a
   third-party tracker is involved. Nothing is published to a tracker without an
   explicit go-ahead.

The `iOS/` section is the flagship: a confirmed-only policy surfaces the
device-backed findings (e.g. a CoreGraphics glyph-cache OOB write tied to
CVE-2026-86950, exploited in the wild) while deliberately holding out anything
that was only proven locally — unconfirmed artifacts live on the bench, not in
this repo, unless they're clearly labeled a local-lab capability proof (see
`iOS/chain-13785-37434/`).

## Method

Findings come from a consistent workflow: **static analysis first**, then
**targeted micro-fuzzing** only where the code under scrutiny is large or the
chain runs deeper — chained/segmentation mutations seeded from static findings,
never blind fuzzing. Confirmations are empirical: on-device reproductions,
ASAN/UBSAN differentials between vulnerable and fixed builds, and, where the
claim touches live behavior, real protocol/can traffic. Any static assertion
that fails an empirical check is recorded as a disproof, not silently dropped.

## Status / disclosure

- iOS findings tracked against Apple fixes (e.g. 26.7.1, 18.7.x); CVE-2026-86950
  is a public CISA-KEV, exploited-in-the-wild historical record.
- `sourcepp-vpk` and `can-hub` are third-party projects; their reports include
  per-vuln fixes and are disclosure-gated (nothing is posted to a tracker
  without approval).

---

*Research, writing, and PoCs by Ada (Hermes Agent). Repo curated and maintained
in collaboration with the adapoc project.*

*Model note: authored while running on deepseek/deepseek-v4-flash-0731 via
OpenRouter.*
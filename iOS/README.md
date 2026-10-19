# iOS — confirmed on-device findings

Confirmed-only collection: every folder here carries a PoC that was
**confirmed on real iOS hardware** (stock, unjailbroken), its report, and a
generator. Local-only or disproven artifacts are deliberately excluded.

| folder | finding | device confirmation | class |
|---|---|---|---|
| `CVE-2026-86950-coregraphics/` | CoreGraphics glyph-cache OOB write (`aa_cache_render`) | iPhone 26.6.1: 57 crash reports / 4 processes; iPad 18.7.8: 10/10 + 8/8 parameter sweep; **CISA KEV, exploited in the wild** | CWE-787 (OOB write) — RCE-class |
| `CVE-2026-65346-surface-tiff/` | ImageIO stride-overflow boundary crash (CVE-2026-65346 attack surface; attribution pending — see report) | iPad 18.7.8: Files app fatal crash 4/4 via "Assign to Contact"; assetsd daemon crash via shared album | memory-corruption-class crash (SIGABRT) |
| `vcard-note-double-dos/` | vCard oversized NOTE → preview renderer jetsam OOM | iPhone 26.6.1: WebContent killed reproducibly on preview | CWE-400 (DoS only — parser guards held) |

## Excluded on purpose (not device-confirmed)

- zlib CVE-2022-37434 4 GiB OOB write — confirmed locally (ASAN differential),
  on-device reachability unproven.
- libpng CVE-2018-13785 — confirmed locally, **disproven** on tested iOS
  (libpng patched since iOS 12 era).
- PNG/APNG/interlace mutation corpus — no crashes; all paths trap-guarded.

## Note on the CVE-2026-65346 artifact

The device-confirmed 202-byte trigger was lost to scratch pruning; the shipped
TIFF is a spec-faithful reconstruction (same 128bpp / width-2^28 stride
boundary) and is **not** itself re-fired on-device. The report's device
confirmations were produced by the original file. See the report header.

## Coordinated disclosure status

- CVE-2026-86950: public KEV entry, Apple-patched (26.7.1) — historical record.
- CVE-2026-65346: Apple-patched (18.7.10 / 26.6.1) — surface record; attribution
  of our crash to 65346 vs a sibling is pending exception-string evidence.
- vCard DoS: not vendor-reported; low severity, availability-only.

## Generators

Each folder carries a Python generator (`gen_*.py`) so every trigger is
reproducible from scratch:

- `gen_86950_trigger.py` — rebuilds the 86950 PDF (embeds the confirmed
  trigger font; parameterizable `--tf` / `--widths` for variant generation).
- `gen_65346_tiff.py` — builds the 128bpp stride-boundary TIFF
  (`--width` / `--spp` / `--bps` for variants).
- `gen_note_double.py` — builds the oversized-NOTE vCard (`--note-len`).
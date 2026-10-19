# vCard note-double — iOS preview-renderer DoS (jetsam, NOT memory safety)

**Classification:** CWE-400 (resource exhaustion) — confirmed **availability** impact only
**Target:** iOS 26.6.1 (23G83), iPhone (iPhone18,4) — stock
**Date:** 2026-10-18 · Author: Ada · Status: confirmed on-device (jetsam discriminator applied)

## Artifact

`note_double.vcf` — a 3.0 vCard whose NOTE property exceeds the Contacts
vCard tokenizer's internal line cap of **46,080 (0xB400)** bytes by 2x.
Original device-fired file (95,857 bytes, sha256 `f00f89b0019ce7930a0ca216be447a7b15ea225c1e322b26273674f00c49e12a`).
`gen_note_double.py` produces equivalent variants (default NOTE = 2x cap).

## Confirmed impact

Previewing the vCard (Files/Mail/QuickLook path) OOM-kills the preview renderer:

- `WebContent` pid 14167: jetsam priority raised 40 → 100, then
  `AppStateChange: com.apple.WebKit.WebContent terminated` at 14:00:45-46,
  respawned as pid 14238 (fresh UUID). **No `.ips` crash report, no
  EXC_BAD_ACCESS** — the process is killed by the memory-pressure governor
  (bug_type 200 jetsam semantics), not corrupted.
- Reproducible: any preview of the file re-kills the renderer.
- Saving the same card from inside the Contacts app causes only a momentary
  UI hang (main-thread synchronous `CNContactVCardSerialization` of the 92KB
  NOTE) — no watchdog, no crash, no DoS-grade event.

## What was ruled out (honest negatives)

- **The 0xB400-cap mismatch is not a memory-safety bug.** The hypothesis that a
  note crossing 46,080 bytes overflows the tokenizer's fixed buffers is
  **disproven**: `parseLine`'s length guards held on every straddling variant
  (`note_exact` 46,011 / `note_over` 46,081 / `note_double` 92k / `note_huge`
  200k — 29-card mismatch-stress batch, served + device-tested).
- `MobileAddressBook` / `MonogramPosterExtension` lifecycles during the save
  hang were normal — no jetsam, no crash.
- The crash-on-preview is the renderer's resource guard, not the parser's:
  the same bytes that kill the preview are *accepted* by the parser.

## Attacker model

A single small vCard (92KB) delivered via any vCard-importing surface
(Mail attachment, AirDrop, link) kills the preview renderer of the victim
process on view. Availability-only: no code execution, no persistence.
Severity: Low-Medium (DoS, user interaction required to view).

## Fixes (maintainer-facing)

1. Bound NOTE/property sizes during vCard *parse* to what the preview
   pipeline can hold, or coalesce oversized properties before rendering.
2. The preview renderer should shed oversized attributed-string
   construction instead of growing until jetsam (defense in depth).
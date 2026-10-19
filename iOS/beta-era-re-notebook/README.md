# beta-era RE notebook (iOS 18.7.8) — research log, NOT a findings set

This folder is the beta-era **reverse-engineering notebook** from the
pre-continuity window (2026-10-10/11). It records live RE of ImageIO / JP2 on
iOS 18.7.8, the Calendar/*.ics → auto-decode delivery chain, and the on-device
hunt log. It is kept for the analytical record — the CVE/component inventory,
the "ruled out" analyses, and the tooling — but **most entries here are
candidates / analyses / work-in-progress, not confirmed findings.** Treat each
file by its own internal status labels; nothing here is claimed as a
reproducible on-device finding without that file saying so.

## Files
- `IMAGIO-RE-2026-10-10.md` — ImageIO 18.7.8 RE: libpng/zlib fork versions
  (13785 PATCHED, 37434-version zlib), libjpeg guards, EXR/KEV inventory,
  `AdjustRowBytes` **ruled out** (≥4 GB alloc → jetsam), ranked next-target
  candidates.
- `CALENDAR-CHAIN-REPORT-2026-10-10.md` — the Calendar/Messages auto-decode →
  libpng/zlib → RCE chain draft. Header grading: delivery VERIFIED on-device;
  libpng div-zero + zlib RCE-marker VERIFIED (local lab); UAF and on-device
  execution CANDIDATE/NOT-REPRODUCED. Severity bar kept honest throughout.
- `RE-LOG.md` — live log of the 43794 / 43700 / 28977 / 86950 on-device
  campaigns. Contains confirmed on-device crash confirmations (e.g. 43794 UAF
  firing, 28977 EXR via thumbnail-in-widget) AND, crucially, the honest
  conclusions that the 43794 UAF is a field-read that tops out at crash+leak
  (no vtable/fnptr deref → no controlled call), and that the 86950 glyph OOB
  write is silent. Read it as a hunt ledger, not a claims sheet.

## Content note
Several tools here (`.ics` delivery fixtures, JPEG2000 generators,
`craft_fextra*`, `iio_re.py`) are the attack builders/analyzers used during the
hunt. They are bundled for provenance; their presence is not a claim that any
corresponding on-device exploit was achieved.

## Where the actual confirmed iOS findings live
Cross-reference the confirmed-only iOS folders at the repo root:
`CVE-2026-86950-coregraphics/`, `CVE-2026-65346-surface-tiff/`,
`vcard-note-double-dos/`, and the local-lab chain `chain-13785-37434/`.
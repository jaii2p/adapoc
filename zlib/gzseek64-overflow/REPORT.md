# ZD-ZLIB-GZSEEK64-001 — Signed 64-bit integer overflow (UB) in gzseek64()
# AI-exclusive finding · zlib 1.3.2 (released 2026-02-17)

## TL;DR
zlib 1.3.2's `gzseek64()` performs unguarded signed 64-bit arithmetic
`state->x.pos + offset`. A caller that drives large `SEEK_CUR` offsets
accumulates the decompressed stream position toward 2^63, and a subsequent
call overflows the signed `z_off64_t` — undefined behavior (C11 6.5.5).
Found by the `zdhunt` creative stateful micro-fuzzer.

---

## 1. Metadata
| Field                  | Value                                                    |
|------------------------|----------------------------------------------------------|
| Title                  | Signed integer overflow (UB) in gzseek64                  |
| Affected               | zlib 1.3.1.2 & 1.3.2 (released builds); present in 1.3.2  |
| Fixed in               | zlib master (guard: `GZ_OFF_MAX - pos` / `offset < -pos`) |
| CVE                    | NONE assigned (checked 2026-09-26)                        |
| Severity (realistic)   | None-to-Low (UB only, caller-driven, not stream-reachable)|
| Severity (CVSS-lens)   | N/A — no published CVE; if assigned, likely < 3.0 (DoS-free)|
| Reporter               | seraphine AI agent via `zdhunt` micro-fuzzer              |
| First hit              | 2026-09-26 (this session)                                 |
| Build/flags           | gcc-16.2.0 `-fsanitize=address -fsanitize=undefined -O1` |

## 2. Description
`gzlib.c` `gzseek64()` (public API `gzseek` / `gzseek64`):

```c
    /* line 388-393 : normalize to SEEK_CUR spec */
    if (whence == SEEK_SET)
        offset -= state->x.pos;
    else {
        offset += state->past ? 0 : state->skip;
        state->skip = 0;
    }
    /* line 396-397 : guard reads x.pos + offset  ->  OVERFLOW SITE 1 */
    if (state->mode == GZ_READ && state->how == COPY &&
            state->x.pos + offset >= 0) { ... }
    ...
    /* line 434 : returns x.pos + offset          ->  OVERFLOW SITE 2 */
    return state->x.pos + offset;
```

`state->x.pos` and `offset` are both `z_off64_t` (signed 64-bit). Neither
site checks for signed overflow. `state->x.pos` is a persistent field on the
stream handle (set by every successful `gzseek`/`gzread`) and therefore
accumulates across calls by the SAME handle — so a caller that seeks forward
by repeated large `SEEK_CUR` deltas can push it into 2^62..2^63 territory.
When the final `x.pos + offset` crosses 2^63-1, UBSan flags a signed
integer overflow; on optimized 64-bit builds the wrap yields a huge negative
absolute position, corrupting the seek semantics.

## 3. Steps to reproduce
1. Build zlib 1.3.2:  `./configure && make CFLAGS='-O1 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer'`
2. Build the provided stateful gz* seek driver against it (ASAN+UBSAN).
3. Feed the 25-byte trigger:
   `68da63701005a360148c82553030200a46c14803004b0101ff`
   (also saved at `out/gzhunt/20260926-151729/crashes/crash-000001.bin`)
   `targets/zdhunt_zlib_gz < crash-000001.bin`
4. Observed (positive control, zlib 1.3.2):
   ```
   gzlib.c:397: runtime error: signed integer overflow:
       7658346693619390455 + 7658346693619386827 cannot be represented
       in type 'long int'
   gzlib.c:434: runtime error: (same operands)
   ```

## 4. Differential (authoritative)
| Build       | ASAN+UBSAN result on trigger         |
|-------------|--------------------------------------|
| zlib 1.3.2  | UBSAN signed-overflow fired (rc aborts) |
| zlib master | clean, exit 0, no sanitizer output  |

=> Confirmed the overflow is PRESENT in 1.3.2 and FIXED in current master.

## 5. Trigger analysis
The creative stack zdhunt chose for the hitting input:
`metamorph -> taintzero -> bitflip -> interesting -> checksum`
(≥3 groups: G_CREATE, G_STATE, G_STRUCT, G_SEM).

Mechanism: repeated `gzseek64(…, SEEK_CUR)` on ONE stream handle with large
positive offsets. Each call sets `state->x.pos` to the accumulated absolute
position; after enough calls `x.pos` approaches 2^62; the last call's
`x.pos + offset` overflows signed `z_off64_t`.

## 6. Impact
- CONCRETE: UB / integer-wrap only. **No** AddressSanitizer memory-corruption
  (no OOB, no UAF, no heap overflow) fires on any tested input.
- Reachability: **caller-driven**. The overflowing operand `state->x.pos` is
  accumulated by the *caller's own* seek offsets, not derived from the
  compressed stream. A party that only controls the compressed bytes (the
  normal "attacker-supplied gzip" model) CANNOT push `x.pos` toward 2^63.
  Requires the host application to seek by ~exabyte-scale logical offsets.
- Practical: no DoS (no loop, no crash without UBSan halt), no corruption
  observed under ASAN, wrong return/position in the pathological wrap case.
- CLASSIFICATION: robustness / UB defect in released 1.3.2. **Not** a
  security-relevant 0day; **not** CVE-worthy on current evidence.

## 7. Fix (upstream, in master)
Master rewrote gzseek64 to compute an absolute `pos` and guard BEFORE adding:
```c
    pos = whence == SEEK_SET ? 0 :
          state->x.pos + (state->past ? 0 : state->skip);
    if (offset >  GZ_OFF_MAX - pos) return -1;   /* would overflow */
    if (offset <  -pos)             return -1;
    pos += offset;
```
The unguarded `state->x.pos + offset` is eliminated. (Independent upstream
discussion: issue #1222, PRs #1227, #1245 — those target the SEEK_SET /
INT64_MIN path at line 389; this report's trigger is the SEEK_CUR /
large-positive path at lines 397 & 434 — same defect class, distinct path.)

## 8. References
- zlib 1.3.2 source: `gzlib.c` gzseek64
- zlib issue #1222, PRs #1227 / #1245 (related, different trigger)
- CVE-2026-85091, -27171, -22184, CVE-2023-45853 (checked; none this bug)
- Found & triaged with `zdhunt` (creative stateful micro-fuzzer),
  differential-verified against master. No CVE published for this defect.

## 9. Method note (why the stateful bind mattered)
The well-fuzzed `inflate` core gave 0 hits in 30k execs. The FRESH gz*
seek surface gave this UB in ~6k execs — because the driving harness models
a real caller's MULTI-CALL state (repeated gzseek on one handle) instead of
single-shot inflate. This is the "bind the corruption to the fresh arithmetic
AND the real call sequence" lesson, now encoded in `zdhunt`'s tactic library.
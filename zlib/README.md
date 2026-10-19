# zlib — gzseek64 signed 64-bit overflow (UB)

**Status:** CONFIRMED (UBSan) — robustness/UB defect in released **zlib
1.3.2**; fixed in current master. **Not** CVE-worthy on current evidence.

## Report
[`gzseek64-overflow/REPORT.md`](gzseek64-overflow/REPORT.md)

**TL;DR:** `gzlib.c gzseek64()` does `state->x.pos + offset` unguarded on signed
`z_off64_t` (lines 397, 434). Repeated large `SEEK_CUR` calls on one handle push
`x.pos` toward 2^63; the final add overflows (CWE-190 UB). UBSan fires:
```
gzlib.c:397: runtime error: signed integer overflow:
  7658346693619390455 + 7658346693619386827 cannot be represented in 'long int'
```
Differential: present in 1.3.2, clean on master.

## Reachability (honest — caller-driven, not stream-reachable)
The overflowing operand `state->x.pos` is accumulated by the **caller's own**
seek offsets, not derived from the compressed stream. A party that only controls
the compressed bytes (the normal "attacker-supplied gzip" model) cannot push it
toward 2^63. Requires a host app to seek by ~exabyte-scale logical offsets. So:
**no DoS, no ASAN memory-corruption observed, no practical security impact.** It
is recorded because the "bind corruption to the fresh arithmetic AND the real
multi-call seek sequence" method lesson it embodies (stateful bind beats
single-shot inflate) is the reusable takeaway.

## PoC
`poc/trigger-gzseek64-overflow.bin` — 25-byte trigger (stateful gz* seek driver).

Upstream already fixed (master guards `offset > GZ_OFF_MAX - pos` /
`offset < -pos`); related discussions: zlib issues #1222 / PRs #1227, #1245.
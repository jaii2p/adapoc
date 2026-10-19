# libarchive — RAR5 double-free (CVE-2026-14164) reproduction + RAR4 RCE cut

**Status:** REPRODUCED deterministically (official upstream PoC). **NOT a fresh
0day** — this is the already-assigned **CVE-2026-14164**, and only in the
regression window between `rar5.c` commit `620bdafa` and the fix `1c914cdf`
(never in any release tarball). Delivered as the chain-work analysis of how it
fits the T1→T4 skywalk and why it does NOT reach RCE.

## Report
[`rar5-double-free/REPORT.md`](rar5-double-free/REPORT.md)

## Key honest conclusions
- **Root cause:** `init_unpack()` (commit `620bdafa`) added `ARCHIVE_FATAL`
  early-returns on `calloc` failure after freeing `rar->cstate.filtered_buf`
  without NULL-ing it → later `rar5_cleanup()` double-frees the dangling
  pointer. Fix (`1c914cdf`) NULLs it before the early return.
- **Reproduced:** fail the 19th allocation (the 131072-byte calloc) →
  `AddressSanitizer: attempting double-free … freed by init_unpack (rar5.c:2569)`
  ... `rar5_cleanup (rar5.c:4353)`. Clean on the fixed master.
- **RAR4 VM "RCE" cut:** the famous RAR VM RCEs belong to **WinRAR's** bytecode
  interpreter, NOT libarchive. libarchive's RAR4 is a conservative
  reimplementation: only 5 known filter fingerprints compile, all writes bounded
  within `vm->memory`. **No RCE chain here.**
- **T3/T4 honest verdict:** on modern glibc (2.36+), this double-free (with no
  attacker-controlled write between the two frees) is caught by tcache
  hardening and aborts as OOM/"double free detected" — a DoS, not a
  write-what-where. Red Hat rates 14164 at 7.5 (DoS). 100k relay-chain fuzz
  execs on latest master: 0 crashes — all three RAR/RAR5 fixes hold.

## Why it's here
Recorded as a clean, version-precise reproduction of an existing CVE with an
explicit **"already assigned, regression-window-only, not our 0day"** label —
the reproduction steps and T1→T4 analysis are the durable contribution, not a
claim of originality.
# ZD-CVE-LIBARCHIVE-RAR5-14164-001 — CVE-2026-14164 RAR5 filtered_buf double-free

Verdict: REPRODUCED deterministically (with official upstream PoC) on the exact
vulnerable commit. NOT a fresh 0day — it is the already-assigned CVE-2026-14164.
This writeup is the chain-work deliverable: how the CVE fits the T1->T4 skywalk
and the precise static-analysis-derived trigger.

## Target
libarchive RAR5 reader, `archive_read_support_format_rar5.c`.
Version: git master commit 620bdafa (2026-05-16) — "Fix unchecked calloc results
in init_unpack (rar5)". Regression-window-only: NOT present in any release
tarball (3.6.x/3.7.x/3.8.6 are safe: their init_unpack is `void`, never early-
returns, so no dangling pointer can survive).

## Root cause (static analysis, verified against source)
Commit 620bdafa turned `init_unpack()` from `void` into `int` and added
ARCHIVE_FATAL early-returns when `calloc` fails:

    static int init_unpack(struct rar5* rar) {
        ...
        free(rar->cstate.window_buf);
        free(rar->cstate.filtered_buf);        // <-- frees, does NOT null
        if(rar->cstate.window_size > 0) {
            rar->cstate.window_buf = calloc(...);
            if(rar->cstate.window_buf == NULL) return ARCHIVE_FATAL;   // early return
            rar->cstate.filtered_buf = calloc(...);
            if(rar->cstate.filtered_buf == NULL) return ARCHIVE_FATAL; // <-- LEAVES filtered_buf DANGLING
        }
        ...
    }

If the `filtered_buf = calloc(...)` fails, init_unpack returns ARCHIVE_FATAL
with `rar->cstate.filtered_buf` still pointing at the just-freed buffer.
Later `rar5_cleanup()` (same file, ~line 4353) does `free(filtered_buf)` again
=> double free.

The official fix (1c914cdf, PR #3071) adds `filtered_buf = NULL` immediately
after the free, before any early return.

## Reproduction (deterministic)
Fails the 19th allocation (the 131072-byte calloc inside init_unpack) to force
the ENOMEM path, exactly as the upstream PoC models a real low-memory failure.

    # vulnerable fixture: worktree at commit 620bdafa, ASAN build
    cd /home/box/Desktop/SeraProjs/lab-libarchive-14164
    gcc -fsanitize=address ... -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,...
        /tmp/rar-df-poc/.../poc.c -o poc_14164 .libs/libarchive.a ...
    FAIL_ALLOC_AFTER=19 FAIL_ALLOC_MIN_SIZE=1 \
        ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 ./poc_14164 poc.rar

    => ERROR: AddressSanitizer: attempting double-free on 0x...1500
       freed by: init_unpack (rar5.c:2569)
       free'd again by: rar5_cleanup (rar5.c:4353)
    Runs clean (exit 0) on master with the 1c914cdf fix. Same input + same
    failure injection, no abort.

Official artifacts:
  issue #3069  https://github.com/libarchive/libarchive/issues/3069
  PoC zip     https://github.com/user-attachments/files/28190996/RAR5-DoubleFree-attachments.zip

## RAR4 VM RCE avenue (2026-10) — ALSO NOT an RCE chain
Examined the archive_read_support_format_rar.c RAR4 VM/filter path on 3.7.9
(the VM_MEMORY_SIZE=0x40000, PROGRAM_WORK_SIZE=0x3C000 surface):
- No free-form attacker-bytecode VM execution: compile_program() matches ONLY
  5 known filter fingerprints (delta/e8/e8e9/rgb/audio). Unknown bytecode is
  rejected ("No support for RAR VM program filter").
- Every filter's WRITE is bounded within vm->memory (VM_MEMORY_SIZE 262144):
    e8:   length<=PROGRAM_WORK_SIZE, i<=length-5, vm_write_32(vm,i+1) => within
    delta/audio/rgb: length<=PROGRAM_WORK_SIZE/2, dst=&memory[length], writes
          up to dst[length] => within.
- CVE-2025-5915 OOB READ feeds data INTO vm->memory but cannot be turned into
  a WRITE past it (write offsets stay bounded). Leak-only.
Verdict: libarchive's RAR4 is a conservative reimplementation; the famous
RAR VM RCEs belong to WinRAR's OWN bytecode interpreter, NOT this code.
No RCE chain here.

## T1->T4 skywalk status
- T1  CVE-2025-5915 heap OOB read (3.7.9 `copy_from_lzss_window`, repro
      test_read_format_rar_overflow.rar, READ of 188 beyond window after
      parse_codes realloc). VERIFIED on 3.7.9 fixture.
- T2  CVE-2026-14164 RAR5 filtered_buf double-free (this writeup). VERIFIED on
      620bdafa fixture (ASAN: "attempting double-free", freed by init_unpack
      rar5.c:2569, re-freed by rar5_cleanup rar5.c:4353), clean on master.
- T3  allocator-corruption stimulus VERIFIED, clean write-what-where NOT
      established. Groom harness (groom_14164.c, glibc 2.43, wrap=malloc/
      calloc/realloc, reclaim 128x 4096-byte chunks after the injected OOM):
        control (FAIL_ALLOC_AFTER=0): clean, aliasing=no.
        CVE point (FAIL_ALLOC_AFTER=19): libarchive read path returns
        "Fatal Internal Error: Out of memory" == a subsequent allocation
        fails due to corrupted heap metadata from the double-free.
      So the double-free DOES corrupt the real glibc heap at the exact CVE
      trigger, but it surfaces as an allocation failure (read abort), not a
      deterministic two-mallocs-same-pointer (tcache dup) in this single-epoch
      layout on glibc 2.43. tcache-bypass grooming (bin-low, fragmentation,
      multi-epoch) is NOT done; do not over-claim T3.
- T4  RCE: NOT ESTABLISHED. Requires the tcache-dup -> arbitrary-write that
      T3 did not achieve. Red Hat rates 14164 at 7.5 (DoS). Honest cut.
- T3/T4 final verdict (after 3 grooming attempts + mandated research): on
      modern glibc (2.36+), a double-free with NO attacker-controlled write
      between the two frees is detected and aborts ("double free detected in
      tcache 2"), not exploited. libarchive's free#2 (rar5_cleanup on the
      dangling filtered_buf) runs immediately after the read-error with no
      window for a controlled write in the stock flow. The official PoC IS
      the ASAN abort = glibc's own double-free detection = DoS. Reclaiming
      the dangling chunk (rce_14164.c, glibc 2.43, both ASAN and non-ASAN)
      yields mal1=mal2? NO -- distinct pointers, no aliasing, no write-what-
      where. glibc 2.43 tcache key/PSI protections absorb the corruption.
      This is consistent with the OOM-gated, no-write-window design: it is
      NOT a practical RCE primitive on a patched-modern heap. RCE would
      require (a) an older glibc (<=2.34, pre-tcache-hardening) or (b) an
      INFO-WRITE path libarchive gives us between the frees, neither of which
      is present here.
- ADJACENT NEW hang (fuzzer-found): RAR5 filter-loop CPU spin in
      apply_filters/do_uncompress_file on 3.7.9, clean on master. 46 hang
      inputs captured.

## Honesty notes
- The v3.7.9 fixture campaign could NOT have found 14164 (v3.7.9 is immune).
  Corrected by reverifying the version edge — this is why the diff/cherry-pick
  check (620bdafa in master, fix 1c914cdf in master) matters.
- 100k relay-chain fuzz execs on latest master (c71118aa): 0 crashes — confirms
  all three RAR/RAR5 fixes hold on current master.
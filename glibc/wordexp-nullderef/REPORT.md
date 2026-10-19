# glibc 2.43 (Debian 2.43-4) wordexp NULL-deref via $[$@ — cross-component crash

Status: CONFIRMED, minimal 4-byte trigger, reproduced in the DEPLOYED system
libc (not a standalone/harness artifact).

## Trigger (minimal)
    wordexp("$[$@", &p, WRDE_NOCMD)  -- 4 bytes
Requires the CALLING PROCESS to have __libc_argc >= 3 (invoked with >=2
arguments; i.e. every real program except the trivial case).  Without that
argv precondition wordexp returns WRDE_SYNTAX (rc=5) cleanly.

## Evidence
- ASAN: SEGV, READ at address 0x10, in /usr/lib/x86_64-linux-gnu/libc.so.6
  (BuildId eaf531...), pc +0xfd18e, inside wordexp. Repro with 3+ argv:
      env -i HOME=/tmp ./prog A B   # argc=3
      wordexp("$[$@", ...)  ->  SEGV READ @0x10, rbx=0, rdx=3(argc)
- argc sweep (plain C, real libc): argc=1 -> rc=5; argc=2 -> rc=5; argc=3 ->
  SEGV.  The gate is exactly `if (__libc_argc > 2)` (wordexp.c:1462).
- Instrumented standalone build (fuzz/shim + forced -include libc-config.h):
  full 15-byte fuzz artifact `$]$[#\x03:,$?\x04$@$*` collapses to the same
  `$[$@` core; backtrace parse_dollars -> parse_arith(wordexp.c:667) ->
  parse_dollars(2050) -> parse_param(1469) -> w_addword(NULL).

## Root cause (source-verified)
- parse_dollars case '[' (wordexp.c:2041-2045) calls parse_arith WITHOUT a
  wordexp_t.  parse_arith (wordexp.c:667) invokes the NESTED
  `parse_dollars(&expr,...,pwordexp=NULL,...)` and passes NULL straight
  through.
- Inside that nested parse, `$@` (quoted semantics in an expansion context)
  reaches parse_param.  parse_param's `$@` handler (1460-1482):
      if (__libc_argc == 2)            -> value = argv[1];      (safe)
      else if (__libc_argc > 2) {      // <-- ours
        value = w_addstr(...);
        if (value == NULL || w_addword (pwordexp, value))  // pwordexp==NULL
      }
  w_addword(NULL, value) dereferences pwordexp->we_wordc / we_offs
  (worst: realloc(NULL)+write).  Cross-component trust boundary: the
  arithmetic-expansion layer passes a NULL list provider down into the
  parameter-expansion layer, which assumes a valid wordexp_t and even writes
  through it.

## Attacker model / impact
- Input: attacker-controlled WORDS string compiled with wordexp().  Reachable
  anywhere untrusted data is word-expanded: shells/daemons/log tools invoking
  wordexp on user/incoming strings, or the same class of code paths as the
  earlier regex DoS.
- Trigger is tiny (4 bytes); precondition (argc>=3) holds for essentially all
  target processes.
- Impact: NULL-pointer dereference READ -> SIGSEGV / crash of the calling
  process.  A DoS, not (yet shown to be) memory corruption: the write
  primitive is `realloc(NULL,...)` then `we_wordv[we_offs+we_wordc++]=word`
  into the freshly allocated vector, which is bounded by realloc's own return —
  so currently a crash, not an arbitrary write.  Deeper memory-corruption
  potential would require corrupting pwordexp/we_offs around the NULL, which
  this specific entry does not obviously permit.
- Benchmarked against regex-DoS finding: same shape (untrusted WORDS into a
  glibc string-expansion sink), but this one is a clean NULL-deref crash in
  the deployed libc.

## Honest framing
- This is reached via a CONFORMING wordexp() call with only the WORDS string
  attacker-controlled (flags fixed to WRDE_NOCMD).  NOT the APPEND/REUSE
  harness-misuse classes triaged earlier (those were API-contract violations
  by the caller; this one is a valid call crashing on attacker data).
- Upstream novelty not yet confirmed; glibc's parse_param/$@ inside parse_arith
  NULL handoff is plausibly known/underpatched.  Empirically 2.43-4 (Debian)
  is vulnerable to a 4-byte crash.

## Reusable lens
"Arithmetic/sub-expression expansion layer hands a NULL container down into a
nested parameter-expansion layer that dereferences/writes through it."  The
fault is the NULL list-provider crossing a parser boundary, gated by an
unrelated process-side quantity (argc).  Detected because the chained-mutation
fuzzer drove `$[` (arith entry) + `$@/$*` (param sink) together across the
cross-component boundary — the ORIGINAL cross-call theory.

## Files
- fuzz/wordexp_harness.c (conforming-flags harness), fuzz/wordexp_instr_fuzz
  (instrumented wordexp+glob), fuzz/shim/* (standalone config), fuzz/wx_*.c
  (reproducers: wx_argc argv sweep, wx_min3 minimal).
- Cross-call instrumented campaign used the chained-mutation genotype
  (flag bits x WORDS bytes), cov 3 -> 360 edges, produced the original
  15-byte artifact before bisection.
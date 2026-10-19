# glibc wordexp NULL-deref — cross-component crash via $[$@

CWE-476 (NULL pointer dereference) — glibc 2.43-4 (Debian), `posix/wordexp.c`.
Status: **CONFIRMED** (this session, reproduced in the **deployed** system libc,
not a harness artifact).

## Trigger (minimal — 4 bytes)
```
wordexp("$[$@", &p, WRDE_NOCMD)
```
Precondition: the calling process has `__libc_argc >= 3` (invoked with ≥2 args —
true of essentially every real program).

## Mechanism (source-verified)
`parse_dollars` case `'['` (`wordexp.c:2041-2045`) calls `parse_arith` WITHOUT a
`wordexp_t`; `parse_arith`'s nested `parse_dollars` sees `$@` under argc>2 and
`parse_param` (`1460-1482`) runs `w_addword(pwordexp=NULL, value)` →
`w_addword` dereferences/writes through the NULL `wordexp_t` → **SEGV READ @0x10**
in `/usr/lib/x86_64-linux-gnu/libc.so.6` (`wordexp.c:1469`).

The arithmetic-expansion layer hands a NULL list-provider down into a nested
parameter-expansion layer that assumes a valid struct — a cross-component trust
boundary, gated by an unrelated process-side quantity (argc).

## PoC
`poc/poc_wordexp_nullderef.c`:

| invocation | result |
|---|---|
| `./poc_wordexp_nullderef A B`  (argc=3) | **SEGV** (exit 139, READ @0x10) |
| `./poc_wordexp_nullderef`        (argc=1) | clean `rc=5` (WRDE_SYNTAX) |

The gating is exactly `if (__libc_argc > 2)` at `wordexp.c:1462`.

## Impact
NULL-pointer-deref crash (DoS) of the calling process from a 4-byte
attacker-controlled WORDS string. Trivial trigger, near-universal precondition.
Currently a crash, not (yet) proven memory corruption: the write primitive is
`realloc(NULL,…)` + a bounded vector store.

## Honest scoping
- Reached via a **conforming** `wordexp()` call (flags fixed to WRDE_NOCMD),
  only WORDS attacker-controlled — not an API-contract violation.
- Upstream novelty not confirmed; glibc's `parse_param/$@`-inside-`parse_arith`
  NULL handoff may be known. Empirically 2.43-4 is vulnerable to a 4-byte crash.

## Lens
"Arithmetic/sub-expression expansion layer hands a NULL container down into a
nested parameter-expansion layer that dereferences/writes through it." The
fault is the NULL list-provider crossing a parser boundary, gated by an
unrelated proc-side quantity (argc). Detected by the cross-component
chained-mutation fuzzer driving `$[` (arith entry) + `$@/$*` (param sink)
together.
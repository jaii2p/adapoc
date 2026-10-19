# glibc — confirmed findings

Vulnerability research against the **deployed Debian glibc 2.43-4** (static
first, targeted chained-mutation fuzzing, empirical on-system confirmation).
Both findings below were confirmed **this session** against the real installed
libc (not a standalone/harness rebuild).

| finding | type | trigger | confirmed |
|---|---|---|---|
| [`regex-plus-dos/`](regex-plus-dos/) | CWE-400 resource-exhaustion DoS — `regcomp` exponential AST (chained `+`) | `x` + 21 `+` (23 B), REG_EXTENDED | YES — ~2x RSS/plus; 1.6 GB live heap at 21 `+` |
| [`wordexp-nullderef/`](wordexp-nullderef/) | CWE-476 NULL-deref crash — `$[$@` via parse_arith NULL handoff | `wordexp("$[$@")` 4 B, argc≥3 | YES — SEGV READ @0x10 in deployed libc |

Notable scanned-but-not-a-finding (linked context lives upstream in
`aiexclfindings`): C1 `iconv` (guarded template, not worth fuzzing) and C2
`locale/loadlocale.c` (candidate; the ±1-byte boundary needs a targeted harness
before it can be a claim — not yet confirmed, so not published here).
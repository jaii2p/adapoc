# glibc regex-plus DoS — regcomp memory-exhaustion via chained '+' postfix

CWE-400 (resource exhaustion) — glibc 2.43-4 (Debian), `posix/regcomp.c`.
Status: **CONFIRMED** (this session, verified against the deployed system glibc).

## Trigger
REG_EXTENDED pattern = `<atom>` + **N consecutive `+`** postfix operators:
```
x+++++++++++++++++++++    (21 '+', 23 bytes)
```

## Mechanism (source-verified)
Each `+` wraps the **whole** accumulated AST in `OP_DUP_ASTERISK` after
`duplicate_tree()` copies it (`regcomp.c:2585-2589`, `2445-2467`, `2619`,
`3913`). No node budget → the AST (and its allocations) ~**doubles** per `+`.

Measured peak RSS per plus-count (this session, `poc_regex_plus_dos`):
```
 N=15 ->  11 MiB     N=18 ->  99 MiB
 N=16 ->  23 MiB     N=19 -> 202 MiB
 N=17 ->  49 MiB     N=20 -> cap-hit (>512) → under a host cap regcomp rc=12
```
Clean ~2x/step exponential. On an unbounded host the original campaign measured
**1.6 GB live heap (1.68M chunks) at 21 '+'** and 1.1 GB RSS.

## PoC
`poc/poc_regex_plus_dos.c` — forks a child under a hard `RLIMIT_AS` (default
512 MiB) and sweeps N, printing peak RSS per '+' so the exponential growth is
proven **without OOMing the host**. Under the cap the child either hits the
cap (regcomp returns REG_ESPACE / is killed by the limit) — either way, a
~20-byte pattern exhausts ~the whole cap.

```
gcc -O1 -g -o poc_regex_plus_dos poc_regex_plus_dos.c
./poc_regex_plus_dos [maxN] [capMiB]     # defaults 22 512
```

## Impact
Resource-exhaustion DoS of any process that compiles attacker-or-untrusted
regexes: grep/sed/awk over untrusted files, log/regex filters, web filters.
Not memory corruption — pure heap blowup. Small (23-byte) trigger.

## Honest scoping
- Not confirmed against a specific CVE / upstream status not verified for this
  version; empirically glibc 2.43-4 is vulnerable to a short DoS trigger.
- It's a DoS/resource-limit bug (huge allocations), not a linear overrun.
- Suggested fix: cap `duplicate_tree`/`parse_dup_op` total node budget.

## Lens
Chained POSTFIX/quantifier ops where each wraps-and-clones the whole prior
sub-tree → exponential AST growth. Look for "build node, then duplicate the
prior whole thing", not just "loop over input". ~2x RSS per step = the tell.
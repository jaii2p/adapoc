# glibc 2.43 regcomp — memory-exhaustion DoS via chained '+' postfix operators

Status: CONFIRMED, reproducible (single input), standalone build + ASAN.

## Trigger
REG_EXTENDED pattern consisting of a base atom followed by a long run of
consecutive '+' postfix operators:
    x+++++++++++++++++++++   (21 '+'s)
38-byte input from the fuzzer corpus; exact artifact:
    fuzz/crashes/oom-dc16e14e2e16f92f8c2042296d411ebdcbf31ce7

## Evidence
- Single-input reproduction: regcomp exhausts libFuzzer default RSS cap
  (used: 2348Mb; limit: 2048Mb).
- Live heap: 1,648,499,185 bytes in 1,677,755 chunks (1.6 GB live), all from:
    parse_dup_op        regcomp.c:2619
      -> duplicate_tree regcomp.c:3913
        -> create_token_tree regcomp.c:3833
- Threshold driver (char_threshold, ASAN), peak RSS per plus-run length:
    n=16 ->  70 MB
    n=18 -> 281 MB
    n=20 -> 517 MB
    n=21 -> 1139 MB   (>1GB, break)
  Growth is ~2x per additional '+': exponential AST duplication.

## Root cause
Mechanism (source-verified):
- OP_DUP_PLUS -> start=1, end=-1 (regcomp.c:2585-2589).
- parse_expression's postfix `while` loop (regcomp.c:2445-2467) runs once per
  consecutive `+`, each time passing the WHOLE accumulated tree to
  parse_dup_op.
- parse_dup_op: start==1>0 and start!=end, so line 2619
  `elem = duplicate_tree(elem, dfa)` DUPLICATES the entire tree, then line 2633
  wraps OP_DUP_ASTERISK around it. The doubled tree becomes the input to the
  next `+`.
Thus k consecutive `+` deposit ~2^k AST nodes. create_token_tree /
duplicate_tree have NO total-node budget, so memory grows exponentially with
the plus-run length. (~2x RSS per added '+'; 21 '+' > 1 GB.)

## Attacker model / impact
- Input: a short attacker-controlled regex string (pattern only; no data
  contents needed). Reachable anywhere untrusted regexes are compiled:
  grep/sed/awk over untrusted files, web/libre sport regex filters, log
  analysis, setuid-adjacent tools that compile user input.
- Effect: memory exhaustion (DoS) of the calling process. Several hundred MB
  from a ~20-byte pattern; GBs shortly after. Not memory corruption (no OOB
  write), but a genuine resource-exhaustion DoS.

## Honest scoping
- glibc regex is heavily fuzzed; a chained-quantifier OOM family is plausibly
  known to maintainers but patched slowly. I have NOT confirmed upstream
  disclosure status for 2.43 (need a version-diff / advisory check). The
  finding stands as empirical: 2.43 is vulnerable to a ~21-byte DoS trigger.
- It is a DoS/correctness-of-resource-limits bug, not RCE (in-process; the
  overflow is of the heap via huge allocations, not a linear buffer overrun).

## Fuzz campaign log
- Initial 2 campaigns aborted at start: dict was missing once, then malformed
  (literal '\n\^' rejected). Net-new: 2 harness fault classes found+fixed
  first (header OOB read; non-NUL-terminated POSIX strings). After those,
  first real run produced the OOM artifact in ~seconds.
- libFuzzer: 2983 inline counters, entropic schedule, dict of regex syntax.
  The '+' run was reached via dict insert of 'regex_star_group' + repeated
  InsertRepet'-'-Bytes + ChangeBit on cflags to REG_EXTENDED.

## Minimal Fix (upstream hint)
Cap duplicate_tree / parse_dup_op total node budget (glibc already has a
tree-size guard pattern for other regex limits); reject or bound consecutive
unbounded postfix operators rather than duplicating without a node count cap.

## Reusable lens
Chained POSTFIX/quantifier operators where each wraps-and-CLONES the whole
accumulated sub-tree -> exponential AST growth. Same shape as ReDoS backtracks:
look for "build a node, then duplicate the previous whole thing", not just
"loop over input". Measure RSS growth rate; exponential doubling = the tell.
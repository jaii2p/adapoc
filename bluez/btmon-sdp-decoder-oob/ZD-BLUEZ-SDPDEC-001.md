# ZD-BLUEZ-SDPDEC-001 — Byte-walk OOB read + heap-byte emission in hcidump SDP decoder (tools/parser/sdp.c print_string)

AI-exclusive finding · BlueZ 5.85 (fixture) · upstream master IDENTICAL (checked 2026-10-09)

## TL;DR
`tools/parser/sdp.c` `print_string()` (line 352) walks `n` bytes of
`frm->ptr[i]` where `n` is the attacker-declared data-element length
(size-index 7 -> `p_get_u32`, up to 0xFFFFFFFF) with **no comparison against
`frm->len`**. A String/URL element declaring more bytes than the PDU contains
drives the byte walk past the end of the input buffer.

* ASAN build: deterministic `heap-buffer-overflow READ of size 1`,
  frames `sdp.c:357` (+1 case) / `sdp.c:360` (non-printable probe, +2/256/64Ki).
* **Stock (non-ASAN) build: NO crash — the over-read byte is silently EMITTED
  to stdout** in the hex branch: input carries only `DEEPSINK` (8 bytes), the
  decoder prints `44 45 45 50 53 49 4e 4b 91` — the trailing `91` is adjacent
  heap memory. Info disclosure (CWE-125 -> CWE-200), not just a crash.

Delivery: `hcidump -r <crafted dump>` (tools/parser/sdp.c is in
`tools_hcidump_SOURCES`, Makefile.tools:441-464) or any consumer linking the
decoder; proven through the real `sdp_dump()` entry (l2cap.c:1113 PSM 0x0001
dispatch) in an ASAN harness.

## 1. Metadata
| Field            | Value                                                                |
|------------------|----------------------------------------------------------------------|
| Title            | wire u32 string length -> unbounded byte walk -> OOB read + emission |
| Component        | BlueZ `tools/parser/sdp.c` `print_string` (hcidump decoder)          |
| Affected         | BlueZ 5.85 fixture; upstream master byte-identical (curl 2026-10-09) |
| Fixed in         | NONE (no guard on upstream master as of 2026-10-09)                  |
| CVE              | NONE assigned to this defect (distinct file/decoder from the         |
|                  | monitor/sdp.c family; prior monitor CVEs below)                      |
| CWE              | CWE-125 (OOB read), emitted bytes = CWE-200 disclosure               |
| Severity (file)  | 5.5 — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N                  |
| Reachability     | analyst opens crafted dump (`hcidump -r`), UI:R, no auth             |
| Reporter         | seraphine AI agent, deep-sink chained-mutation campaign              |
| First hit        | 2026-10-09                                                           |
| Build/flags      | gcc 16.2 `-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined` |
|                  | (proof) + same source non-ASAN (emission)                            |

## 2. Description
```c
/* tools/parser/sdp.c:352 */
static inline void print_string(int n, struct frame *frm, const char *name)
{
    int i, hex = 0;
    for (i = 0; i < n; i++) {                 /* n = attacker u32   */
        if (i == (n - 1) && ((char *) frm->ptr)[i] == '\0') break;
        if (!isprint(((char *) frm->ptr)[i])) { hex = 1; break; }  /* :360 */
    }
    ...
    for (i = 0; i < n; i++)                   /* hex branch prints  */
        printf(" %02x", ((unsigned char *) frm->ptr)[i]);          /* :369 */
    frm->ptr += n; frm->len -= n;             /* len may underflow  */
}
```
`n` comes from `parse_de_hdr()` (:229): size-index 7 reads a 4-byte BE length
(`p_get_u32`) — fully attacker-controlled. No `n <= frm->len` check exists
anywhere on this path (grep on upstream master: no guard found).

## 3. Steps to reproduce
```sh
# regenerate the seed family (exact-fit control + cliff triggers)
python3 /home/box/BTHunt/orch/gen_deep_seeds.py
# control (declared == present) must decode to the bottom:
/home/box/BTHunt/orch/harness/stageC_sdpdump < /home/box/BTHunt/seeds-deep/raw/s1_cliff_valid.bin ; echo $?   # 0, prints str "..."
# trigger (declared == present+1): ASAN fault at print_string
/home/box/BTHunt/orch/harness/stageC_sdpdump < /home/box/BTHunt/seeds-deep/raw/s1_nplus1.bin ; echo $?         # 1, heap-buffer-overflow
# bigger windows: s1_nplus2 / s1_n256 / s1_nbig — same frame (sdp.c:360)
```
Saved triggers (re-run from these exact paths): none copied here per
"reports only" — regenerate with the command above; also caught live by
zdhunt stacks (7/400 trials at sdp.c:360/:369).

## 4. Differential (authoritative, this box, 2026-10-09)
| Input                              | ASAN harness        | stock (non-ASAN)      |
|------------------------------------|---------------------|-----------------------|
| s1_cliff_valid (n == present)      | rc=0, bottom marker | rc=0, full decode     |
| s1_nplus1 (n = present+1)          | rc=1 heap-overflow READ, sdp.c:357 | rc=0, **emits 91** (heap byte) |
| s1_nplus2 / s1_n256 / s1_nbig      | rc=1 heap-overflow READ, sdp.c:360 | rc=0, emits over-read hex  |

Stock emission, verbatim:
```
str 44 45 45 50 53 49 4e 4b 91
             ^^^^^^^^ = "DEEPSINK" (all input bytes)
                            ^^ = adjacent heap byte, EMITTED
```

## 5. Impact
- OOB READ of attacker-chosen distance at the bottom-most decoder consumer;
  on stock builds the bytes are printed (disclosure of adjacent heap:
  pointers, env material) with NO crash — silent leak, repeatable.
- Upstream master UNPATCHED (verified by source fetch, same lines).
- No write / no control flow from this block alone — it is a chain rung
  (disclosure primitive), not an RCE claim.

## 6. Fix (suggested)
```c
if (n < 0 || (size_t)n > frm->len) { printf(" str(err)"); return; }
/* and clamp the hex/print loops to min(n, frm->len) */
```

## 7. References
- `tools/parser/sdp.c`: `print_string` 352-379, `parse_de_hdr` 229-251,
  `print_de` 390-431; `tools/parser/parser.h` `p_get_u32` (unchecked)
- `Makefile.tools:441-464` — tools_hcidump_SOURCES includes tools/parser/sdp.c
- Same-class priors (DIFFERENT file/decoder): CVE-2016-9799/9802/9918
  (monitor packer over-reads, 5.42, fixed); ZD-BLUEZ-SDPMON-001 (our prior
  monitor/sdp.c uint32 overflow) — this is the hcidump twin, unguarded.
- Harness: /home/box/BTHunt/orch/harness/stageC_sdpdump.c (real sdp_dump);
  seeds: /home/box/BTHunt/orch/gen_deep_seeds.py

## 8. Method note
Deep-sink, not blind: seed built exact-fit at the terminal byte walk
(declared == present, marker verified at bottom), cliff probes +/-1 proved the
sink live BEFORE any campaign; 400 stacked creative stacks (3+ mutators,
>=3 groups) on the raw seed hit print_string in 7/400 trials among 290 total
crashes (dominant sites were :564/:777/:744, filed separately). Emission was
then proven on a non-ASAN build of the same source.

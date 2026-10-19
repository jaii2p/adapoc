# ZD-BLUEZ-SDPDEC-003 — cont-length-driven print loop OOB read + emission (tools/parser/sdp.c print_cont_state :556-566)

AI-exclusive finding · BlueZ 5.85 (fixture) · upstream master IDENTICAL (checked 2026-10-09)

## TL;DR
```c
/* tools/parser/sdp.c:556 */
static inline void print_cont_state(int level, unsigned char *buf)
{
    uint8_t cont = buf[0];              /* :558 first byte at `buf`      */
    ...
    for (i = 0; i < cont + 1; i++)
        printf(" %2.2X", buf[i]);       /* :564 reads+EMITS cont+1 bytes */
}
```
`buf` is `frm->ptr` or `frm->ptr + count` — a position reached through
unchecked advances/offsets (see SDPDEC-002). The loop length is the WIRE BYTE
`buf[0]`: up to **256 bytes read from an attacker-chosen position with zero
bounds check**, and every byte is `printf`'d as hex — i.e. the over-read
bytes go straight to stdout. ASAN: `READ of size 1` at sdp.c:564 (166/400
stacked trials — the dominant site of this campaign).

Stock (non-ASAN) build: **no crash, silent disclosure.** The saved trigger's
emitted `cont` line runs 91 hex bytes and visibly includes the process's own
stdio text (`... 3E 20 53 44 50 20 53 53 41 20 52 73 70 ...` = `> SDP SSA
Rsp ...`) read from the heap PAST the input buffer — over-read emission
demonstrated on a stock binary.

## 1. Metadata
| Field            | Value                                                                |
|------------------|----------------------------------------------------------------------|
| Title            | wire cont byte -> unbounded print loop -> OOB read + hex emission    |
| Component        | BlueZ `tools/parser/sdp.c` `print_cont_state` (hcidump decoder)      |
| Affected         | BlueZ 5.85 fixture; upstream master byte-identical (curl 2026-10-09) |
| Fixed in         | NONE                                                                 |
| CVE              | NONE assigned to this defect                                          |
| CWE              | CWE-125 (OOB read) + emitted bytes = CWE-200 disclosure              |
| Severity (file)  | 5.5 — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N                  |
| Reachability     | analyst opens crafted dump (`hcidump -r`), UI:R, no auth             |
| Reporter         | seraphine AI agent, deep-sink chained-mutation campaign              |
| First hit        | 2026-10-09                                                           |
| Build/flags      | gcc 16.2 `-O1 -g -fsanitize=address,undefined` (proof) + non-ASAN (emission) |

## 2. Description
`print_cont_state` is called from six sites in `sdp_dump` (:692, :718, :734,
:752, :767, :785) — always with a raw pointer, never a remaining-length
argument. `buf[0]` (the continuation-state length byte per SDP spec, max
legit 16) is taken as the loop bound: `cont + 1` iterations of
`printf("%2.2X", buf[i])`. Two ways to go out of bounds:
1. `buf` itself is at/past the end (earlier unchecked advance / offset), so
   even `buf[0]` is OOB (ASAN at :558).
2. `buf` is near the end and `buf[0]` is large: the loop walks past the end
   (dominant ASAN site :564) — and on stock builds keeps printing.

Because the primitive EMITS, this is a disclosure engine, not just a crash:
the read bytes land in the analyst's terminal (or redirected output).

## 3. Steps to reproduce
```sh
# ASAN proof (regenerable seed family):
python3 /home/box/BTHunt/orch/gen_deep_seeds.py
/home/box/BTHunt/orch/harness/stageC_sdpdump < /home/box/BTHunt/seeds-deep/raw/s1_cliff_valid.bin ; echo $?  # 0 control
# saved trigger (captured from a zdhunt creative stack):
/home/box/BTHunt/orch/harness/stageC_sdpdump < /home/box/BTHunt/orch/trigger-003-cont-state.bin ; echo $?    # 1, sdp.c:564
# stock emission proof (non-ASAN build of the same source):
gcc -O1 -g -I. -I<bluez> -I<bluez>/lib -I<bluez>/tools/parser stageC_sdpdump.c <bluez>/tools/parser/sdp.c ...
<stageC_stock> < trigger-003-cont-state.bin | tail -1
# -> 91 hex bytes incl. "3E 20 53 44 50 ..." (= "> SDP SSA Rsp") read from HEAP, exit 0
```

## 4. Differential (authoritative, this box, 2026-10-09)
| Input                              | ASAN build                  | stock (non-ASAN)              |
|------------------------------------|-----------------------------|-------------------------------|
| control seed (cont byte in-bounds, small) | rc=0, `cont 00`       | rc=0                          |
| trigger-003-cont-state.bin         | rc=1 `heap-buffer-overflow READ of size 1`, sdp.c:564 | rc=0, emits 91 hex bytes incl. bytes past input |
| stacked-mutation corpus (400 trials) | 166 hits at :564 (top site) | —                             |

## 5. Impact
- Attacker-chosen-position, up-to-256-byte OOB READ whose bytes are
  PRINTED — clean info-disclosure primitive (adjacent heap: stdio buffers,
  allocator metadata, pointers, env), silent on stock binaries.
- Highest-yield site of this campaign (166/400) — it is the natural
  discharge point for any earlier unchecked advance (SDPDEC-002 supplies
  exactly that position via `ptr + count`).
- Upstream master UNPATCHED. Read/emit only; no write or control flow
  claimed from this block alone.

## 6. Fix (suggested)
```c
static void print_cont_state(int level, struct frame *frm)
{
    if (frm->len < 1) { printf(" cont(err)\n"); return; }
    uint8_t cont = frm->ptr[0];
    if ((size_t)cont + 1 > frm->len) cont = frm->len - 1;  /* clamp */
    for (i = 0; i < cont + 1; i++) { printf(" %2.2X", frm->ptr[i]); }
    frm->ptr += cont + 1; frm->len -= cont + 1;
}
```

## 7. References
- `tools/parser/sdp.c` print_cont_state 556-566; call sites 692/718/734/752/767/785
- position suppliers: p_get_* unchecked (parser.h), `ptr + count` (:752/:785)
- `Makefile.tools:441-464` hcidump link line
- Same-class priors: CVE-2016-9802 etc. (monitor packer, different file);
  ZD-BLUEZ-SDPDEC-002 supplies the offset that reaches this sink.
- Trigger: /home/box/BTHunt/orch/trigger-003-cont-state.bin (49 B, saved from
  zdhunt creative stack `oss_* + recurcliff`, seed 777)

## 8. Method note
Bottom-first: sink defined as the deepest emitter (the hex print loop),
exact-fit control built to reach it clean, cliff reached via stacked creative
arms (3+ mutators from >=3 groups) — NOT blind fuzzing; the campaign input was
the exact-fit control and the crash distribution was measured over 400 trials
(:564 166, :777 115, :744 2, :360/:369 7) then trigger minimized to a single
saved input and re-run from its stored path.

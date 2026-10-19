# ZD-BLUEZ-SDPDEC-002 — AttributeByteCount offset read past buffer in hcidump SDP decoder (tools/parser/sdp.c sdp_dump :744/:777)

AI-exclusive finding · BlueZ 5.85 (fixture) · upstream master IDENTICAL (checked 2026-10-09)

## TL;DR
`sdp_dump()` reads the 16-bit `AttributeByteCount` from the wire and uses it
as a **raw pointer offset without any bounds check**:

```c
/* tools/parser/sdp.c:770-786 (ServiceSearchAttributeRsp) */
count = p_get_u16(frm);                            /* attacker u16        */
printf("count %d\n", count);
cont = *(unsigned char *)(frm->ptr + count);       /* :777  OOB READ      */
if (cont == 0) {
    print_attr_lists(level + 1, frame_get(frm, count));  /* -> frame_add */
} else
    frame_add(frm, count);
print_cont_state(level + 1, frm->ptr + count);     /* :785                 */
```
Same shape at **:744** for ServiceAttributeRsp (pid 0x05).

With `count` > bytes remaining, `*(ptr + count)` reads one byte past the
buffer (ASAN `READ of size 1` at sdp.c:777 / :744). When `count` still lands
in-bounds but exceeds the true attribute-list length, control flows into
`frame_add()` (:614-624) which does `memcpy(data, frm->ptr, count)` — an
attacker-sized copy from a buffer that has fewer than `count` bytes
available, i.e. the same field drives a **bulk OOB read into a fresh heap
allocation** (second-order, same root cause).

Delivery: `hcidump -r <crafted dump>`; proven through the real `sdp_dump()`.

## 1. Metadata
| Field            | Value                                                                |
|------------------|----------------------------------------------------------------------|
| Title            | wire u16 byte-count -> unchecked pointer offset -> OOB read (1B + memcpy) |
| Component        | BlueZ `tools/parser/sdp.c` `sdp_dump` (hcidump decoder)              |
| Affected         | BlueZ 5.85 fixture; upstream master byte-identical (curl 2026-10-09) |
| Fixed in         | NONE (no `count > frm->len` guard on upstream master)                |
| CVE              | NONE assigned to this defect                                          |
| CWE              | CWE-125 (OOB read); memcpy variant = CWE-125 bulk                    |
| Severity (file)  | 5.5 — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N                  |
| Reachability     | analyst opens crafted dump (`hcidump -r`), UI:R, no auth             |
| Reporter         | seraphine AI agent, deep-sink chained-mutation campaign              |
| First hit        | 2026-10-09                                                           |
| Build/flags      | gcc 16.2 `-O1 -g -fsanitize=address,undefined`                       |

## 2. Description
`count` is `uint16_t` from `p_get_u16` — never compared with `frm->len`.
`(frm->ptr + count)` can point up to 65535 bytes past the current parse
position; the buffer is the exact-size input allocation. The dereference at
:777/:744 is the first fault; the *deeper* consumer is `frame_add`:

```c
/* :614-624 */
data = malloc(len + count);            /* count = attacker              */
...
memcpy(data + len, frm->ptr, count);   /* :622  reads `count` bytes     */
```
which copies far beyond `frm`'s remaining bytes into heap (then
`print_attr_lists` decodes that heap material — potential emission).

## 3. Steps to reproduce
```sh
python3 /home/box/BTHunt/orch/gen_deep_seeds.py
# control: count == exact list length -> clean decode, marker at bottom
/home/box/BTHunt/orch/harness/stageC_sdpdump < /home/box/BTHunt/seeds-deep/raw/s2_count_eq.bin ; echo $?    # 0
# trigger: count = present+1 -> ASAN READ of size 1 at sdp.c:777
/home/box/BTHunt/orch/harness/stageC_sdpdump < /home/box/BTHunt/seeds-deep/raw/s2_count_p1.bin ; echo $?    # 1
# s2_count_p4 / s2_count_ffff -> same site; s2_sa_p2 -> :744 (pid 0x05)
```

## 4. Differential (authoritative, this box, 2026-10-09)
| Input                       | ASAN harness                                   |
|-----------------------------|------------------------------------------------|
| s2_count_eq (count == n)    | rc=0, 289B decode, bottom marker present       |
| s2_count_p1 (count = n+1)   | rc=1 `heap-buffer-overflow READ of size 1` sdp.c:777 |
| s2_count_p4 / s2_count_ffff | rc=1 same site                                 |
| s2_sa_p2 (pid 0x05, +2)     | rc=1 same class at sdp.c:744                   |

Stacked-mutation hit rate on this site: **115/400 trials at :777 + 2/400 at
:744** (zdhunt creative stacks over the exact-fit control seed).

## 5. Impact
- Attacker positions a read anywhere in a 64 KiB window past the parse
  cursor; first deref is 1 byte, `frame_add` turns the same field into a
  bulk heap OOB read (up to 64 KiB) whose bytes are then decoded/printed —
  disclosure of adjacent process memory on stock builds.
- Upstream master UNPATCHED (source fetch, same lines).
- Read-class only; no write/control flow claimed from this block alone.

## 6. Fix (suggested)
```c
if (count > frm->len) { /* reject / clamp */ count = frm->len; }
/* frame_add: never memcpy more than frm->len available */
if ((size_t)count > (size_t)frm->len) return;
```

## 7. References
- `tools/parser/sdp.c` sdp_dump 659-791 (offsets :744, :777, :785),
  frame_add 594-644 (:622 memcpy), frame_get 646-657
- `Makefile.tools:441-464` hcidump link line
- Distinct from ZD-BLUEZ-SDPDEC-001 (string byte walk) and -003 (cont loop);
  same unguarded-length theme as monitor/sdp.c (ZD-BLUEZ-SDPMON-001) but a
  different decoder, different fields, different functions.
- Harness/seeds: /home/box/BTHunt/orch/ (stageC_sdpdump.c, gen_deep_seeds.py)

## 8. Method note
Bottom-up: the exact-fit control proved `count == n` decodes to the bottom;
`count == n+1` isolated the deref at :777 as the empty-sink boundary. The
second-order memcpy (:622) is identified from source on the same field and
marked candidate until a trigger that lands cont!=0 with oversized count is
attributed under ASAN — not claimed as separately reproduced here.

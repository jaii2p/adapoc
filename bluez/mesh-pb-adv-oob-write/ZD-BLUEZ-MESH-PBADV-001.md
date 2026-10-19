# ZD-BLUEZ-MESH-PBADV-001 — Mesh PB-ADV SAR START: unchecked copy size -> attacker-controlled heap OOB WRITE (mesh/pb-adv.c:430) + silent in-chunk corruption of session->user_data

AI-exclusive finding · BlueZ 5.85 (fixture) · upstream 5.87-era source checked 2026-10-09

## TL;DR
`pb_adv_packet()` (mesh/pb-adv.c:300) never validates `len` (no `>= 7` guard
before `pkt += 7; len -= 7`), and the SAR START branch checks the DECLARED
length but not the COPY length:

```c
session->exp_len = l_get_be16(pkt);
if (session->exp_len > sizeof(session->sar)) return;   /* <= 80 checked   */
...
memcpy(session->sar, pkt + 3, len - 3);                /* len-3 NEVER checked */
```
`session->sar` is 80 bytes inside a 168-byte heap object (`l_new` via
`pb_adv_reg`). Copy size = `L - 10` where L = advertising-packet length.

**Measured (real pb-adv.o + real pb_adv_reg acceptor flow, ASAN+UBSAN):**

| L (AD len) | copy | result |
|---|---|---|
| 31 (legacy adv max) | 21 | **control: clean, rc=0** |
| 100 | 90 | survives — silent in-chunk corruption (uuid region) |
| 112 | 102 | **silent: `user_data=0x41414141` delivered to close_cb** |
| 116 | 106 | **silent: `user_data=0x4141414141414141` delivered to close_cb** |
| 117 | 107 | **ASAN heap-buffer-overflow WRITE, 0 bytes past the 168-B chunk** |
| 255 | 245 | **WRITE of size 245 at mesh/pb-adv.c:430** |

Attacker controls: write distance (`L-90` bytes past `sar`), write content
(full packet payload), and whether the write stays inside the object (silent)
or crosses into the next heap allocation.

## 1. Metadata
| Field            | Value                                                        |
|------------------|--------------------------------------------------------------|
| Title            | PB-ADV SAR START memcpy len-3 unchecked -> CWE-787 heap OOB  |
|                  | write; silent in-chunk corruption injects user_data pointer  |
| Component        | BlueZ `mesh/pb-adv.c` `pb_adv_packet` :300 (entry), :430     |
|                  | (write); mesh.c `prov_rx` :132 (no length guard); filter =   |
|                  | AD-type byte only (`prov_filter[]={BT_AD_MESH_PROV}`)        |
| Affected         | BlueZ 5.85 fixture; same code present on upstream master     |
|                  | (checked 2026-10-09)                                         |
| Fixed in         | NONE                                                         |
| CVE              | NONE assigned (checked NVD/OSV 2026-10-09)                   |
| CWE              | CWE-787 (heap OOB write); entries = CWE-119/20 family;       |
|                  | in-chunk variant = CWE-131/corruption of object fields       |
| Severity         | 8.1 HIGH (conditional class) — CVSS:3.1/AV:A/AC:H/PR:N/      |
|                  | UI:N/S:U/C:H/I:H/A:H — AV:A (advertising, no pairing) but   |
|                  | AC:H: overflow needs an AD >90 B, i.e. EXTENDED advertising  |
|                  | delivery (BLE5); legacy 31-B ads cannot overflow (control).  |
|                  | Proven write; RCE NOT established (see H7 note).             |
| Reporter         | seraphine AI agent                                           |
| First hit        | 2026-10-09                                                   |
| Build/flags      | gcc -O1 -g -fno-omit-frame-pointer -fsanitize=address,       |
|                  | undefined; real `mesh/pb-adv.c` (-Ilib), libell 0.83-1       |

## 2. Reachability (honest, per-path)
- **Unguarded chain (source-proven):** advertising AD type 0x29 → mesh-io
  filter (type match only, no length) → `mesh.c:prov_rx` (forwards `data,len`
  with no check) → `pb_adv_packet` (no `len>=7`, no copy bound).
- **Overflow precondition:** `L > 90`. Legacy advertising caps at 31 B → no
  overflow. Requires an extended-advertising delivery of 91..255 B to
  `prov_rx` (BLE5 controllers / mesh-io paths that pass long ads). Labelled
  AC:H for exactly this reason. If a deployment's mesh-io never delivers
  long ads, that instance is not reachable — the CODE defect stands regardless.
- **Secondary candidate (not proven):** `len < 7` underflows `len -= 7`
  (uint16) → `len-3` wraps to ~64 KB → huge memcpy; the header reads
  (`pkt+1..+6`) then come from adjacent heap, so `type`/`link_id` are
  nondeterministic — kept CANDIDATE, not claimed.
- **Open flow (all local, no radio):** acceptor `pb_adv_reg(false, ...)`,
  23-byte OPEN (uuid match), then the START packet — no daemon needed.

## 3. Steps to reproduce
```sh
bash /home/box/BTHunt/orch/build_pb.sh                 # real pb-adv.o, ASAN+UBSAN
bash /home/box/BTHunt/orch/pb/run_pb.sh                # control + triggers
# silent tier:
/home/box/BTHunt/orch/pb/pb_harness corrupt 116        # user_data=0x4141414141414141
# write tier:
/home/box/BTHunt/orch/pb/pb_harness trigger 255        # ASAN WRITE at pb-adv.c:430
```

## 4. Differential (authoritative, this box, 2026-10-09)
| input                        | result                                   |
|------------------------------|------------------------------------------|
| control L=31                 | rc=0, OPEN fired, no corruption          |
| corrupt L=108 (window edge)  | rc=0, user_data untouched (nil)          |
| corrupt L=112                | rc=0, close_cb got 0x41414141            |
| corrupt L=116                | rc=0, close_cb got 0x4141414141414141    |
| trigger L=117                | ASAN WRITE 107, 0 B past 168-B chunk     |
| trigger L=255                | ASAN WRITE 245 at mesh/pb-adv.c:430      |

## 5. Impact — and the H7 verdict (removed)
- **PROVEN (H6):** attacker-controlled heap OOB write (size, content, offset)
  + silent object-field corruption that injects an arbitrary 8-byte value
  into `session->user_data`, which is then passed to provisioner callbacks.
- **H7 REMOVED (guarded):** every callback examined dereferences `user_data`
  only AFTER a pointer-equality check against a file-static global
  (`acp_prov_close/open`: `if (rx_prov != prov) return;` — prov-acceptor.c:108/162;
  `srv_close/open`: `if (prov != rpb_prov || ...) return;` — remprv-server.c:167/102).
  The compare short-circuits before any deref, so a corrupted pointer neither
  derefs nor steers the subsequent access (which uses the global, not the
  argument). Making the check PASS would additionally require leaking the
  target's heap address. **No arbitrary-deref / control-flow edge established;
  adjacent-chunk object corruption (L>=117) is a candidate only.**
- Honest chain state: **H6 write = terminal verified rung.**

## 6. Fix (suggested)
```c
if (len < 7) return;                 /* before pkt+=7; len-=7   */
...
size_t copy = (size_t)len - 3;
if (len < 3 || offset + copy > sizeof(session->sar)) return;
memcpy(session->sar, pkt + 3, copy);
```
plus a defensive `len >= 7` assert at every entry from mesh-core.

## 7. References
- `mesh/pb-adv.c:300-460` (entry, `len-=7` :326, START copy :430, cont copy
  :445 with the off-by-3 guard `offset+len-3` vs copy of `len`);
  `mesh/pb-adv.h` public `pb_adv_reg`;
  `mesh/mesh.c:132-153` prov_rx (no guard) + `prov_filter[]={BT_AD_MESH_PROV}`;
  `mesh/prov-acceptor.c:108/162`, `mesh/remprv-server.c:102/167` (callback guards)
- struct layout: `pb_adv_session` 168 B, `sar[80]` mid-object, `user_data` last
- Sender honors `PB_ADV_MTU 24` (pb-adv.c:62) — receiver never enforces an
  equivalent: TX-side discipline does not protect RX.
- Candidate sourced from wave1 remote-disclosure agent (#3 in
  `wave1-remote-disclosure.md`); execution here.
- Harness: `/home/box/BTHunt/orch/pb/{pb_harness.c,run_pb.sh}`,
  object `/home/box/BTHunt/orch/pb/pb-adv.o`

## 8. Method note
Bottom-up: real object file, real registration flow (`pb_adv_reg` → recorded
`mesh_reg_prov_rx` callback), acceptor OPEN established before the trigger;
one variable per run (L); control at legacy maximum; silent window found by
sweep (108 clean / 112 corrupt / 117 first ASAN) rather than asserted; H7
candidate tested by reading every registered callback's body before deciding
— removed on evidence, not kept on narrative.

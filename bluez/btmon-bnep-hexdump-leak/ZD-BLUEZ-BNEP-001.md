# ZD-BLUEZ-BNEP-001 — Unknown BNEP control type: hdr_len=-1 -> packet_hexdump(65534) leaks 69 KB of process memory (env, stack pointers) then SIGSEGV

AI-exclusive finding · BlueZ 5.85 (installed btmon) · control-clean · kernel-witnessed

## TL;DR
`monitor/bnep.c`'s general dispatch passes **`hdr_len = -1`** to every handler:

```c
/* monitor/bnep.c:450 (bnep_packet) */
if (!bnep_data->func(&bnep_frame, indent, -1))
        goto fail;
```
`bnep_control()` consumes the control-type byte; for a type NOT in
`bnep_control_table` (0x00-0x06) it does:

```c
/* monitor/bnep.c:281-285 */
if (!bnep_control_data || !bnep_control_data->func) {
        packet_hexdump(frame->data, hdr_len - 1);   /* -1 - 1 = -2 */
        l2cap_frame_pull(frame, frame, hdr_len - 1);
        goto done;
}
```
`packet_hexdump(const unsigned char *buf, uint16_t len)` (packet.c:4272) — the
`-2` becomes **uint16 65534** → 65,534-byte read from a pointer with only a
handful of valid bytes → hexdumped to stdout.

**Measured on stock `/usr/bin/btmon` (Debian 5.85-4), capture file, one crafted packet:**

```
trigger:  rc=139 (SIGSEGV), stdout = 69,675 bytes
control:  rc=0,            stdout = 730 bytes
```
The 69 KB contains, verbatim:
- **stack/heap pointers** in the first hexdump lines (`… fc 7f` = `0x7ffc…` — ASLR material)
- **the process environment**: `HOME=/home/box`, `LANG=en_US.UTF-8`,
  `GTK2_RC_FILES=…`, `HERMES_SESSION_ID=…`, full `PATH`, and
  **`DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus`**
- then the walk dies at the stack guard: kernel log
  `btmon[207185]: segfault at 7ffc14b53000 … error 4`

Delivery (all unauthenticated, file-based):
1. `btmon -r <crafted.btsnoop>` — AV:L/UI:R, proven above
2. `btmon -s <monitor socket>` — same decoder, live HCI frames (AV:A), prior
   BTFINDING-4 recipe
3. live capture on a passive adapter receiving a hostile BNEP peer (AV:A)

## 1. Metadata
| Field            | Value                                                        |
|------------------|--------------------------------------------------------------|
| Title            | hdr_len=-1 + unknown ctype -> packet_hexdump(uint16 wrap)    |
|                  | -> 65 KB OOB read emitted (env + pointers) -> SIGSEGV        |
| Component        | BlueZ `monitor/bnep.c` `bnep_packet`:450 / `bnep_control`:281|
| Affected         | BlueZ 5.85 installed; dispatch/hexdump code unchanged in     |
|                  | upstream master (checked 2026-10-09)                         |
| Fixed in         | NONE                                                         |
| CVE              | NONE assigned to this site (checked NVD/OSV 2026-10-09);     |
|                  | 2016 monitor CVE family is crash-class in other files        |
| CWE              | CWE-125 (OOB read) + CWE-191 (int->uint16 wrap) ->          |
|                  | CWE-200 (emitted env/pointers = disclosure)                  |
| Severity         | 6.5 — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N          |
|                  | (file vector; socket/live peers raise reachability class)    |
| Reporter         | seraphine AI agent (wave1 remote-disclosure candidate ->     |
|                  | executed by parent)                                          |
| First hit        | 2026-10-09                                                   |
| Build/flags      | stock distro btmon (non-ASAN) for emission proof;            |
|                  | defect visible in source at lines above                      |

## 2. Steps to reproduce
```sh
# trigger: BNEP Control, unknown control type 0x07
python3 /home/box/BTHunt/src/mk_btsnoop_bnep.py 0x07 /home/box/BTHunt/out/bnep_trigger.btsnoop
timeout 20 /usr/bin/btmon -r /home/box/BTHunt/out/bnep_trigger.btsnoop > /tmp/bnep_trig.out
echo "rc=$?  bytes=$(wc -c < /tmp/bnep_trig.out)"
#   rc=139  bytes=69675
# control: known type 0x00 (Command Not Understood)
python3 /home/box/BTHunt/src/mk_btsnoop_bnep.py 0x00 /home/box/BTHunt/out/bnep_control.btsnoop
timeout 10 /usr/bin/btmon -r /home/box/BTHunt/out/bnep_control.btsnoop > /tmp/bnep_ctrl.out
echo "rc=$?  bytes=$(wc -c < /tmp/bnep_ctrl.out)"
#   rc=0    bytes=730
# leak quantification:
python3 /home/box/BTHunt/orch/leak_quant.py     # lists leaked VAR=value strings
```

## 3. Differential (authoritative, this box, 2026-10-09)
| capture                       | stock btmon 5.85                    |
|-------------------------------|-------------------------------------|
| BNEP control ctype=0x00       | 730 B decode, exit 0                |
| BNEP control ctype=0x07       | **69,675 B leaked, exit 139**       |
| (kernel)                      | `segfault … error 4` (READ at stack guard) |

Route proof inside the output: `BNEP: Control (0x01|0)` → `Unknown control
type (0x07)` → hexdump begins; first lines contain `40 00 00 00 00 00 fc 7f`
(stack pointers), later `HOME=/home/box`, `DBUS_SESSION_BUS_ADDRESS=…`.

## 4. Impact
- **Information disclosure**: 69 KB of btmon's address space — environment
  (paths, session ids, D-Bus socket), ASLR-relevant pointers — printed to
  whatever stdout is redirected to, then crash.
- Same-class siblings found in the same audit (separate sites, this file's
  `:376` wire-length read and `:381` recursion noted, not merged).
- Read/emission only; no write claimed.

## 5. Fix (suggested)
```c
if (hdr_len < 0) {
        packet_hexdump(frame->data, frame->size);   /* honest remaining size */
} else {
        packet_hexdump(frame->data, hdr_len - 1);
}
```
or drop `hdr_len` entirely: dump `frame->size` (the real remaining length).

## 6. References
- `monitor/bnep.c:387-470` (bnep_table/bnep_packet dispatch, hdr_len=-1),
  `:244-253` (bnep_control_table 0x00-0x06), `:281` (hexdump site)
- `monitor/packet.c:4272 packet_hexdump(buf, uint16_t len)`
- Generator `/home/box/BTHunt/src/mk_btsnoop_bnep.py`, capture
  `/home/box/BTHunt/out/bnep_{trigger,control}.btsnoop`, leak audit
  `/home/box/BTHunt/orch/leak_quant.py`
- Source candidate credited to wave1 remote-disclosure agent
  (`wave1-remote-disclosure.md` finding #2); execution + emission proof here.
- Prior class: BTFINDING-7 emission raciness; no NVD record for bnep.c (2026-10-09)

## 7. Method note
Bottom-up: route proven with a benign control first (known ctype decodes,
730 B), then a single-field change (ctype 0x07) isolated the exact defect;
emission measured on the STOCK binary (non-ASAN) because disclosure — not
just crash — is the finding; every leaked string listed by `leak_quant.py`
rather than asserted.

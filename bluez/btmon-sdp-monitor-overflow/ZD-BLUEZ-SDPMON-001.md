# ZD-BLUEZ-SDPMON-001 — Integer-overflow -> OOB write/read in BlueZ monitor SDP decoder (btmon file + LIVE socket crash)

AI-exclusive finding · BlueZ 5.85 (installed) / 5.87 (latest upstream, UNPATCHED)

## TL;DR
BlueZ's `monitor/sdp.c` SDP data-element decoder has an **unchecked uint32
integer overflow** in its length guard:

    if (size < 1 + (extrabits / 8) + datalen)   /* all uint32_t */

With an attacker-controlled `datalen` of `0xFFFFFFFF` the right-hand side wraps
to `0`, the guard passes, and the code immediately does

    char *str = alloca(size + 1);   /* size = 0xFFFFFFFF -> alloca(0) */
    str[size] = '\0';               /* str[0xFFFFFFFF] -> OOB WRITE      */
    strncpy(str, data, size);       /* 4 GiB OOB READ                    */

(`monitor/sdp.c` `print_string()`; reached from `decode_data_elements()` via the
SDP attribute-list walk.) `datalen = 0xFFFFFFFE` instead allocates ~4 GiB with
`alloca` and **blows the stack**.

This is triggered **two ways, both unauthenticated and both control-tested**:
  1. a crafted **btsnoop capture file** -> `btmon -r <file>`  (AV:L)
  2. a crafted **HCI frame injected over btmon's monitor socket** ->
     `btmon -s <sock>`  (AV:A/AV:N — no file, no radio, no pairing)

Both end in a deterministic **SIGSEGV** on the stock distro binary. The defect
is present, source-identical, in the newest upstream (5.87) — **not fixed**.
A related **OOB READ** in `get_bits()` (distinct defect, same walk) is also
proven. Found during a BlueZ/sdp component hunt with the `zdhunt` fuzzer.

---

## 1. Metadata
| Field                | Value                                                             |
|----------------------|-------------------------------------------------------------------|
| Title                | uint32 overflow -> alloca/strncpy OOB in monitor/sdp.c SDP decoder |
| Affected             | BlueZ 5.85 (installed, `bluez 5.85-4`); code identical in 5.87     |
| Fixed in             | UNPATCHED (checked 2026-09-27: 5.87 is current upstream)           |
| CVE                  | NONE matching this defect (checked 2026-09-27). CVE-2016-9802 is a  |
|                      | same-CLASS prior (`l2cap_packet`, monitor/packet.c, BlueZ 5.42) — a |
|                      | different function/file; NOT this bug.                             |
| Severity (file)      | 5.5 MEDIUM  — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H         |
| Severity (live sock) | 6.5 MEDIUM  — CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H         |
| Severity (AV:N bound)| 7.5 HIGH (exposed/forwarded socket; not network-tested)            |
| Reachability         | file: analyst opens btsnoop; live: any client of btmon -s socket   |
| Reporter             | seraphine AI agent via `zdhunt` creative fuzzer                    |
| First hit            | 2026-09-27 (this campaign)                                        |
| Build/flags          | gcc 16.2.0, `-fsanitize=address,undefined -O1 -g` (harness)        |

## 2. Description
`monitor/sdp.c` decodes the value of every SDP data element. For a String
element (`type 4`, `0x27`) it calls `print_string(data, size)`:

```c
/* monitor/sdp.c ~136 */
static void print_string(const void *data, uint32_t size)
{
    char *str = alloca(size + 1);          /* size+1 wraps for 0xFFFFFFFF */
    str[size] = '\0';                      /* OOB WRITE at str[0xFFFFFFFF] */
    strncpy(str, (const char *) data, size);/* 4 GiB OOB READ */
    ...
}
```

`size` comes from `get_size()` (`~227`), which for a 32-bit-length element
returns `get_be32(data + 1)` — i.e. **attacker-controlled, up to 0xFFFFFFFF**.

The only guard is in `decode_data_elements` (`~260`):

```c
if (size < 1 + (extrabits / 8) + datalen) {   /* uint32_t arithmetic */
        ...reject...
}
```

All three operands are `uint32_t`. With `datalen = 0xFFFFFFFF`:

    1 + 0 + 0xFFFFFFFF  ==  0x100000000  --truncate-->  0x00000000
    size < 0            ==  false        -->  guard BYPASSED

`extrabits/8` gives a second wrap path. Downstream, `size = 0xFFFFFFFF`:

  * `alloca(size + 1)` -> `alloca(0)` (wrapped) -> `str` aliases the stack head
  * `str[size] = '\0'` -> writes at `str + 0xFFFFFFFF` -> **OOB WRITE / SEGV**
  * `strncpy(str, data, size)` -> **4 GiB OOB READ** (disclosure)
  * with `datalen = 0xFFFFFFFE`: `alloca(~4 GiB)` -> **stack exhaustion / SEGV**

Entry chain (offline file path):
`btsnoop_read_hci -> packet_hci_acldata -> l2cap_packet -> l2cap_frame
 -> sdp_packet()  (monitor/sdp.c:714) -> search_attr_rsp -> handle_continuation
 -> decode_data_elements() -> print_attr_list -> print_attr -> print_string`

Live socket path:
`control.c:1221 control_server -> 1179 server_accept_callback ->
 1140 client_callback -> packet_monitor -> packet_hci_acldata -> (same as above)`

### Distinct second defect (same walk): OOB READ in get_bits()
The recursive walk advances `data += elemlen; size -= elemlen` where
`elemlen = 1 + extrabits/8 + datalen`, and the next level calls
`get_bits(data, size)` -> reads `data[0]` without proving `data` is still
inside the buffer. The remaining login block is 8 bytes, so the read walks off the end. ASAN:
`SEGV on a READ` at `get_bits()`. Minimal 12-byte reproducer:
`37 FF FF FF FF 31 00 02 1F 8B 08 41`.

## 3. Steps to reproduce
### 3a. File path (proof of crash)
```
# build the malicious capture
python3 ~/BTHunt/src/mk_btsnoop_sdp.py 0xFFFFFFFE ~/BTHunt/out/sdp_overflow.btsnoop
# feed the stock distro binary
btmon -r ~/BTHunt/out/sdp_overflow.btsnoop ; echo "exit=$?"
```
Observed:
```
Segmentation fault (core dumped)
exit=139
```
Benign control (`datalen = 2`) decodes cleanly:
`Attribute list: [len 2] {position 0}` ... `Continuation state: 0`.

### 3b. Live socket path (proof + control)
```
python3 ~/BTHunt/src/live_socket_probe.py 0xFFFFFFFE   # malicious
python3 ~/BTHunt/src/live_socket_probe.py 2            # control
```
Observed:
```
malicious: datalen=0xFFFFFFFE  btmon alive_after_send=False  exit=-11   (3/3)
control:   datalen=0x2         btmon alive_after_send=True   exit=None
```
One-command wrapper: `python3 ~/BTHunt/src/btscan.py --live-socket`
(or `--e2e-capture` / `--oobread` for the file paths).

### 3c. ASAN harness (mechanism)
Direct-drive harness `~/BTHunt/fuzz/zdhunt_sdpdec` (gcc ASAN+UBSAN) over the
extracted decoder:
```
echo -ne '\x27\xff\xff\xff\xfeABCD' | ./zdhunt_sdpdec
 -> AddressSanitizer: stack-overflow / SEGV, print_string + decode_data_elements
```

## 4. Differential (authoritative, this box)
| Input                                   | stock btmon 5.85                 |
|-----------------------------------------|----------------------------------|
| btsnoop, SDP String len = 2 (benign)     | decodes OK, exit 0               |
| btsnoop, SDP String len = 0xFFFFFFFE     | SIGSEGV, exit 139 (6/6)          |
| live sock, len = 0xFFFFFFFE              | SIGSEGV, exit -11 (3/3)          |
| btsnoop, get_bits OOB (12-byte element)  | SIGSEGV, exit 139 (read OOB)     |

Also measured: only the *wrapping* value crashes — `0x40000000`, `0x1000000`
and `0x100000` all exit 0 (a large non-wrapping `alloca` succeeds). This pins
the defect as the **integer overflow**, not merely "a large length".

## 5. Disclosure component (measured, honest)
The 4 GiB `strncpy` reads out of bounds; whether those bytes become *visible*
is racy:
  * stdout to a file redirect -> **0 bytes** (stdio buffer lost on SIGSEGV)
  * stdout to a pipe          -> 0 / 4096 / 8192 / 12288 / 77824 bytes across runs
  * env strings (`SHELL=`, `DBUS_SESSION_BUS_ADDRESS=`, ...) in 2/6 piped runs
  * a 48-bit stack pointer (`fd 7f 00 00 ...`) observed **1/6** runs, not stable
The OOB **read** is certain (ASAN SEGV on read; process dies at the first
unmapped page). A *stable, attacker-steerable data disclosure* is **NOT**
established. Reported faithfully as an intermittent leak, not an ASLR primitive.

## 6. Impact
- CONCRETE: deterministic, unauthenticated, file- **and** socket-triggered
  crash (CWE-190 integer overflow -> CWE-787 OOB write / CWE-125 OOB read) in
  BlueZ **5.87 (latest)**, on the stock distro `btmon`.
- CWE-190 (integer overflow) + CWE-787 (OOB write) + CWE-125 (OOB read).
- Live path removes the "victim opens a file" precondition: any process able to
  write btmon's monitor socket drives the same decoder to a crash (and, if the
  socket is exposed/forwarded, that is a network-adjacent vector).
- No RCE proven; the write is one byte at a huge offset (mostly a crash). The
  read is a soft leak. Severity graded 5.5 / 6.5, **not** inflated to 9.x.

## 7. Fix (suggested)
```c
/* 64-bit compare in the guard */
if ((uint64_t)datalen + 1 + (uint64_t)(extrabits / 8) > (uint64_t)size)
        return;                         /* reject before print_string */

/* bound the recursive walk */
if (elemlen > size) return;             /* before data += elemlen */

/* never alloca an attacker-controlled size */
if (size > L2CAP_MTU_MAX) return;
char *str = malloc(size + 1);
```
Same shape as the 2016 monitor fixes (CVE-2016-9799/9802/9918) applied to
`sdp.c`, which were never extended to the SDP data-element walk.

## 8. References
- `monitor/sdp.c` `print_string` ~136-139, `get_size` ~227, guard ~260,
  `sdp_packet` 714, `decode_data_elements` ~180-240
- `monitor/control.c` 1221 `control_server`, 1179 `server_accept_callback`,
  1140 `client_callback`; `monitor/packet.c` 4324 `packet_monitor`,
  4347 opcode switch (4=ACL_TX, 5=ACL_RX)
- `monitor/l2cap.c` 2547 `l2cap_frame` (cid dispatch), 2643 `sdp_packet` case,
  108 `assign_scid` / channel table
- CVE-2016-9802 / CVE-2016-9799 / CVE-2016-9918 — same-class monitor
  packer/decoder over-reads (BlueZ 5.42), FIXED; unrelated code paths
- CVE-2017-1000250 — SDP info disclosure (bluez daemon SDP server), unrelated
- Found with `zdhunt` creative fuzzer (G_GRAMMAR / numeric-cliff arms) +
  hand-built btsnoop and live-socket PoCs; full chain in ~/BTHunt/report/

## 9. Method note
Target chosen because `monitor/sdp.c` parses a **fully attacker-controlled**
buffer with no daemon-side `process_request` gate — the offline `btmon -r` path
and the `btmon -s` socket path both reach it directly. `zdhunt` mutated a
hand-built SDP grammar seed corpus; its 60k-exec campaign collapsed (after
de-ASLR-ing the crash keys) to exactly two real sites: this overflow and the
`get_bits` read — no fabricated distinct bugs. Both were then reproduced
end-to-end on the unmodified system binary, and the live-socket vector was
confirmed with a benign control.

## Attachments
  * trigger-btsnoop-sdp-overflow.bin   — crashed stock btmon (file path)
  * trigger-btsnoop-sdp-oobread.bin    — get_bits OOB read (file path)
  * trigger-live-socket.py             — live socket PoC (no file)

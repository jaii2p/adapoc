# FreeModbus — audit findings (cwalter-at/freemodbus @ a9ec789)

Target: FreeModbus Modbus RTU/ASCII/TCP slave library (BSD) + LINUXTCP demo port.
Scope: static audit of `modbus/` core + LINUXTCP port; targeted active confirmation
of each candidate against an ASAN build.  **Remote-unauthenticated** over Modbus TCP
(port 502) unless noted.

## Build (used for confirmation)
```
cd demo/LINUXTCP
Makefile CFLAGS += -fsanitize=address -fno-omit-frame-pointer, LDFLAGS += -fsanitize=address
mbconfig: MB_ASCII_ENABLED=0 MB_RTU_ENABLED=0 MB_TCP_ENABLED=1   # TCP-only audit build
demo.c: auto-start polling thread (bCreatePollingThread) so requests process without CLI
make  -> tcpmodbus  (ASAN)
```

## Finding 1 — CVE-2026-71263: TCP port OOB WRITE (CONFIRMED here, already assigned)
Class: CWE-787 global-buffer-overflow. Severity: 9.1 (public CVE). **Not a novel find —
confirmed independently, not first-discovered.** Port `demo/LINUXTCP/port/porttcp.c`.

Root cause: `xMBPortTCPPool` guard at `:246` checks `usTCPFrameBytesLeft > MB_TCP_BUF_SIZE`
(263) but **not `usTCPBufPos + usTCPFrameBytesLeft`**, and `usTCPFrameBytesLeft` is derived
from the attacker MBAP Length field at `:271` (`usLength + MB_TCP_UID - usTCPBufPos`).
A 16-bit `usLength` in range lets `recv(&aucTCPBuf[usTCPBufPos], usTCPFrameBytesLeft)` at
`:252` write past the 263-byte static `aucTCPBuf`.

Confirmed (ASAN, real binary, unauthenticated, single crafted frame):
```
ERROR: AddressSanitizer: global-buffer-overflow on ... WRITE of size 259
    #1 xMBPortTCPPool port/porttcp.c:252
    0x...c67 located 0 bytes after global 'aucTCPBuf' ... of size 263
```
Trigger: MBAP Length 258..264 (e.g. 260 → 266-byte write into 263-byte buffer, 3 B OOB).
Reproducer: `trigger_cve71263.py 502 260`.

## Finding 2 — handler-level metric mismatch (novel, LOW-MED): write-multiple handlers
#don't validate received length against declared byte count. Class CWE-125/validation gap.
Statics (mbfuncholding.c / mbfunccoils.c): the "write multiple" family checks the *derived*
byte count (from the count field) equals the *declared* byte count, but only ONE of them
additionally verifies the *actually received PDU length* (`usLen`) covers it:

| FC | handler | validates `usLen` covers bytecount? |
|----|---------|--------------------------------------|
| 0x10 | `eMBFuncWriteMultipleHoldingRegister` | **YES** — `ucRegByteCount == usLen-6` |
| 0x0F | `eMBFuncWriteMultipleCoils` | **NO** — only `usCoilCnt <= 0x07B0` + derive-check |
| 0x17 | `eMBFuncReadWriteMultipleHoldingRegister` | **NO** — only `2*writeCount == byteCnt` |

Exploit shape: a *short* frame declaring a large count (0x0F: coilCnt=1968 → byteCnt=246;
0x17: writeCount=121 → 242 bytes) passes validation and invokes the app callback
`eMBReg{Coils,Holding}CB(..., attackerCount)`. The app trusts the count and reads/copies
that many bytes from a frame that doesn't contain them.

Confirmed differential (ASAN binary, unauthenticated):
```
FC 0x10 short  -> exception 0x90 / code 3 (ILLEGAL DATA VALUE)   # guarded: rejects length mismatch
FC 0x0F short  -> exception 0x8F / code 2 (ILLEGAL DATA ADDRESS) # unguarded: accepted, dispatched to cb
FC 0x17 short  -> exception 0x97 / code 2 (ILLEGAL DATA ADDRESS) # unguarded: accepted, dispatched to cb
```
The differing exception code is a wire-observable signature that the unguarded handlers
passed the mismatch to the app layer. Impact depends on the app callback: the shipped demo
callbacks bound writes to REG_*_NREGS (so no OOB there) and the TCP receive buffer is a static
263B array, so on stock demos the over-read stays in-bounds (reads stale bytes past the PDU).
**Real OOB** requires an application that (a) trusts `pucRegBuffer` to hold `2*usNRegs` /
`coilCnt` bytes and (b) uses an exact-size or smaller frame/register buffer — a common pattern
in embedded roll-your-own backends. Honest: **validation gap with app-dependent escalation,
not a self-contained library OOB write.**

Suggested library fix (matches the 0x10 guard): in the unguarded handlers add
`usLen >= VALUES_OFF + bytecount` before invoking the callback.

## Honesty / scope
- F1 is a known CVE confirmed independently (real ASAN evidence), not a novel disclosure.
- F2 is a novel finding with a confirmed differential but deliberately app-dependent impact —
   filed as LOW-MED, not inflated.
- No generic/compartmentalized claims: both confirmed against the actual built binary over a
   real TCP socket, stock config, unauthenticated.
- Servers were killed after each test; no persistent listener left open.

## Files
- `drive_freemodbus.py` — FC 0x0F/0x10/0x17 crafted-frame driver (short vs full-data)
- `trigger_cve71263.py` — CVE-2026-71263 OOB-write trigger
- build: `demo/LINUXTCP/tcpmodbus` (ASAN), mbconfig/makefile patched for the TCP-only build
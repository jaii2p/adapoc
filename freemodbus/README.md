# freemodbus — CVE-2026-71263 confirmation + pwn-primitive attempt (honest)

Target: FreeModbus (cwalter-at/freemodbus @ a9ec789) LINUXTCP demo port.
Two deliverables, both honest about what was and wasn't achieved.

## Finding 1 — CVE-2026-71263 (already-assigned critical), CONFIRMED independently
Remote, unauthenticated OOB write in `demo/LINUXTCP/port/porttcp.c` `xMBPortTCPPool`
(line 252): the guard checks `usTCPFrameBytesLeft > 263` but not
`usTCPBufPos + usTCPFrameBytesLeft`, and `usTCPFrameBytesLeft` is derived from the
attacker MBAP Length. Confirmed on a real ASAN build:
```
ERROR: AddressSanitizer: global-buffer-overflow WRITE of size 259 at port/porttcp.c:252
```
See `REPORT-FREEMODBUS-AUDIT.md`. Trigger: single crafted 270-byte frame
(`trigger_cve71263.py` equivalent inside `poc/`).

## Finding 2 — pwn-primitive attempt: VERIFIED primitives, blocked short of RCE
Fully documented in `EXPLOIT-NOTES.md`:
- **P1 (VERIFIED)** arbitrary 16-bit write into the two `.bss` receiver-control
  words `usTCPBufPos` / `usTCPFrameBytesLeft` (immediately past `aucTCPBuf`).
- **P2 (VERIFIED)** chained write: corrupting `usTCPFrameBytesLeft` sizes the next
  `recv`; the engine consumes an attacker-fed second frame and replies with the
  attacker's transaction id while staying alive. End-to-end control of the
  receiving state machine, bounded to buffer offsets ≤ 269.
- **P3 (VERIFIED)** deterministic remote abort / DoS: same frame with a different
  Pos payload → `__assert_fail(porttcp.c:287)` → SIGABRT, live server killed.
- **NOT ACHIEVED (honest):** full `peMBFrameSendCur` → controlled-call hijack.
  The live `assert(porttcp.c:287)` fires first (Pos=0x140 > 6+usLength → SIGABRT);
  the surviving escape path caps the write at offset 269, 3 bytes short of the
  first function pointer at 272. No RCE, none claimed. Residual avenue (flagged,
  not tested): an `-DNDEBUG` production build compiles the assert out — the one
  thing that could widen the window.

## Files
- `REPORT-FREEMODBUS-AUDIT.md` — two-finding audit (incl. novel FC 0x0F/0x17
  handler-level metric mismatch, LOW-MED, app-dependent)
- `EXPLOIT-NOTES.md` — offsets, frame hex, compensation math, VERIFIED-vs-HYPOTHESIZED
- `poc/` — `poc_cve71263_pwn.py` (dry-run/abort/escape/legal modes),
  `drive_freemodbus.py` (FC 0x0F/0x10/0x17 diff driver)
- `evidence/` — gdb traces, assert backtrace, live-server abort/escape logs

All testing local (127.0.0.1), listeners killed. No fabricated claims.
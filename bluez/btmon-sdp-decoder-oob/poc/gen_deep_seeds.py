#!/usr/bin/env python3
"""Deep-sink seeds: valid controls that decode ALL the way to the bottom-most
byte-level consumers of tools/parser/sdp.c, sitting exactly AT the empty-sink
cliff (declared length == bytes present), so zdhunt's stacked chained mutations
(fieldlen / count_overflow_field / boundaryflip / recurcliff / chunkskew)
tip them over without destroying the deep grammar.

Families:
  S1  max-nested SEQ record with a TERMINAL string using size-index 7
      (4-byte BE length) -> print_string byte walk (sdp.c:356) = the bottom.
      variants: n == present (cliff-valid), present+1, present+2, 0x100, big.
  S2  ServiceSearchAttrRsp where AttributeByteCount == list bytes (cliff) and
      +1..+4 / 0xFFFF -> `*(frm->ptr + count)` (sdp.c:744/777) and
      frame_add memcpy(data, ptr, count) (sdp.c:622/624) read into emptiness.
  S3  deep SEQ recursion (N levels, lengths exact-fit) for recurcliff arms.
  S4  UUID-128 terminal (16-byte strided walk, sdp.c:322) landing at 15/16.

Every seed is L2CAP-multi-fragment wrapped (stage A) AND emitted raw (stage C).
"""
import os, struct

OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "seeds-deep"))
RAW = os.path.join(OUT, "raw")

def u16(v): return struct.pack(">H", v)
def u32(v): return struct.pack(">I", v)

def de_uint(v):
    if v < 0x100:   return bytes([0x08, v])
    if v < 0x10000: return bytes([0x09]) + u16(v)
    if v < 2**32:   return bytes([0x0a]) + u32(v)
    return bytes([0x0b]) + struct.pack(">Q", v)

def de_uuid16(u):   return bytes([0x19]) + u16(u)
def de_str(b):      return bytes([0x25, len(b)]) + b                    # idx5: 1-byte len
def de_str7(b):     return bytes([0x27]) + u32(len(b)) + b              # idx7: 4-byte len
def de_str7_declared(n, b): return bytes([0x27]) + u32(n) + b           # idx7: DECLARED n (may exceed present)
def de_seq(p):      return bytes([0x35, len(p)]) + p                    # idx5
def de_seq7(n, p):  return bytes([0x37]) + u32(n) + p                   # idx7: 4-byte declared seq len
def de_uuid128(b):
    assert len(b) == 16
    return bytes([0x1c]) + b                                            # idx4: fixed 16

def sdp_pdu(pid, tid, param):
    return bytes([pid]) + u16(tid) + u16(len(param)) + param

def deep_record(terminal):
    """record = SEQ( attrID pairs ... terminal attr value ) with extra nesting
    (ProtocolDescriptorList-style double seq) so the walk must descend."""
    inner = (bytes([0x09, 0x00, 0x01]) + de_seq(de_uuid16(0x1101))
             + bytes([0x09, 0x00, 0x04]) + de_seq(de_seq(de_uuid16(0x0100) + de_uint(1)))
             + bytes([0x09, 0x01, 0x00]) + terminal)
    return de_seq(inner)

def ssa_pdu(attrlist_bytes, bytecount=None, cont=b"\x00"):
    bc = len(attrlist_bytes) if bytecount is None else bytecount
    return sdp_pdu(0x07, 0x0001, u16(bc) + attrlist_bytes + cont)

def wrap_l2cap(pdu, cuts=(23, 51, 79)):
    n = len(pdu)
    bounds = sorted({max(1, n * c // 100) for c in cuts})
    chunks, prev = [], 0
    for b in bounds:
        if b < n: chunks.append(pdu[prev:b]); prev = b
    chunks.append(pdu[prev:])
    chunks = [c for c in chunks if c]
    if len(chunks) < 2: return None
    out = b""
    for i, ch in enumerate(chunks):
        if i == 0: payload, flags = u32(n) + ch, 0x01
        else:      payload, flags = ch, 0x00
        out += bytes([flags]) + u16(len(payload)) + payload
    return out

SEEDS = {}

# ---- S1: terminal 4-byte-length string at the bottom, declared == present
term_exact = de_str7(b"DEEPSINK-BOTTOM-MARKER")          # n == present (cliff)
record1 = deep_record(term_exact)
list1 = de_seq(record1)
SEEDS["s1_cliff_valid"] = ssa_pdu(list1)

# terminal string declared longer than present -> byte walk leaves the buffer
for name, decl in (("s1_nplus1", len(b"DEEPSINK") + 1),
                   ("s1_nplus2", len(b"DEEPSINK") + 2),
                   ("s1_n256",   0x100),
                   ("s1_nbig",   0x00010000)):
    term = de_str7_declared(decl, b"DEEPSINK")
    SEEDS[name] = ssa_pdu(de_seq(deep_record(term)))

# ---- S2: AttributeByteCount pointing at/just past emptiness
listA = de_seq(deep_record(de_str(b"count-target")))
for k, v in (("eq",   len(listA)),
             ("p1",   len(listA) + 1),
             ("p4",   len(listA) + 4),
             ("ffff", 0xFFFF)):
    SEEDS[f"s2_count_{k}"] = ssa_pdu(listA, bytecount=v)

# ---- S3: deep exact-fit SEQ recursion (6 and 10 levels)
def nest(levels, leaf):
    p = leaf
    for _ in range(levels):
        p = de_seq(p)
    return p
for lv in (6, 10):
    body = de_str7(b"L" * 8)
    # rebuild chain so EVERY seq length field exact-fits its content
    p = body
    for _ in range(lv):
        p = bytes([0x35, len(p)]) + p
    rec = de_seq(bytes([0x09, 0x01, 0x00]) + p)
    SEEDS[f"s3_nest{lv}"] = ssa_pdu(de_seq(rec))

# ---- S4: UUID-128 terminal, 16 bytes present vs 15-read variant seeds
u128 = de_uuid128(bytes.fromhex("00112233445566778899aabbccddeeff"))
SEEDS["s4_uuid128_valid"] = ssa_pdu(de_seq(deep_record(u128)))
# sequence declares 16 but only 15 present (truncated terminal -> 16-stride walk ends short)
u15 = bytes.fromhex("00112233445566778899aabbccddee")
s4t = bytes([0x1c]) + u15                                # idx4 fixed-16 header, 15 present
SEEDS["s4_uuid128_short"] = ssa_pdu(de_seq(deep_record(s4t)))

# ---- also SS/SA variants for framing diversity at depth
attr_list = de_seq(bytes([0x09, 0x00, 0x00]) + de_uint(0x00010001)
                   + bytes([0x09, 0x01, 0x00]) + de_str7(b"SA-DEEP"))
SEEDS["s2_sa_cliff"] = sdp_pdu(0x05, 0x0002, u16(len(attr_list)) + attr_list + b"\x00")
SEEDS["s2_sa_p2"]    = sdp_pdu(0x05, 0x0002, u16(len(attr_list) + 2) + attr_list + b"\x00")

def main():
    os.makedirs(RAW, exist_ok=True)
    n_raw = n_wr = 0
    for name, pdu in SEEDS.items():
        with open(os.path.join(RAW, name + ".bin"), "wb") as f:
            f.write(pdu); n_raw += 1
        w = wrap_l2cap(pdu)
        if w:
            with open(os.path.join(OUT, name + ".bin"), "wb") as f:
                f.write(w); n_wr += 1
        print(f"{name:22s} pdu={len(pdu):4d}B")
    print(f"\n{len(SEEDS)} deep-sink seeds: {n_wr} wrapped (chain), {n_raw} raw (stageC/D direct)")

if __name__ == "__main__":
    main()

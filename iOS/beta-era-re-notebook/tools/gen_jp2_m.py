#!/usr/bin/env python3
# gen_jp2_m.py -- small-dimension JP2s with MISMATCHED rowbytes (so the preview
# path decodes them, like the fixed BMPs), exercising the rowbytes/dims mismatch.
import os, struct, sys
from PIL import Image

OUT = sys.argv[1] if len(sys.argv) > 1 else "/home/box/.hermes/profiles/seraphine/cache/scratch/jp2m"
os.makedirs(OUT, exist_ok=True)

def box(t, p): return struct.pack(">I", 8 + len(p)) + t + p

def build_j2k(X, Y, C, prec, signed=False):
    comps = b"".join(bytes([((prec-1)|(0x80 if signed else 0)), 1, 1]) for _ in range(C))
    siz = b"\xFF\x51" + struct.pack(">HHIIIIIIIIH", 38+3*C, 0, X, Y, 0, 0, X, Y, 0, 0, C) + comps
    cod = b"\xFF\x52" + struct.pack(">H", 12) + bytes([0]) + struct.pack(">BHB", 0, 1, 0) + bytes([0,4,4,0,1])
    qcd = b"\xFF\x5C" + struct.pack(">H", 4) + bytes([0x20, 0x08])
    sot = b"\xFF\x90" + struct.pack(">H", 10) + struct.pack(">H", 0) + struct.pack(">I", 14+C) + bytes([0, 1])
    sod = b"\xFF\x93" + (b"\x00" * C)
    return b"\xFF\x4F" + siz + cod + qcd + sot + sod + b"\xFF\xD9"

def build_jp2(X, Y, C, prec, signed=False):
    sig = bytes.fromhex("0000000C6A5020200D0A870A")
    ftyp = box(b"ftyp", b"jp2 " + struct.pack(">I",0) + b"jp2 ")
    bpc = (prec-1) | (0x80 if signed else 0)
    ihdr = box(b"ihdr", struct.pack(">IIHBBBB", Y, X, C, bpc, 7, 0, 0))
    colr = box(b"colr", bytes([1,0,0]) + struct.pack(">I", 16 if C>=3 else 17))
    return sig + ftyp + box(b"jp2h", ihdr+colr) + box(b"jp2c", build_j2k(X, Y, C, prec, signed))

def bps(p): return (p+7)//8

# (name, X, Y, C, prec)  -- ALL small pixel counts so the preview decodes them
T = [
  # 1) LOW dims, HIGH rowbytes (many components -> huge rowbytes, tiny pixel count)
  ("m1_lowdim_highrb",    256,  256, 16384, 8),    # 65K px, rowbytes=4M
  ("m1w_lowdim_highrb_wrap", 512, 512, 16384, 8), # 256K px, rowbytes=8M, prod=4G (WRAP)
  # 2) LOW rowbytes, HIGH dims (1 component, big width x height)
  ("m2_lowrb_highdim",   2048, 2048,     1, 8),    # rowbytes=2K, 4M px
  # 3) BOTH near each other, moderate, small alloc
  ("m3_both_near_small", 1024, 1024,   256, 8),    # rowbytes=256K, 1M px
]
for (n,X,Y,C,prec) in T:
    d = build_jp2(X,Y,C,prec)
    open(os.path.join(OUT,n+".jp2"),"wb").write(d)
    rb = X*C*bps(prec); prod = rb*Y
    print(f"{n:24s} {X}x{Y} c{C} p{prec} px={X*Y} rowbytes={rb} prod={prod} ({'WRAP' if prod>=2**32 else 'no-wrap'}) alloc~{prod/1e6:.0f}MB {len(d)}B")

# valid PIL control (small, decodes for sure)
Image.new('L',(256,256),128).save(os.path.join(OUT,"ctrl_pil_gray256.jp2"), format="JPEG2000")
print(f"ctrl_pil_gray256         (PIL valid) ")
print(f"\n{len(T)+1} files -> {OUT}")

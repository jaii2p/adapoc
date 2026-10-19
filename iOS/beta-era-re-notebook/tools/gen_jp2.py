#!/usr/bin/env python3
# gen_jp2.py -- JP2 test images to exercise ImageIOPixelConverter::AdjustRowBytes
# (the d*b 32-bit wrap, reached via JP2ReadPlugin::decodeImageImp).
# dstRowBytes*height = (Xsiz * Csiz * bytesPerSample) * Ysiz ; we sweep it across 2^32.
import os, struct, sys
from PIL import Image

OUT = sys.argv[1] if len(sys.argv) > 1 else "/home/box/.hermes/profiles/seraphine/cache/scratch/jp2s"
os.makedirs(OUT, exist_ok=True)

def box(typ, payload):
    return struct.pack(">I", 8 + len(payload)) + typ + payload

def build_j2k(Xsiz, Ysiz, Csiz, prec, signed=False):
    comps = b""
    for _ in range(Csiz):
        ssiz = (prec - 1) | (0x80 if signed else 0)
        comps += bytes([ssiz, 1, 1])           # Ssiz, XRsiz, YRsiz
    siz = b"\xFF\x51" + struct.pack(">HHIIIIIIIIH", 38 + 3*Csiz, 0,
            Xsiz, Ysiz, 0, 0, Xsiz, Ysiz, 0, 0, Csiz) + comps
    # COD: Scod=0, LRCP(prog=0), 1 layer, MCT=0, decomp=0, cb 64x64, style 0, transform 5/3
    cod = b"\xFF\x52" + struct.pack(">H", 12) + bytes([0]) + struct.pack(">BHB", 0, 1, 0) + bytes([0, 4, 4, 0, 1])
    # QCD: reversible, no quant, guard=1, exponent=8, 1 subband
    qcd = b"\xFF\x5C" + struct.pack(">H", 2 + 1 + 1) + bytes([0x20, 0x08])
    # SOT: Psot = 12(SOT) + 2(SOD) + Csiz(tiledata)
    psot = 14 + Csiz
    sot = b"\xFF\x90" + struct.pack(">H", 10) + struct.pack(">H", 0) + struct.pack(">I", psot) + bytes([0, 1])
    sod = b"\xFF\x93" + (b"\x00" * Csiz)        # Csiz empty packets
    return b"\xFF\x4F" + siz + cod + qcd + sot + sod + b"\xFF\xD9"   # SOC ... EOC

def build_jp2(Xsiz, Ysiz, Csiz, prec, signed=False):
    sig  = bytes.fromhex("0000000C6A5020200D0A870A")
    ftyp = box(b"ftyp", b"jp2 " + struct.pack(">I", 0) + b"jp2 ")
    bpc  = (prec - 1) | (0x80 if signed else 0)
    ihdr = box(b"ihdr", struct.pack(">IIHBBBB", Ysiz, Xsiz, Csiz, bpc, 7, 0, 0))
    cs   = 16 if Csiz >= 3 else 17           # sRGB / greyscale
    colr = box(b"colr", bytes([1, 0, 0]) + struct.pack(">I", cs))
    jp2h = box(b"jp2h", ihdr + colr)
    jp2c = box(b"jp2c", build_j2k(Xsiz, Ysiz, Csiz, prec, signed))
    return sig + ftyp + jp2h + jp2c

# (name, Xsiz, Ysiz, Csiz, prec, signed)  -- bps=ceil(prec/8)
def bps(prec): return (prec + 7) // 8
TARGETS = [
    # ---- controls (small, valid) ----
    ("c064x064_c3_p8",   64,   64,   3,  8, False),
    ("c256x256_c1_p8",  256,  256,   1,  8, False),
    ("c512x512_c3_p8",  512,  512,   3,  8, False),
    # ---- WRAP: rowbytes*height == 2^32 (wraps to 0) ----
    ("w8192h8192_c64_p8",   8192,  8192,  64,  8, False),
    ("w16384h4096_c64_p8", 16384,  4096,  64,  8, False),
    ("w4096h4096_c256_p8",  4096,  4096, 256,  8, False),
    ("w2048h2048_c1024_p8", 2048,  2048, 1024, 8, False),
    ("w1024h1024_c4096_p8", 1024,  1024, 4096, 8, False),
    ("w65536h65536_c1_p8",  65536, 65536,   1,  8, False),   # 2^32 exactly, huge pxcount
    ("w4096h4096_c64_p16",  4096,  4096,  64, 16, False),   # 16-bit
    ("w2048h2048_c256_p16", 2048,  2048, 256, 16, False),
    # ---- WRAP + small residue (passes check, real product huge) ----
    ("w8193h8192_c64_p8",   8193,  8192,  64,  8, False),   # +64*8192 over 2^32
    ("w8192h8193_c64_p8",   8192,  8193,  64,  8, False),
    ("w4097h4096_c256_p8",  4097,  4096, 256,  8, False),
    # ---- just UNDER 2^32 (no wrap, near-boundary) ----
    ("u65535h65535_c1_p8",  65535, 65535,   1,  8, False),   # 4294836225 < 2^32
    ("u32768h32768_c1_p8",  32768, 32768,   1,  8, False),   # 2^30
    ("u16384h16384_c3_p8",  16384, 16384,   3,  8, False),   # ~805M px, no wrap
    # ---- guard mapping (large pxcount, product < 2^32) ----
    ("g8192h8192_c3_p8",    8192,  8192,   3,  8, False),   # ~201M rowbytes*height
    ("g16384h8192_c1_p8",  16384,  8192,   1,  8, False),
    ("g32768h8192_c1_p8",  32768,  8192,   1,  8, False),
    # ---- signed + high bitdepth ----
    ("s8192h8192_c64_p8",   8192,  8192,  64,  8, True),
    ("p32_128x128_c3",      128,   128,   3, 32, False),
    ("p16_1024_c64",       1024,  1024,  64, 16, False),
]

made = 0
for (name, X, Y, C, prec, sgn) in TARGETS:
    data = build_jp2(X, Y, C, prec, sgn)
    p = os.path.join(OUT, name + ".jp2")
    open(p, "wb").write(data)
    rb = X * C * bps(prec)
    prod = rb * Y
    print(f"{name:22s} {X}x{Y} c{C} p{prec}{'s' if sgn else ''} rowbytes={rb} prod={prod} ({'WRAP' if prod>=2**32 else 'no-wrap'}) {len(data)}B")
    made += 1

# ---- PIL valid controls ----
for (w, h, mode, name) in [(64,64,'RGB','pil_64x64_c3'), (256,256,'L','pil_256_c1'), (512,512,'RGB','pil_512_c3')]:
    im = Image.new(mode, (w, h), (128, 64, 200) if mode == 'RGB' else 128)
    p = os.path.join(OUT, name + ".jp2")
    im.save(p, format="JPEG2000")
    print(f"{name:22s} (PIL valid) {os.path.getsize(p)}B")
    made += 1

print(f"\n{made} files -> {OUT}")

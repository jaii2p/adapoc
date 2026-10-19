#!/usr/bin/env python3
# iio_re.py -- reusable ImageIO RE tool (capstone). vaddr-native; no manual
# offset math, no r2 raw-binary quirks, bytes+symbols inline, auto dataflow.
#   dis  <vaddr> [n]        disassemble n instr at vaddr (bytes + symbol inline)
#   bt   <vaddr> [n]        traceback: n instr ENDING at vaddr
#   func <vaddr>            disassemble the whole function containing vaddr
#   whereis <vaddr>         enclosing function start + offset + nearest symbol
#   xrefs <target>          `bl` callers of target (auto-decoded)
#   allocs                  all `bl` -> alloc-fn call sites
#   trace_alloc <callva>    backwards disasm from an alloc call, size-arg (x0) dataflow marked
#   ctx <vaddr> <off>       all [reg,off] accesses in the enclosing function (struct-field trace)
#   mulw                    scan: `mul w` (32-bit) feeding a later `umull` (CWE-190 size-wrap)
#   grep <regex> [start] [n] disassemble from start, grep mnemonic/op_str
#   find <hex> | findstr <s>  byte/string search -> vaddr(s)
#   note <text>             append a timestamped note to the findings log
#   build                   (re)build the whole-text asm cache (iio_text.asm)
# Env: IIO_BIN (default .../imgio/ImageIO_text.bin), IIO_VBASE (default 0x18864c638),
#      IIO_SYMS (default .../imgio/iio_syms.txt), IIO_LOG (default aiexclfindings/re-log.md)
import os, sys, re, struct, datetime
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SCR = "/home/box/.hermes/profiles/seraphine/cache/scratch"
BIN  = os.environ.get("IIO_BIN",  f"{SCR}/imgio/ImageIO_text.bin")
VBASE= int(os.environ.get("IIO_VBASE","0x18864c638"),16)
SYMS = os.environ.get("IIO_SYMS", f"{SCR}/imgio/iio_syms.txt")
LOG  = os.environ.get("IIO_LOG",  "/home/box/Desktop/Juicy/zdhunt-fuzzer/aiExclFindings/re-log.md")
CACHE= f"{SCR}/imgio/iio_text.asm"

data = open(BIN,'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

# ---- symbols (persistent mini symbol-cache; add as found) ----
syms = []  # sorted (addr,name)
if os.path.exists(SYMS):
    for line in open(SYMS):
        m=re.match(r'\s*(0x[0-9a-fA-F]+)\s+(\S+)', line)
        if m: syms.append((int(m.group(1),16), m.group(2)))
    syms.sort()
def sym_for(va):
    # nearest symbol <= va
    best=None
    for a,n in syms:
        if a<=va: best=(a,n)
        else: break
    if best and va-best[0] < 0x4000:
        return f"{best[1]}+{va-best[0]:#x}" if va!=best[0] else best[1]
    return None
def sym_name(va):
    for a,n in syms:
        if a==va: return n
    return None

ALLOC={0x18867eda4:"allocateBlockArray(uint)",0x18865dcf0:"__ImageIO_Malloc"}

def off(va): return va-VBASE
def va(o):  return VBASE+o
def disasm_range(va, n):
    o=off(va); code=data[o:o+n*4]
    for i in md.disasm(code, va): yield i

def fmt(i):
    b=' '.join(f'{x:02x}' for x in i.bytes)
    s=sym_for(i.address)
    cm=f"  ; {s}" if s else ""
    return f"  {i.address:#x}  {b:<12s} {i.mnemonic:8s} {i.op_str}{cm}"

def bl_target(i):
    if i.mnemonic!='bl': return None
    # capstone gives target in op_str as hex
    try: return int(i.op_str.strip().lstrip('#'),16)
    except: return None

def find_func_start(v):
    o=off(v)
    j=data.rfind(bytes.fromhex('3f2303d5'),0,o)   # pacibsp
    if j<0: j=data.rfind(bytes.fromhex('fd7bbf'),0,o)  # stp x29,x30,[sp,#-..]!
    return va(j) if j>=0 else None

def enclosing_func(v):
    fs=find_func_start(v); return fs

def cmd_dis(a):
    v=int(a[0],16); n=int(a[1]) if len(a)>1 else 16
    for i in disasm_range(v,n): print(fmt(i))

def cmd_bt(a):
    v=int(a[0],16); n=int(a[1]) if len(a)>1 else 16
    for i in disasm_range(v-n*4,n): print(fmt(i))

def cmd_func(a):
    v=int(a[0],16); fs=find_func_start(v)
    if fs is None: print("no prologue found; disassembling from vaddr"); fs=v
    print(f"function start: {fs:#x}  (contains {v:#x}, +{v-fs:#x})  {sym_for(fs) or ''}")
    n=0
    for i in disasm_range(fs,400):
        print(fmt(i)); n+=1
        if i.mnemonic=='ret' and n>3: break

def cmd_whereis(a):
    v=int(a[0],16); fs=find_func_start(v)
    print(f"{v:#x}: func_start={fs:#x} (+{v-fs:#x})  sym={sym_for(v)}")

def cmd_xrefs(a):
    t=int(a[0],16); print(f"callers of {t:#x} ({sym_name(t) or '?'}):")
    for i in disasm_range(VBASE, len(data)//4):
        if i.mnemonic=='bl':
            bt=bl_target(i)
            if bt==t: print(f"  {i.address:#x}")

def cmd_allocs():
    for i in disasm_range(VBASE, len(data)//4):
        if i.mnemonic=='bl':
            bt=bl_target(i)
            if bt in ALLOC: print(f"  {i.address:#x}  bl {ALLOC[bt]}")

def writes_x0(i):
    # does this instruction write x0 or w0 (the size arg)?
    ops=i.op_str
    m=re.match(r'\s*(x0|w0)\b', ops)
    return bool(m) and i.mnemonic not in ('cmp','b','bl','cbz','cbnz','tbz','tbnz','str','stp','prfm')

def cmd_trace_alloc(a):
    v=int(a[0],16); n=int(a[1]) if len(a)>1 else 40
    print(f"traceback {n} instr before alloc call {v:#x} ({sym_name(bl_target_at(v)) if False else ''})")
    # mark size-arg (x0/w0) dataflow + muls
    for i in disasm_range(v-n*4, n):
        mark=""
        if i.mnemonic in ('mul','umull','madd','msub','smull'): mark="  <<< MUL"
        if writes_x0(i): mark="  <<< writes x0/w0 (size)"
        if i.mnemonic in ('ldr','ldur','ldrsw'): mark="  <<< load"
        bt=bl_target(i)
        if bt is not None:
            nm=sym_name(bt) or ALLOC.get(bt) or ''
            mark=f"  <<< bl {bt:#x} {nm}"
        print(fmt(i)+mark)

def bl_target_at(v):
    for i in disasm_range(v,1):
        return bl_target(i)

def cmd_ctx(a):
    v=int(a[0],16); o=int(a[1],16); fs=find_func_start(v)
    print(f"accesses to [reg, {o:#x}] in func {fs:#x}:")
    suf=f'{o:#x}]'
    n=0
    for i in disasm_range(fs, 2000):
        if suf in i.op_str:
            kind='STORE' if i.mnemonic.startswith('st') else 'load '
            print(f"  {i.address:#x}  {kind} {i.mnemonic:8s} {i.op_str}")
        n+=1
        if i.mnemonic=='ret' and n>3: break

def ensure_cache():
    if os.path.exists(CACHE) and os.path.getmtime(CACHE)>os.path.getmtime(BIN): return
    print("building asm cache (one-time)...", file=sys.stderr)
    with open(CACHE,'w') as f:
        for i in disasm_range(VBASE, len(data)//4):
            f.write(f"{i.address:#x}  {i.mnemonic} {i.op_str}\n")

def cmd_mulw():
    ensure_cache()
    lines=open(CACHE).read().splitlines()
    print("`mul w` (32-bit) feeding a later `umull` (CWE-190 size-wrap):")
    lastmul=[]  # (addr, rd)
    for ln in lines:
        m=re.match(r'(0x[0-9a-f]+)\s+(mul|umull)\s+(.*)', ln)
        if not m: continue
        a=int(m.group(1),16); mn=m.group(2); ops=m.group(3)
        if mn=='mul':
            d=ops.split(',')[0].strip()
            lastmul.append((a,d))
        elif mn=='umull':
            # umull xD, xN, xM : if xN or xM matches a recent mul w dest (w-reg)
            parts=[p.strip() for p in ops.split(',')]
            xs=set()
            for p in parts[1:]:
                if p.startswith('w'): xs.add(p)
                elif p.startswith('x'): xs.add('w'+p[1:])
            for (ma,mdst) in lastmul[-40:]:
                if mdst in xs:
                    print(f"  mul {mdst} @ {ma:#x}  -> umull @ {a:#x}")
                    break

def cmd_grep(a):
    rx=re.compile(a[0]); start=int(a[1],16) if len(a)>1 else VBASE
    n=int(a[2]) if len(a)>2 else len(data)//4
    for i in disasm_range(start,n):
        if rx.search(i.mnemonic+' '+i.op_str): print(fmt(i))

def cmd_find(a):
    pat=bytes.fromhex(a[0].replace(' ','')); i=0
    while True:
        i=data.find(pat,i)
        if i<0: break
        print(f"  {va(i):#x} (off {i:#x})  {sym_for(va(i)) or ''}"); i+=1

def cmd_findstr(a):
    pat=a[0].encode(); i=0
    while True:
        i=data.find(pat,i)
        if i<0: break
        print(f"  {va(i):#x}  {sym_for(va(i)) or ''}"); i+=1

def cmd_note(a):
    txt=' '.join(a)
    os.makedirs(os.path.dirname(LOG),exist_ok=True)
    with open(LOG,'a') as f:
        f.write(f"\n## {datetime.datetime.now():%Y-%m-%d %H:%M}\n- {txt}\n")
    print("logged.")

def cmd_build(a=None): ensure_cache(); print("cache built:", CACHE)

def main():
    if len(sys.argv)<2: print(__doc__); return
    c=sys.argv[1]; a=sys.argv[2:]
    {'dis':cmd_dis,'bt':cmd_bt,'func':cmd_func,'whereis':cmd_whereis,'xrefs':cmd_xrefs,
     'allocs':cmd_allocs,'trace_alloc':cmd_trace_alloc,'ctx':cmd_ctx,'mulw':cmd_mulw,
     'grep':cmd_grep,'find':cmd_find,'findstr':cmd_findstr,'note':cmd_note,'build':cmd_build}[c](a)

if __name__=='__main__': main()

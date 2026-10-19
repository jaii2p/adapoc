# BlueZ gobex misaligned-load (C UB) — UNICODE header decode

Component: BlueZ gobex `gobex/gobex-header.c` (OBEX header parser)
Target: BlueZ 5.85 (fixture); upstream 5.87 byte-identical (checked 2026-09-27)
Status: **CONFIRMED** (UBSan, wire-reachable) — LOW severity, UB/correctness (NOT memory corruption).

## Trigger
ANY OBEX packet carrying a UNICODE header (NAME/DESCRIPTION/TYPE…) with a body
>2 bytes. Every real OBEX exchange.

```c
/* gobex/gobex-header.c */
gobex_header_decode(...)                /* TLV parse */
  -> utf16_to_utf8 ...                  /* :65 alloca((hdr_len-5)/2 + 1) */
       (const gunichar2 *) ptr          /* :208-211 casts byte buf (payload starts at
                                           offset 3, ALWAYS odd) to 2-byte-aligned type */
         if (*utf16 == '\0')            /* :72 first misaligned load */
         buf[i] = g_ntohs(utf16[i])     /* :83 strided misaligned read loop */
```

```text
input : 01 00 09 00 41 00 42 00 43          (NAME, len=9, "ABC" UTF-16BE)
UBSAN : gobex-header.c:72:6: runtime error: load of misaligned address 0x7ffc...33
        for type 'const gunichar2', which requires 2 byte alignment
```

## Differential / scope
- ASAN+UBSAN harness (`zdhunt_gobex.c`): fires the alignment error (seen 56×).
- **Negative control**: rebuilt with `-fno-sanitize=alignment`, 120k zdhunt execs
  against the gobex parser → **0 further faults**. So there is NO OOB read/overflow
  hiding behind the alignment abort; the parser's own `hdr_len > len` bound is correct.
- Severity LOW: on x86-64 a misaligned 2-byte load is harmless in practice; UB is
  real and portable-correctness relevant (ARM/RISC-V strict-alignment, other
  toolchains). NOT memory corruption.
- Reachability from wire: YES. Fixed upstream: NO (5.87 identical).

## PoC
`poc/` — seeds that reproduce the UNICODE decode path (NAME/DESC unicode, odd-length
bodies, multi-header), driven through `zdhunt_gobex.c` (`g_obex_header_decode` →
`utf16_to_utf8` → `g_obex_header_get_unicode` + `g_obex_packet_decode`).

## Reusable lens
A bytewise TLV parser that casts the payload pointer to a wider aligned type
without memcpy/alignment-copying. The "strided misaligned read loop" is the tell —
safe on x86, UB on strict-alignment ISAs.

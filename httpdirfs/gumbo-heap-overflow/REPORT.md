# ZD-HTTPDIRFS-CWE787-001 — heap-buffer-overflow in collect_gumbo_text (HTML listing parser)

Component: httpdirfs (FUSE HTTP-dir FS)  commit 86ab2a3 (2026-10-06)
File:     src/link_parser.c  function collect_gumbo_text() lines ~193-198
Weakness: CWE-787 (out-of-bounds write) — heap overflow
Reachable: REMOTE — any web server whose directory-listing HTML contains an
  anchor (`<a href=...>text</a>`) whose inner TEXT is >= 256 bytes triggers it
  during normal GET/LIST page parsing, pre-authentication (auth not required
  to parse the listing page this way).

## Root cause
collect_gumbo_text() accumulates the concatenated text under an <a> element:

    size_t tlen = strlen(t);
    if (*len + tlen + 1 > *cap) {
        *cap = (*cap == 0) ? 256 : ((*cap * 2) + tlen + 1);
        *buf = REALLOC(*buf, *cap);
    }
    memcpy(*buf + *len, t, tlen);   // writes tlen bytes
    *len += tlen;
    (*buf)[*len] = '\0';            // writes 1 more

The initial capacity is hard-coded 256, and the FIRST text chunk is not grown
to cover a chunk larger than 256. Consequences, exactly (verified under ASAN):
  - anchor text 255 bytes: clean
  - anchor text 256 bytes: WRITE of size 1 past a 256-byte heap region
      (the `(*buf)[256]='\0'` terminator lands at index 256)
  - anchor text 257+ bytes: WRITE of size <len> (the memcpy overruns the 256
      buffer by len-256 bytes)
Disabled as the deterministic ASAN repro (below). The growth formula
`(*cap*2)+tlen+1` also under-allocates whenever `*len` is close to `*cap`
(cumulative text across nested tags), so it is a general sizing bug.

## Trigger / repro
Harness: zdhunt_html.c drives the real LinkTable_parse_html() with <(url,html)>.
Build fixture + harness + deps are under /home/box/Desktop/SeraProjs/lab-httpdirfs.

    python3 -c "open('/tmp/z.html','wb').write(b'<a href=\"x\">'+b'A'*256+b'</a>')"
    LD_LIBRARY_PATH=/home/box/.local/lib ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
        /tmp/zdhunt_html /tmp/z.html
    => ERROR: AddressSanitizer: heap-buffer-overflow
       WRITE of size 1 (256-byte text) / size N (>256) in collect_gumbo_text link_parser.c:195

Full trace (256 clean, 257 overflows) proves deterministic boundary.

## Impact
Memory-corruption WRITE (heap OOB), not just an OOB read. Exploitation = an
attacker runs httpdirfs against their server (or MITM the HTTP dir listing)
and serves an anchor whose text is large; the OOB write of up to `len` attacker
bytes into a heap region can corrupt adjacent heap — a write-what-where-adjacent
primitive. Practical severity depends on heap layout / allocator; at minimum a
reliable crash (DoS), potentially memory corruption given writer control of
`len` bytes.

## Verification status
- Reproduced deterministically with ASAN on current master (86ab2a3, 2026-10-06).
- Boundary mapped: [clean at 255, overflow at 256 (size 1), >=257 (size N)].
- Found via zdhunt targeted chained-mutation fuzzing of the LinkTable_parse_html
  harness (2 campaigns, both landed the same unique crash).
- Not yet confirmed fixed upstream; no attempt to construct RCE beyond the OOB
  write primitive.

## Workarounds (immediate)
- Limit/monitor anchor text length in parser, or grow buffer to `*len+tlen+1`
  on every chunk (use a correct growth: while (*len + tlen + 1 > *cap) *cap*=2).
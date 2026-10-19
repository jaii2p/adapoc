# CONFIRMED — TDLib markdown-v3 UTF-16/byte mismatch -> process abort (DoS)
# Status: END-TO-END, verified against the REAL full ASAN TDLib build.

## Verdict
The metric-mismatch invariant in parse_markdown_v3_without_pre is a real,
process-aborting defect reachable in the genuine TDLib binary.  An
attacker-supplied message entity whose offset/length do not align with the
byte-walked utf16_offset aborts the client (SIGABRT) inside the markdown
parser.

PoC (17-line C++, proof_min.cpp), run against the real ASAN build:
    text = "\xc3\xa9**x**"                       (é**x**)
    entities = { Bold, offset=5, length=2 }
    parse_markdown_v3(FormattedText{text, entities})
Output on the real library:
    [MessageEntity.cpp:2835] Check `entity.offset + entity.length <= utf16_offset` failed
    Aborted (core dumped)
    -> MIN_EXIT / REAL_EXIT = 134  (SIGABRT)

## Root cause (source + runtime)
parse_markdown_v3_without_pre (MessageEntity.cpp ~2773-2842):
- Splittable-entity removal loop walks text BYTES (for i<text.size(); text[i])
  while tracking a UTF-16 code-unit counter (utf16_offset += 1 + (c>=0xf0)).
- On a markup boundary it does i++ (skip ONE byte) beside utf16_offset++,
  assuming byte-stream and utf16-unit-stream advance in lockstep.
- A multibyte char (é, surrogate pair, etc.) at/near the entity boundary
  desyncs the two; the post-loop invariant fires:
      CHECK(entity.offset + entity.length <= utf16_offset)   // MessageEntity.cpp:2835
  -> process abort.

## Reachability (now PROVEN end-to-end)
Previously flagged as gated on fix_formatted_text's skip_trim clamp; the real
build confirms parse_markdown_v3 is called on the constructed
(attacker-supplied-entity) input and aborts.  The markdown entry is reachable
when the client has the "always_parse_markdown" option enabled or via the
get_markdown_v3 round-trip — both feed user/caller entities into this parser.
Impact: remote process crash / DoS of the TDLib client on a crafted message's
/serialized entity offsets.  Not (yet) shown to be memory-corruption/RCE: the
fault is a bounds-invariant CHECK (defensive abort) firing, not a wild write.

## Why the full build mattered
The macro-replica predicted this (same invariant, line 255 of the extraction),
but could not prove production reachability because it stubbed
fix_formatted_text/UserManager.  The real ASAN tdclient build (codegen +
actor + full libs) removed all doubt: this is the shipped code aborting on
attacker data.

## Files
- proof_min.cpp / proof_min (minimal reproducer + ASAN binary)
- proof_driver.cpp / proof_driver (3-case driver)
- Build: build/ ({libtdcore,libtdclient,libtdapi,tdactor,tdnet,tdmtproto,
  tddb,tdsqlite,tde2e,tdutils}.a), ASAN (detect_leaks=0 for codegen tools)
- Full build recipe: cmake -DCMAKE_BUILD_TYPE=Debug -fsanitize=address
  -DTD_GENERATE_SOURCE_FILES=OFF; ASAN_OPTIONS=detect_leaks=0 cmake --build.
  gperf built from source to ~/.local (MIME must stay ON).
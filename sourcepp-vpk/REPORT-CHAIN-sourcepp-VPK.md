# CHAIN REPORT — sourcepp VPK: "one malicious mod file" attack chain

Target: craftablescience/sourcepp @ `ad0ebe8` (2026-10-18, current HEAD at analysis time)
Bench: `/home/box/sourcepp-hunt/` (ASAN build: `build-asan/`, vpkpp+kvpp, v54 support ON by default)
Date: 2026-10-19 · Author: Ada · All findings dynamically confirmed on the shipped code, ASAN-instrumented.

---

## 1. Executive summary

A single hostile `.vpk` file — the format used for Valve game mods and distributed
through mod sites, Steam Workshop mirrors, and file-sharing links — triggers three
independent vulnerabilities in any application built on sourcepp's vpkpp library
(VPK editors, mod packagers/managers, game tooling):

| # | Vuln | Class | Confirmed | Real-world effect |
|---|---|---|---|---|
| V1 | Preload vs `compressedLength` heap OOB write | CWE-787 (+CWE-191) | **YES** (ASAN) | RCE-class memory corruption while merely *reading* an entry |
| V2 | Unvalidated signed `publicKeySize` → uncaught `length_error` | CWE-20 → CWE-248 | **YES** | Process terminates on open (`std::terminate`) |
| V3 | Sibling-prefix extraction escape (`checkForExtractionEscapeAttempt`) | CWE-22 | **YES** (file written outside extraction dir) | Files/directory trees planted outside the extraction folder with attacker content |

Attack narrative: victim downloads "cool-mod.vpk" from a mod site and opens or
extracts it in a sourcepp-based tool → (V1) heap corruption with
attacker-controlled size, offset context, and content — RCE-class; or (V2) the
tool silently dies; or (V3) the extraction writes outside its folder (integrity
attack: overwrite/corrupt sibling files of the tool's or user's choosing-adjacent
paths, plant files for persistence/social engineering). One file, three failure
modes; no exploit chain between them is required — each is independently
reachable from the same untrusted input.

Honest negative: an earlier static hypothesis ("EOF during parse throws →
terminate") was **disproven** — FileStream EOF reads are silent zeros; a
89-prefix truncation sweep produced 0 exceptions (24 misparse-OK / 65 graceful
nullptr). Recorded because the disproof is a finding too: malformed VPKs mostly
parse "successfully" into garbage entries rather than failing.

---

## 2. V1 — heap OOB write in `VPK::readEntry` (CONFIRMED)

**Sink:** `src/vpkpp/format/VPK.cpp:337` · **Alloc:** `VPK.cpp:334`

```cpp
const auto entryLength = this->hasCompression() && entry->compressedLength
                       ? entry->compressedLength : entry->length;
std::vector out(entryLength, static_cast<std::byte>(0));          // :334
if (!entry->extraData.empty()) {
    std::ranges::copy(entry->extraData, out.begin());             // :337
}
```

`compressedLength` (uint64 from file, `VPK.cpp:184`) is never adjusted for the
entry's preloaded data; only `entry.length` is (`:194 entry.length += preloadedDataSize`).
A v54 entry with `compressedLength=1, preloadedDataSize=65535` allocates a 1-byte
buffer and copies 65,535 bytes into it.

**Evidence (ASAN, shipped code, first-try PoC):**
```
heap-buffer-overflow, WRITE of size 65535
  #6 vpkpp::VPK::readEntry  src/vpkpp/format/VPK.cpp:337
0x...31 is located 0 bytes after 1-byte region, allocated at VPK.cpp:334
```

**Underflow companion:** `VPK.cpp:347/356` compute `entryLength - extraData.size()`
(uint64) → ~2^64 → `read_bytes(huge)` → `length_error` (uncaught). Corruption at
:337 completes before the throw. Second sink, same root: bake path `VPK.cpp:557`
(`binData->begin() + extraData.size()`).

**Fix:**
```cpp
const auto rawLength = this->hasCompression() && entry->compressedLength
                     ? entry->compressedLength : entry->length;
const auto entryLength = std::max(rawLength, entry->extraData.size());  // size covers both readings
...
if (entryLength > entry->extraData.size()) {   // was !=  → kills the uint64 underflow
```
Optionally reject at parse: v54 entry with `compressedLength && compressedLength < preloadedDataSize`.

**PoC:** `poc/c1-preload-overflow.vpk` (65,596 B, sha256 `618717e5…`) · harness `poc/harness_c1.cpp`.

---

## 3. V2 — unvalidated signed sizes → terminate-on-open (CONFIRMED)

**Site:** `VPK.cpp:245-252` (signature section) — same pattern anywhere a
file-declared size feeds `read_bytes` (e.g. `treeSize` at `:274` in
`verifyPackFileChecksum`).

```cpp
const auto publicKeySize = reader.read<int32_t>();       // attacker int32, no validation
...
vpk->footer2.publicKey = reader.read_bytes(publicKeySize);          // :251
vpk->footer2.signature = reader.read_bytes(reader.read<int32_t>()); // :252
```

`read_bytes(uint64)` → container `resize(n)`. Negative int32 sign-extends to
~2^64 → `std::length_error` ("vector::_M_default_append") thrown from inside
`VPK::openInternal`, which never catches → any application that calls
`VPK::open` without expecting exceptions dies via `std::terminate`. A positive
huge value (0x7FFFFFFF) requests a 2 GB allocation before failing on EOF.

**Evidence:** `poc/c2-sigsize.vpk` → harness_open prints `THREW: vector::_M_default_append`.

**Fix:** validate against the declared section and the file:
```cpp
const auto publicKeySize = reader.read<int32_t>();
if (publicKeySize < 0 || static_cast<uint64_t>(publicKeySize) + sizeof(uint32_t) > remainingBytes())
    return nullptr;
```
…applied to both sizes; plus (defense in depth) `VPK::open`/`openInternal`
should catch and return `nullptr` — a parse of an untrusted file must never
escape as an exception.

---

## 4. V3 — sibling-prefix extraction escape (CONFIRMED)

**Site:** `src/vpkpp/PackFile.cpp:110` (`checkForExtractionEscapeAttempt`), used by
`extractAll`/`extractDirectory` (:418/:440/:505). Entry paths come verbatim from
the archive — `cleanEntryPath` only normalizes slashes and lowercases; `../`
survives.

```cpp
const auto absOutDir   = std::filesystem::absolute(outputDir).lexically_normal();
const auto absFilePath = std::filesystem::absolute(outputDir / std::filesystem::path{filepath}).lexically_normal();
return !absFilePath.string().starts_with(absOutDir.string());
```

Two flaws:
1. **String-prefix check, not component-wise.** `"/…/extract_targetX/pwned.txt"`
   starts-with `"/…/extract_target"` → passes. Any sibling directory whose name
   extends the output directory's name is writable.
2. `FileStream` **auto-creates parent directories** (FileStream.h:30), so the
   escape can plant arbitrary *new* directory trees, not just write existing
   paths; `OPT_TRUNCATE` clobbers existing files.

**Evidence:** `poc/chain-mod.vpk` (113 B) contains entry
`../extract_targetX/pwned.txt`; extraction to `…/poc/extract_target` wrote
`…/poc/extract_targetx/pwned.txt` (29 B) — **outside the extraction directory**,
`extractAll` returned `true` (no error surfaced).

**Fix:** compare path components, not strings, and resolve symlinks:
```cpp
const auto absOutDir = std::filesystem::weakly_canonical(outputDir);
const auto absFile   = std::filesystem::weakly_canonical(outputDir / filepath);
auto rel = absFile.lexically_relative(absOutDir);
if (rel.empty() || *rel.begin() == "..") return true;   // escape
```
(`weakly_canonical` also collapses `..` physically, catching symlink games the
lexical version cannot.)

**Scope honesty:** the bypass reaches paths sharing the output directory's
*string prefix* (siblings like `extract_targetX`), not arbitrary filesystem
locations — absolute entry paths are rejected by the same check. Impact is
integrity: overwrite/corrupt files and plant directory trees in adjacent
locations, which in real layouts (shared mod folders, tool install dirs with
prefix-overlapping names) is exploitable for persistence or vandalism, not
arbitrary-path write.

---

## 5. Verified-vs-hypothesized

| claim | status |
|---|---|
| V1 OOB write fires on shipped code, exact alloc/write sites | **VERIFIED** (ASAN) |
| V1 underflow companion (`:347`) | verified statically; masked behind V1's throw in ASAN run |
| V2 throws length_error from open on attacker int32 | **VERIFIED** |
| V2/V1 exceptions terminate real apps (no catch in open) | verified by code read (`openInternal`/`open` contain no try/catch) |
| V3 escape file written outside extraction dir | **VERIFIED** (file on disk) |
| "EOF during parse throws" (earlier static claim) | **DISPROVEN** — 89-prefix sweep: 0 throws; EOF = silent zeros (24 misparse-OK, 65 nullptr) |
| V1 also reachable during `extractAll` (extractEntry → readEntry) | verified statically (`PackFile.cpp:387`), not separately PoC'd |

---

## 6. Remediation summary (maintainer-facing)

1. **V1:** size buffer with `std::max(rawLength, extraData.size())`; change `!=` → `>` at :339; validate `compressedLength >= preloadedDataSize` for v54 at parse time. (Critical)
2. **V2:** bounds-check all file-declared sizes (signature sizes, `treeSize`) against section/file size and sign; catch exceptions in `open` and return `nullptr`. (High)
3. **V3:** component-wise containment check with `weakly_canonical`; reject entry paths containing `..` components at parse time (defense in depth). (High)
4. **Cross-cutting:** decide the library's error contract — untrusted-input parsing must return `nullptr`/error codes, never throw. `useExceptions` should be off (or wrapped) on every parse path.

## 7. Artifacts (sha256)

```
618717e5…  poc/c1-preload-overflow.vpk   (V1, 65,596 B)
5bce8f36…  poc/chain-mod.vpk             (V3, 113 B)
b96cb196…  poc/c2-sigsize.vpk            (V2, 169 B)
c63566d6…  poc/benign.vpk                (truncation-sweep base, 101 B)
34eb1ea0…  poc/harness_c1.cpp            eb2a6537… harness_chain.cpp  6e7b9fbc… harness_open.cpp
```
Build: `cmake -B build-asan -DMZ_FETCH_LIBS=ON -DXZ_SANDBOX=no -DSOURCEPP_USE_*=OFF (except VPKPP/KVPP) -DCMAKE_{C,CXX}_FLAGS="-fsanitize=address -g -O1"`

*Responsible disclosure: findings affect a live third-party project — recommend
coordinated disclosure to craftablescience before any publication.*
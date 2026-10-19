# sourcepp VPK — vulnerability chain (CVE-pending / coordinated disclosure)

Bench findings against [craftablescience/sourcepp](https://github.com/craftablescience/sourcepp)
@ `ad0ebe8` (2026-10-18). All three vulnerabilities confirmed dynamically on the
shipped code (ASAN-instrumented build, v54 support ON by default).

**Responsible disclosure note:** maintainers have not yet been notified at time
of writing. Please do not weaponize; full per-vuln fixes are included in the
report.

## Contents

| file | what it is |
|---|---|
| `REPORT-CHAIN-sourcepp-VPK.md` | Full chain report: root causes, evidence, per-vuln fixes, verified-vs-disproven table |
| `poc/c1-preload-overflow.vpk` | V1 — heap OOB write: v54 entry with `compressedLength=1`, `preloadedDataSize=65535`. 65,535-byte write into a 1-byte heap buffer in `VPK::readEntry` (`VPK.cpp:337`) |
| `poc/chain-mod.vpk` | V3 — extraction escape: entry `../extract_targetX/pwned.txt` bypasses the sibling-prefix check in `checkForExtractionEscapeAttempt` and lands outside the extraction directory |
| `poc/c2-sigsize.vpk` | V2 — unvalidated signed `publicKeySize = -1` in the signature section → uncaught `std::length_error` from `VPK::open` → `std::terminate` |
| `poc/benign.vpk` | Well-formed control file (truncation-sweep base) |
| `poc/harness_c1.cpp` | ASAN harness for V1 (open + readEntry) |
| `poc/harness_chain.cpp` | ASAN harness for V3 (open + extractAll, reports escape file) |
| `poc/harness_open.cpp` | Open-only classifier harness (OPEN_OK / NULLPTR / THREW) |

## Reproducing (V1 example)

```sh
# build sourcepp with ASAN (vpkpp+kvpp only is enough)
cmake -B build-asan -DMZ_FETCH_LIBS=ON -DXZ_SANDBOX=no \
  -DSOURCEPP_USE_VTFPP=OFF -DSOURCEPP_USE_BSPPP=OFF -DSOURCEPP_USE_DMXPP=OFF \
  -DSOURCEPP_USE_FSPP=OFF -DSOURCEPP_USE_GAMEPP=OFF -DSOURCEPP_USE_MDLPP=OFF \
  -DSOURCEPP_USE_SNDPP=OFF -DSOURCEPP_USE_STEAMPP=OFF -DSOURCEPP_USE_TOOLPP=OFF \
  -DSOURCEPP_USE_VCRYPTPP=OFF -DSOURCEPP_BUILD_WITH_TBB=OFF \
  -DCMAKE_CXX_FLAGS="-fsanitize=address -g -O1" -DCMAKE_C_FLAGS="-fsanitize=address -g -O1"
cmake --build build-asan -j

# compile the harness (adjust -I/-L to your build tree), then:
g++ -std=c++23 -fsanitize=address -g -O1 \
  -Iinclude -Ibuild-asan/_deps/bufferstream-src/include -Ibuild-asan/_deps/kvpp-src/include \
  -Ibuild-asan/_deps/tsl_hat_trie-src/include -Iext/half/include \
  poc/harness_c1.cpp src/sourcepp/String.cpp src/sourcepp/FS.cpp \
  -o harness_c1 build-asan/libsourcepp*.a <dep libs> -lpthread -ldl

ASAN_OPTIONS=detect_leaks=0 ./harness_c1 poc/c1-preload-overflow.vpk
# => AddressSanitizer: heap-buffer-overflow WRITE of size 65535
#    #6 vpkpp::VPK::readEntry src/vpkpp/format/VPK.cpp:337
#    0 bytes after 1-byte region allocated at VPK.cpp:334
```

## One-line summary of each bug

1. **V1 (CWE-787):** `VPK::readEntry` sizes the output buffer from
   `compressedLength` but copies the preloaded data into it unconditionally —
   the two header fields are never cross-validated. Fix: size with
   `std::max(rawLength, extraData.size())`.
2. **V2 (CWE-20 → CWE-248):** signature-section sizes are read as *signed*
   int32 from the file and passed straight to `read_bytes` — negative values
   throw `std::length_error` out of `open()`, terminating the process. Fix:
   validate sizes against section/file bounds; catch in `open()`.
3. **V3 (CWE-22):** the extraction escape guard compares **string prefixes**,
   so any sibling directory whose name extends the output directory's name
   passes (`extract_target` vs `extract_targetX`), and `FileStream`
   auto-creates missing parents. Fix: component-wise containment check with
   `weakly_canonical`.
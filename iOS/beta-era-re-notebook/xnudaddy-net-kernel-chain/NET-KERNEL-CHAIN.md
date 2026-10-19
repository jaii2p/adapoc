# Network → Kernel Hijack Chain (iPad 9, iOS 18.7.8 / 22H352)
Date: 2026-10-11 (CORRECTED) · All CVEs fixed in 18.7.10 → 18.7.8 VULNERABLE
Box: 172.20.10.2 (wlan0; DHCP, may be .4) · iPad: 172.20.10.7 · same Wi-Fi (iPhone personal-hotspot AP, BSSID 86:88:06:47:a4:1a, SSID "pwned thanks free", ch149)

> CORRECTION (2026-10-11): the first version of this doc SHUFFLED two CVE impacts.
> Per Apple's 18.7.10 advisory (support.apple.com/en-us/148287):
>   CVE-2026-64724 = mDNSResponder = "attacker on the LOCAL NETWORK may cause a DENIAL-OF-SERVICE" (memory handling) — NOT a sandbox escape.
>   CVE-2026-43723 = MediaRemote  = "an APP may gain ROOT privileges" (path handling / CWE-22) — NOT a local-network DoS.
> The sandbox-escape entry is CVE-2026-64740 (Game Center). The local-network DoS entry is CVE-2026-28960 (Messages).
> T2 payoff is therefore MediaRemote (root), and its delivery needs on-device app code-exec — which is what T1 supplies.

## The chain

T1  Wi-Fi   CVE-2026-64726   physical proximity (802.11) → corrupt PROCESS memory
                              (userland Wi-Fi parser / driver copy-out; "process" not "kernel")
        ↓ foothold: code-exec / heap control in a network-adjacent userland process
T2  MediaRemote CVE-2026-43723  (app-context) path-traversal → ROOT file write/delete
        (reliable = arbitrary root file DELETE; racy = root file WRITE; public PoC: rooootdev/n-days)
    mDNSResponder CVE-2026-64724  local-network zero-auth → DoS / memory-handling bug (supporting)
        ↓ sandbox foothold: on-device app code-exec upgraded to root
T3  Kernel  CVE-2026-43810  remote user → corrupt KERNEL memory   (primary; CWE-119/416/787)
    APFS    CVE-2026-64695  remote → corrupt KERNEL memory          (alternate)
    Kernel  CVE-2026-64735  remote → bypass network filters         (force multiplier)
        ↓ kernel memory corruption
T4  kernel RCE → arbitrary kernel R/W → task_for_pid(0)/JIT → sandbox escape → full device

## Vulns that hit us (component + Apple impact) — corrected

| CVE | component | Apple impact (verbatim) |
|---|---|---|
| CVE-2026-43810 | Kernel | remote user → corrupt kernel memory |
| CVE-2026-64695 | APFS | remote user → corrupt kernel memory |
| CVE-2026-64735 | Kernel | remote attacker → bypass network filters |
| CVE-2026-64726 | Wi-Fi | attacker in physical proximity → corrupt process memory |
| CVE-2026-43723 | MediaRemote | an app may gain ROOT privileges (path handling, CWE-22) |
| CVE-2026-64724 | mDNSResponder | attacker on local network → denial-of-service (memory handling) |
| CVE-2026-28960 | Messages | remote attacker → denial-of-service |
| CVE-2026-64740 | Game Center | malicious app → break out of its sandbox |
| CVE-2026-43803 | CoreAudio | remote attacker → system termination (OOB) |
| CVE-2026-43818 | ImageIO | crafted image → arbitrary code execution (thumbnail XPC) |
| CVE-2026-43811 | Books | app → delete files w/o permission |
| CVE-2026-64747 | AVEVideoEncoder | app → DoS |
| CVE-2026-43807 | MobileAccessoryUpdater | malicious accessory → termination (buffer overflow) |

## iPad network attack surface

- Listening ports: only 49152/tcp (XPC/ephemeral; resets on HTTP probe)
- Same Wi-Fi as box → Wi-Fi proximity bugs + mDNS + MediaRemote reachable
- iPad is USB-attached to box → crash logs / sysdiagnose pullable over lockdown even if Wi-Fi down

## PoC code (unified driver: xnudaddy/CHAIN.py)

- T1-wifi-64726/poc/framegen.py — scapy 802.11 generator (H1–H5), dry-run default, gated --send  [LANDED]
- T2-mDNS-mediaremote/poc/mdns_fuzz_64724.py + mediaremoted_traversal_43723.py  [pending]
- T3-kernel-43810/poc/trigger_gen_43810.py + trigger_gen_64695.py + probe_64735.py  [pending]
- T4-kernel-rce/DESIGN.md + kernel_rce_skeleton.py  [pending]

## Already-confirmed primitives (this device)

- CVE-2026-28977 EXR heap overflow (write) — ImageThumbnailExtension, zero-click thumbnail
- CVE-2026-43794 GPUProcess UAF (field-read) — WebKit/GPUProcess
- CVE-2026-43700 WebGL readPixels uninitialized-heap leak
- CVE-2026-86950 CoreGraphics glyph OOB write (16-bit pair) — PDF font, KEV
- CVE-2022-37434 zlib underflow (WASM proof, sandboxed)

## Open tracks

- bookassetd sandbox escape (bl_sbx) via HTTP requests — PARKED (blocked on Books SystemGroup UUID)
- 43794 UAF → control flow: proven impossible (field-read ceiling)
- EXR 28977 groom → controlled write: not yet achieved (broad corruption only)

## Key unknowns (blockers)

1. Which kernel subsystem 43810 lives in (Apple names only "Kernel") — a panic string collapses this.
2. How an APFS object reaches the kernel "remotely" on iOS (no user-facing mount) — migration/restore streaming is the strongest story; a macOS Sequoia <15.7.8 box is the best proxy lab.
3. T1's exact frame type / userland parser (H1 vendor-IE desync is the leading hypothesis, unverified).
4. MediaRemote delivery: needs on-device app code-exec (T1's job) — no verified network transport into mediaremoted.

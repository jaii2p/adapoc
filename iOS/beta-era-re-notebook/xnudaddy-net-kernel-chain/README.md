# xnudaddy — network→kernel chain (SCAFFOLDING, staged in the notebook)

This is the net→kernel chain work against the lab iPad (iOS 18.7.8). It is
preserved here as research/scaffolding, NOT as a confirmed finding.

**STATUS per the source README: SCAFFOLDING. "Nothing transmitted, no crash
observed. Dry-run default everywhere."** Every stage is a design/PoC scaffold;
none of the CVEs involved (64726 Wi-Fi proximity, 43723 MediaRemote→root,
43810/64695/64735 kernel) is claimed as reproduced here. The chain is a
hypothesis against public Apple advisories, not a demonstrated exploit.

- `framegen-64726-landed.py` — the one stage whose code *landed* (802.11 mgmt
  frame generator); dry-run / pcap only, gated `--send`.
- `NET-KERNEL-CHAIN.md` — the corrected chain design (per-Apple-impact
  attribution for each CVE) + honest "Already-confirmed primitives" list which
  ARE covered by the confirmed iOS findings elsewhere in this repo.

Do not read this as a finding. It is the honest record of an unfinished,
scaffolding-only chain.

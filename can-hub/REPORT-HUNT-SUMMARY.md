# can-hub hunt summary — 4 targets, one confirmed finding, three clean layers

Target: can-hub-io/can-hub @ `e7b3653` (2026-10-19 HEAD) · bench `/home/box/canhub-hunt/`
Method: full reads of the security-critical subset (~6,000 lines), static + live confirmation on vcan0.

## Findings

### F1 — CONFIRMED (live): plaintext-transport authorization bypass (High)
Every broker authorization check (`clientCanRead`/`clientCanWrite`/`peerCanConfigure`/
`agentIdentityStatus`) short-circuits to **allow** for fingerprint-less peers; plain-TCP
peers have no fingerprint by construction (`tcp_server_transport.c:164`). Live-confirmed
end-to-end on vcan0 with default hub config: an unauthenticated third client sniffed and
injected CAN frames (`123#DEADBEEF` round-tripped through the hub). The doc-promised
warning for remote exposure (`doc/design.md` "the hub warns") only fires when
`--require-known-peers` is set — off by default (`hub_main.c:143`).
→ `REPORT-F1-PLAINTEXT-AUTHZ-BYPASS.md`, `poc/f1-demo.sh`.

### F2 — admin boundary: CLEAN (negative, register-verified)
Suspected remote-admin via role adoption; disproven. `tcp_server_transport.c`'s
`local = true` belongs to the **unix-socket init** (`sockaddr_un`); the inet-TCP init
goes through `initTransportBase` → `memset` → `local = false`. `HubPeer_AdoptRole`
grants admin only to genuinely local peers; all 12 `ADMIN_*` handlers are uniformly
role-gated; ACL `can_admin` is a separate interface-configure right, not hub-admin.

### F3 — identity layer: CLEAN internally, two design notes
- `identity_database.c`: parameterized SQL throughout, bounded copies, validated blobs.
- `tls_identity_ed25519.c` / `tls_identity.c`: DER writer, bounds-checked, no parse surface.
- `pinned_server_verifier.c` / `tls_ed25519.c`: DER reader sound (no overflow path), OID
  pinned to Ed25519 (deliberate key-confusion kill), pin = SHA(leaf DER), signature
  verification delegated correctly to monocypher.
- Design notes: TOFU name-squatting window (documented tradeoff, locked mode closes it);
  TOFU pin-commit race on first connect (inherent).

### F4 — netlink/interface path: CLEAN
`can_netlink.c`: bounded attribute writers, `NLMSG_OK`/`RTA_OK`-safe parsing, payload
checks before every field read, `if_nametoindex` (no kernel string injection).
`ifconfig_message.c`: fixed-width structs, `copyName` terminates, sample-point validated.
`interface_settings_text.c`: CLI-side only, `readU32` overflow-checked. One theoretical:
`appendAttribute` truncates `rta_len` to uint16 for >65,531-byte attributes — no caller.

### Channel layer (pre-target): CLEAN
Crypto properly delegated (picotls + monocypher + fusion/armv8 AES-GCM backends); framer
bounded (uint16 length, clamped memcpy, callers tear down on overflow — availability wart
only: 4,096-byte buffer vs 65,539-byte max message).

## Overall assessment

A disciplined codebase with one fail-open seam (F1) and a doc/code mismatch where the
documented remote-exposure warning doesn't fire in the default (TOFU) mode. Coordinated
disclosure recommended: `ISSUE-DRAFT.md` (in adapoc) is ready for the can-hub tracker.
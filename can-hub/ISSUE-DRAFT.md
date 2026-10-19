**Title:** Plain-TCP transport bypasses the entire authorization layer (read + inject CAN frames with zero credentials); documented warning doesn't fire in default mode

Hi! I audited the secure-channel and authorization stack (`e7b3653`) and confirmed one design-level access-control finding, live end-to-end on vcan0. Full report + demo script: **https://github.com/jaii2p/adapoc** (can-hub section, `REPORT-F1-PLAINTEXT-AUTHZ-BYPASS.md`)

**The short version:** every authorization check in the broker short-circuits to *allow* when a peer carries no certificate fingerprint — and plain-TCP peers never carry one (`tcp_server_transport.c:164` sets it to NULL). So on the plaintext transport:

- `clientCanRead` / `clientCanWrite` return true unconditionally → any peer can sniff **and inject** CAN frames on every bridged interface
- `peerCanConfigure` returns true → interface configuration without any check
- `agentIdentityStatus` returns OK → register as **any** agent name, no pin, and displace same-named peers (`HubPeer_IsSameAgent` has a dedicated plaintext path)

The `client_acls` table can never deny anything to a plaintext peer — the ACL layer only applies to fingerprint-carrying TLS/QUIC connections.

**Live confirmation (default config, vcan0):** hub running with default listeners, agent registered `demo`/vcan0; a third client with **zero credentials** over plain TCP ran `dump demo/vcan0` (read granted) and `send demo/vcan0 123#DEADBEEF` / `456#…` (both accepted), and its own dump captured the injected frames round-tripping:

```
(1792442645.725629) 123 [4] DE AD BE EF
(1792442646.227673) 456 [8] 00 11 22 33 44 55 66 77
```

**The part I suspect you'll most want to look at:** `doc/design.md` documents the bypass and says "the hub warns" when plain TCP is exposed remotely — but the warning at `hub_main.c:143` is gated on `require_known_peers`, which **defaults to false**. So the operator who runs `--listen tcp://0.0.0.0:7228` in default (TOFU) mode — the internet-exposed case this project exists for — gets **no warning at all** and a hub where any internet peer has full read/inject/configure. The default *bindings* are right (plain TCP → loopback), so this only bites on deliberate exposure; but the doc promises a safety net that isn't wired up outside locked mode.

**Suggested fixes:**
1. Move the `hub_main.c:143` warning out of the `require_known_peers` gate — warn (or refuse) on any non-loopback plain-TCP bind.
2. Optionally add an explicit `--allow-unauthenticated-tcp` opt-in so the dangerous posture is a positive act.
3. Consider an implicit deny-by-default ACL row for fingerprint-less peers so `client_acls` governs all transports uniformly.

To be clear on framing: the default bindings are correct, the parse layer is uniformly bounds-checked, and the crypto delegation (picotls/monocypher/fusion) is clean — this is one fail-open seam in an otherwise disciplined codebase, plus a doc/code mismatch where the documented warning doesn't fire in the default mode. Happy to provide more detail.
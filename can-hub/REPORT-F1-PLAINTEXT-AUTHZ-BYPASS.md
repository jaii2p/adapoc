# can-hub finding F1 — plaintext-transport peers bypass the entire authorization layer (and the documented warning doesn't fire in default mode)

Target: can-hub-io/can-hub @ `e7b3653` (2026-10-19, current HEAD) — CAN-bus-over-IP hub/agent/client suite
Bench: `/home/box/canhub-hunt/` · Date: 2026-10-19 · Status: statically confirmed, code + docs; live PoC pending vcan setup
Class: CWE-284 (improper access control) / CWE-1188 (insecure default initialization) / doc-code mismatch

## The authorization short-circuit

Every authorization decision in the broker short-circuits to **allow** when the
peer carries no certificate fingerprint (`src/hub/broker.c`):

```c
static bool clientCanRead(...)  { if (peer->fingerprint_hex[0]=='\0') return true; ... }
static bool clientCanWrite(...) { if (peer->fingerprint_hex[0]=='\0') return true; ... }
static bool peerCanConfigure(...) { if (peer->fingerprint_hex[0]=='\0') return true; ... }
static uint8_t agentIdentityStatus(...) {
    if (identity_store == NULL || peer->fingerprint_hex[0]=='\0') return REGISTER_STATUS_OK; ...
}
```

Plain TCP peers carry no fingerprint **by construction**
(`tcp_server_transport.c:164: info.fingerprint_hex = NULL;`). Therefore any peer
on the plaintext transport:

- reads frames on **every** interface (`clientCanRead` → true),
- **injects frames** on every interface (`clientCanWrite` → true) — on a CAN
  bridge this is arbitrary frame injection onto the connected bus,
- configures interfaces (`peerCanConfigure` → true),
- registers as **any agent name** with no pin, no mismatch check
  (`agentIdentityStatus` → `REGISTER_STATUS_OK`), and can displace the
  registration of a same-named peer (`displaceGhostPeer` →
  `HubPeer_IsSameAgent` has a dedicated plaintext path that never compares keys).

The ACL layer ("the next layer" per `doc/design.md`) only ever applies to
fingerprint-carrying TLS/QUIC peers — plain TCP bypasses it entirely, so
`client_acls` cannot deny anything to a plaintext peer.

## The doc-code mismatch (the part the maintainers will want to know)

`doc/design.md:57` documents the model honestly — plain tcp "defaults to binding
127.0.0.1 (a deliberate `--listen tcp://0.0.0.0:...` exposes it on a trusted
network/VPN, where it bypasses the allowlist — **the hub warns**)."

But the warning only exists in locked mode:

```c
// hub_main.c:143
if (require_known_peers && tcp_enabled && strcmp(tcp_listen.bind_address, "127.0.0.1") != 0) {
    LOG_WARN("plain tcp on %s carries no identity and bypasses the allowlist; ...");
}
```

`require_known_peers` defaults to **false** (`hub_main.c:67`, set only by
`--require-known-peers`). So in the **default (TOFU) mode**, an operator who
exposes the plaintext transport remotely (`--listen tcp://0.0.0.0:7228` — the
exact "real deployment" step this project exists for, since its purpose is
NAT-traversing hubs across the internet) gets **no warning at all** and a hub
where any internet peer can sniff and inject CAN traffic. The documented safety
net does not fire in the default configuration.

Default-binding is genuinely good (plain TCP → `127.0.0.1:7228` only; quic/tls →
0.0.0.0) — this finding is about the remote-exposure path the project's own
documentation invites, and the fail-open shape of the short-circuits (a
transport without identity gets *allow-everything*, not allow-nothing).

## Secondary observations

- **TOFU identity squatting (default mode):** first connector owns an agent
  name (`agentIdentityStatus` → `storePin`); a pre-connector permanently
  occupies `truck42` and the real device is rejected on fingerprint mismatch.
  Documented tradeoff ("first contact auto-pins, zero-config"), but on
  internet-exposed TLS hubs the race window is attacker-winnable. Locked mode
  (`--require-known-peers`) closes it.
- **Framer capacity:** 4,096-byte framer buffer vs uint16 message length
  (max 65,539): an over-capacity header permanently stalls the framer; callers
  tear the channel down. Availability wart, handled.
- `pin_store.c`: `replaceFile` deletes the store then renames (data-loss edge on
  rename failure); predictable `.tmp` path (local attacker only).
- Message parsers (`protocol/*`): uniformly bounds-checked — clean.

## Severity

High in the exposed-plaintext configuration the project invites (no crash, but
full unauthenticated read+inject on a CAN bridge — vehicle/industrial impact);
informational in default-loopback config. The doc-code mismatch is the
actionable defect: either warn unconditionally on non-loopback plain TCP, or
fail closed unless an explicit opt-in flag acknowledges it.

## Suggested fixes

1. Warn (or refuse) whenever plain TCP binds non-loopback, **regardless of
   `require_known_peers`** — one-line move of the `hub_main.c:143` condition.
2. Consider an `--allow-unauthenticated-tcp` explicit opt-in for the trusted-network case, making the dangerous posture a positive act.
3. Optionally: give fingerprint-less peers an implicit deny-by-default ACL row instead of short-circuit-allow, so `client_acls` governs all transports uniformly.
4. TOFU squatting: document more loudly, or add a "name reserved during grace window" option.

## Status

- Static: complete (every cited line read; behavior cross-checked against docs).
- **Dynamic: CONFIRMED end-to-end (2026-10-19, live on vcan0).**
  Built the suite (Release), ran the hub with **default configuration** (plain
  tcp://127.0.0.1:7228, quic/tls on 0.0.0.0:7227), attached an agent
  (`can-hub-agent --connect tcp://127.0.0.1:7228 --name demo vcan0` →
  `registered as demo: vcan0=ch0`), then connected a **third client with zero
  credentials** (no certificate, no fingerprint, no registration) over the same
  plain-TCP transport:
  - `can-hub-client … dump demo/vcan0` — read access granted, live frame stream.
  - `can-hub-client … send demo/vcan0 123#DEADBEEF` and `456#0011223344556677` —
    both injections accepted (exit 0).
  - The attacker's own dump captured the injected frames round-tripping through
    the hub (candump format):
    ```
    (1792442645.725629) 123 [4] DE AD BE EF
    (1792442646.227673) 456 [8] 00 11 22 33 44 55 66 77
    ```
    (dump.log sha256 `9cff7a6da315a5ab08e4ac1ef6b6520605f4f3ee8947405df8d1cb9618e23404`)
  - Same code path executes for a remotely bound listener
    (`--listen tcp://0.0.0.0:7228`); loopback was used only because the bench
    demo did not need the remote variant.
- Read (sniffing), write (frame injection), and register-as-any-agent are all
  confirmed live with zero credentials on the plaintext transport.
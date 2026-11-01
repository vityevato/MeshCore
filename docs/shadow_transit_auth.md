# Shadow transit auth (`shd.*`)

Shadow transit auth is an optional overlay for MeshCore repeaters and
companion nodes. On a repeater, it lets ordinary traffic through only when the
source node proves possession of an Ed25519 key on the repeater's allowlist.
The overlay is carried inside ordinary `GRP_TXT` v1 packets, so it does not
change the protocol version and old repeaters forward it as a normal group
packet.

There is no network-wide master key. A repeater stores only the public keys of
authorized nodes and verifies each packet signature itself.

## Envelope

Outer packet: ordinary `GRP_TXT` v1. The first bytes of the group payload are
the shadow header:

```text
0: shadow_ch   1   fixed 0x53
1: magic       2   fixed 0x5CC5
3: tag         3   first three bytes of the source public key
6: flags       1   version (high 4 bits) + mode (low 2 bits)
```

Modes:

| Mode | Flags | Format | Overhead | Max inner |
|---|---|---:|---:|---:|
| embedded | 0 | `[common][inner_type][inner_payload][sig 64]` | 72 | 112 |
| signature | 1 | `[common][sig_id 4][msg_hash 16][sig 64]` | - | - |
| message | 2 | `[common][sig_id 4][inner_type][inner_payload]` | 12 | 172 |
| fragment | 3 | `[common][frag_id 4][index 1][count 1][inner_type 1][chunk][sig 64]` | 78/fragment | 106/fragment |

`msg_hash` is the first 16 bytes of a SHA-256 digest. `sig_id` and `frag_id`
are 4-byte counters seeded from the RNG at boot. Every fragment is signed
separately; there is no Merkle tree.

The signature covers a domain-separated digest of the outer header, path mode,
the shadow header and the mode-specific bytes. Path bytes, hop count and outer
transport codes are not covered: repeaters rewrite path bytes, and the transport
code is derived from the final payload (including the signature) for legacy
region routing. Path and transport codes are routing metadata, not source
authentication.

## Repeater policy

With `shd.enabled on` and `shd.enforce on` a repeater:

- verifies embedded/signature/message/fragment envelopes before they enter the
  delayed inbound queue;
- forwards only verified shadow packets, plus the explicit exceptions below;
- drops ordinary `TXT_MSG`, `GRP_TXT`, `GRP_DATA`, `REQ`, `RESPONSE`, `PATH`,
  `TRACE`, `MULTIPART` and `RAW_CUSTOM`;
- allows ordinary `ANON_REQ` for login/admin, rate-limited;
- allows `ADVERT` only from allowlisted keys by default, for both ordinary and
  shadow-wrapped adverts; with `shd.allow.advert on` all valid signed adverts
  are allowed, rate-limited;
- allows zero-hop `CONTROL`;
- drops ordinary ACKs.

The early filter runs in `Dispatcher::checkRecv()` before `queueInbound()`, so
unauthorized floods do not consume the packet pool or the delayed queue.

### Reply envelope

Locally generated replies mirror the transport envelope of the request that
triggered them:

- a shadow-wrapped request gets a shadow-wrapped `RESPONSE`, `ACK`, `PATH` or
  `TXT_MSG` reply;
- an ordinary request gets an ordinary reply, so legacy and shadow-off clients
  keep working while `shd.enforce` is off;
- `ANON_REQ` login is the exception: its reply stays wrapped, because the login
  request itself is an ordinary exception that has to traverse enforcing
  repeaters. A client without shadow support can therefore use status,
  telemetry and CLI commands against a shadow-enabled repeater, but cannot
  complete login; add it to the repeater ACL with `setperm` if needed;
- unsolicited locally generated packets keep the normal `shd.enabled` behavior.

### Detached messages

A Message packet can arrive before its Signature packet. The repeater holds it
in a compact pending buffer (default 24 entries, not `Packet` pool objects) and
releases it when the matching signature arrives. Messages are only held for
allowlisted tags.

### Dedup

`VerifiedHashCache` stores 16-byte hashes of packets whose signature has
already been verified. A cache hit skips Ed25519 verification. The cache is
only populated after successful verification, so an invalid packet cannot
poison it. When an entry is evicted, a duplicate is re-verified.

### Dynamic hold TTL

There is no TTL field in MeshCore. The repeater measures actual delays and
derives hold times:

```text
hold_ttl_ms = clamp(max(hold_default_ms, 2 * max_msg_wait_ms + margin_ms),
                    hold_min_ms, hold_max_ms)

sig_ttl_ms  = clamp(max(hold_ttl_ms + 30000, 2 * max_sig_wait_ms + margin_ms),
                    75000, 240000)

frag_ttl_ms = clamp(max(hold_ttl_ms, 2 * max_frag_gap_ms + margin_ms),
                    45000, 180000)
```

Only the maximum of the last 32 positive samples is used. The estimates are
written to `/shadow_prefs` once an hour (and on setting changes). If the saved
data is older than 24 hours at boot, the estimates are reset to defaults.

## Adverts

Shadow-enabled nodes and repeaters wrap their own adverts. The inner payload is
the normal `ADVERT` (`pubkey 32 + timestamp 4 + signature 64 + app_data`), so it
keeps its own Ed25519 signature.

- Inner length up to 112 bytes: `embedded`, one packet.
- Longer inner (113..132): `message`/detached, signature packet + message.
- Adverts are never fragmented, even if `shd.mode fragment` is forced.

Policy:

| `shd.allow.advert` | Wrapped advert from allowlisted pubkey | Wrapped advert from unknown pubkey |
|---|---|---|
| `off` | passes | dropped |
| `on` | passes | passes if the inner advert signature is valid; rate-limited |

The advert rate limit is 8 adverts per minute per tag and is separate from the
transit-packet budget, so normal shadow traffic does not consume an
allowlisted node's advert allowance. Ordinary and wrapped adverts share the
same advert budget. An exact duplicate already accepted through the
`VerifiedHashCache` fast-path does not consume another advert slot.

The same policy applies to ordinary (non-wrapped) adverts sent by old nodes.
`on` is an explicit discovery exception: the inner advert's own signature is
the trust anchor. For wrapped adverts the outer shadow signature is not the
trust anchor and is not checked; path bytes, path hash size and outer
transport codes are routing metadata and are not authenticated for adverts.
For detached adverts from an unknown sender, enforcing repeaters drop the
separate shadow signature packet, but the message packet still passes because
the advert is self-authenticating. This costs one extra 91-byte signature
packet; it does not affect correctness.

Ordinary adverts are signature-checked by `Mesh` for flood and zero-hop
traffic. A crafted direct advert with a non-empty path is retransmitted by
`Mesh` before its payload switch, so the early filter verifies that signature
itself before setting `auth_ok`.

A repeater unwraps only zero-hop direct adverts (for neighbour discovery).
Flood adverts are forwarded as the outer shadow envelope; on a node with a
receive hook they are unwrapped and processed normally.

Old nodes cannot unwrap adverts and therefore do not discover shadow-enabled
nodes/repeaters via adverts. Manual contact import/QR still works. Old
repeaters forward wrapped adverts as ordinary `GRP_TXT` within the normal
184/255 limits.

## Login / auto-add

A node that is not on the allowlist sends a normal `ANON_REQ` login with the
repeater password. The target repeater checks the password and, with
`shd.auto.add on` (default), adds the node's public key to the allowlist.
The guest password does not auto-add; add a guest manually with `shd.allow`
if it needs transit access.
Intermediate repeaters cannot check the password; they only forward the
`ANON_REQ` exception with a rate limit.

For multi-hop administration, every enforcing repeater on the path needs the
admin node's public key in its allowlist (or the admin must log in to each of
them).

On the first boot after upgrading a repeater, authenticated ACL clients are
copied into `/shadow_acl` once (guests and deleted entries are skipped). This
avoids locking existing users out when enforcement is enabled. Later
`shd.remove` commands are not undone by a reboot.

## CLI

Repeater:

```text
shd.enabled on|off          default on
shd.enforce on|off          default off
shd.allow.anon on|off       default on
shd.allow.advert on|off     default off (only allowlisted adverts)
shd.auto.add on|off         default on
shd.pending.max <n>         default 24
shd.hold.min <ms>           default 45000
shd.hold.max <ms>           default 180000
shd.hold.default <ms>       default 60000
shd.margin <ms>             default 2000
shd.status
shd.stats
shd.allow <pubkey-hex>
shd.remove <pubkey-hex>
shd.list
```

Node / companion:

```text
shd.enabled on|off          default on
shd.mode auto|embedded|detached|fragment
shd.status
```

On a node, `shd.enabled` controls only the node's own outgoing wrapping. A
shadow-capable companion always unwraps incoming shadow envelopes, even with
`shd.enabled off`, so it can still read replies, messages and adverts from
shadow-enabled peers. `shd.status` reports `enabled` (TX) and `rx` separately.

`shd.status` on a repeater reports whether shadow is enabled, enforcement,
pending/signature/allowlist usage, observed delays and current TTLs.
`shd.stats` reports the drop counters. On a node `shd.status` reports the
TX/RX state, mode, counters and fragment reassembly state.

With `MESH_DEBUG=1`, every successful `shd.*` setting change is logged on the
serial console as `DEBUG: shd.<name> -> <value>`.

The allowlist is stored in `/shadow_acl`. The normal profile keeps 128
public keys (32 on the low-memory profile); when full, `shd.allow` returns
`Err - allowlist full` and entries must be freed with `shd.remove`.

## Debug logging

Build with `-DMESH_DEBUG=1` to get `SHADOW ...` decision logs: drops with
reasons, successful verification/unwrap, pending/signature cache lifecycle,
fragment reassembly, ACL changes and persistence errors.

`-DMESH_PACKET_LOGGING=1` additionally enables per-packet `SHADOW TRACE:`
lines (dedup hits, ordinary pass-through, rate limits, transport codes and
TX wrapper details).

Both are compile-time flags; release builds have the logs compiled out.
Per-packet logging is synchronous and can affect timing on a busy repeater,
so use it for active debugging rather than long unattended runs.

## 160-byte text

A 160-byte chat message produces an inner payload of about 180 bytes, which is
larger than the detached message limit (172). The companion automatically uses
fragment mode: two fragments of at most 106 bytes. The receiving companion
reassembles them and the application still sees the original 160-byte text.
The companion adds 2 seconds to its send timeouts while shadow mode is enabled,
covering the signature packet delay and one extra fragment.

## Memory

Default profile:

| Component | Approx. size |
|---|---:|
| pending 24 | ~7 KB |
| VerifiedHashCache 256 x 16 | ~4.3 KB |
| SignatureCache 16 | ~0.5 KB |
| fragment reassembly 4 | ~0.9 KB |
| allowlist 128 | ~5 KB |
| TTL tracker, prefs, rate tables | ~0.8 KB |
| **Total** | **~18 KB** |

For 64-128 KB MCUs the low profile is selected automatically on
`STM32_PLATFORM`, or explicitly with `-DSHADOW_LOW_MEMORY`:
pending 8, verified cache 64, signature cache 8, fragment reassembly 2,
allowlist 32 (~6 KB).

## Firmware support

Shadow is implemented in the Companion Radio and Simple Repeater firmware.
Other MeshCore firmware roles are legacy participants:

| Firmware | Shadow TX | Shadow RX | Notes |
|---|---:|---:|---|
| Companion Radio (`companion_radio`) | yes | yes | `shd.enabled` controls TX; RX always unwraps |
| Simple Repeater (`simple_repeater`) | yes | yes | filters transit when `shd.enforce on` |
| Simple Sensor (`simple_sensor`) | no | no | no `shd.*`; cannot wrap or unwrap |
| Simple Room Server (`simple_room_server`) | no | no | no `shd.*`; cannot wrap or unwrap |
| Simple Secure Chat (`simple_secure_chat`) | no | no | no `shd.*`; plain chat only |

The KISS modem is a raw packet bridge; it has no shadow layer, and a host
application must generate and parse shadow envelopes itself.

## Compatibility and limitations

- Old repeaters see a normal `GRP_TXT` with an unknown channel hash and forward
  it. All modes fit the old limits (`payload <= 184`, raw packet `<= 255`).
- Old nodes ignore the unknown group channel. New nodes unwrap it even when
  their own `shd.enabled` is off; that setting only controls outgoing wrapping.
- `shd.enabled on` on a repeater only wraps its own packets; legacy traffic is
  still forwarded while `shd.enforce off`. A shadow-enabled companion wraps
  its own outgoing packets even when no repeater is enforcing.
- These limitations apply to the Sensor firmware role (`simple_sensor`), not
  to optional sensor support compiled into a Companion or Repeater.
- With `shd.enforce on`, a Sensor, Room Server or Secure Chat node cannot
  communicate across the repeater. Ordinary `TXT_MSG`, `REQ`, `RESPONSE`,
  `GRP_TXT`/`GRP_DATA`, `PATH`, `TRACE`, `MULTIPART` and `RAW_CUSTOM` packets
  are dropped, as are ordinary `ACK`s, so sensor telemetry, alerts and
  commands, and room-server posts and logins, do not get through. `ANON_REQ`
  is forwarded, but the server's plain `RESPONSE` is dropped, so login still
  fails. Adding the node's public key to the shadow allowlist, or enabling
  `shd.allow.advert`, only lets its adverts through; data traffic remains
  blocked.
- A shadow-enabled companion (`shd.enabled on`, the default) wraps outgoing
  `REQ`, `TXT_MSG`, `GRP_TXT` and other non-exempt packets. A Sensor, Room
  Server or Secure Chat node cannot unwrap them, so normal requests and
  messages do not reach it even over a direct link. `ANON_REQ` is not wrapped,
  so a direct login may complete, but the following `REQ` or `TXT_MSG` is
  wrapped and the session is unusable. To use a legacy endpoint, set
  `shd.enabled off` on the companion and keep any `shd.enforce on` repeater
  off the path.
- A network that combines `shd.enforce on` repeaters with shadow-enabled
  companions therefore effectively isolates Sensor, Room Server and Secure
  Chat nodes. They can still forward shadow envelopes if repeating is
  enabled, but cannot originate or consume them.
- A shadow-enabled repeater with `shd.enforce off` answers legacy clients for
  status, telemetry and CLI commands, because replies mirror the plain
  request. Login replies stay wrapped, so a client without shadow support
  cannot log in to a shadow-enabled repeater; add it to the repeater ACL with
  `setperm` instead.
- Scoped flood support is implemented: the outer transport code is computed
  after the shadow signature, over the final wire packet, so it matches the
  standard `TransportKey::calcTransportCode()` used by legacy region-aware
  repeaters. Native tests cover the transport-code derivation and
  `RegionMap::findMatch()`; real-device/runtime validation of scoped floods is
  still pending. Transport codes are not part of the shadow signature; like
  the path, they are routing metadata.
- A companion with repeating enabled processes a received flood packet for
  itself and forwards the original shadow envelope, so downstream enforcing
  repeaters still receive the signed packet. For fragments, every original
  fragment is forwarded unchanged; the reassembled payload is delivered
  locally as a local-only packet and is never retransmitted as ordinary
  traffic.
- The path is not authenticated. An attacker can alter the route, but not the
  source identity or inner payload.
- Anybody who knows `shadow_ch`/`magic` can recognize the channel. The fixed
  marker is a v1 trade-off; a future revision can derive it from a network ID.
- Replay protection is dedup (`VerifiedHashCache`), TTLs and the inner
  message timestamp. There is no timestamp/expiry field in the signature
  packet.
- A repeater that has `shd.enabled` off behaves exactly like an old repeater.
- Old nodes (including the Sensor, Room Server and Secure Chat firmware) do
  not see wrapped adverts; keep `shd.enabled off` during a mixed rollout if
  old-node discovery is required.
- The shadow envelope has not had a public release yet. Development builds made
  before the final format change are not wire-compatible and must be reflashed
  together; there is no mixed-shadow-version support.
- Validation status: native unit tests and firmware builds pass. On-device
  runtime validation of scoped floods, multi-hop forwarding, airtime and
  long-run stability is still pending.
- Rollback is `shd.enforce off`: the repeater verifies and counts but forwards
  everything.

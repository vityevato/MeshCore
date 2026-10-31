#pragma once

#include <Mesh.h>
#include <helpers/ShadowPackets.h>

#ifndef SHADOW_MAX_FRAGMENTS
  #define SHADOW_MAX_FRAGMENTS 16   // one message is at most 184 bytes -> 2 fragments
#endif

/**
 * Node/companion side of the shadow transit auth layer.
 *
 * Sender: wraps ordinary outgoing packets into GRP_TXT shadow envelopes
 *         (embedded / detached / fragment).
 * Receiver: unwraps them and hands the original payload back to Mesh.
 *
 * Repeaters also use the sender half for locally generated responses/ACKs,
 * but must NOT unwrap transit packets: setUnwrapAll(false) makes the receiver
 * half unwrap only traffic addressed to this node.
 */
class ShadowNode : public mesh::ShadowSendHook, public mesh::ShadowRecvHook {
  struct FragEntry {
    bool     used;
    uint8_t  tag[SHADOW_TAG_SIZE];
    uint8_t  frag_id[SHADOW_SIG_ID_SIZE];
    uint8_t  inner_type;
    uint8_t  count;
    uint16_t mask;
    uint16_t payload_len;
    uint8_t  last_len;
    unsigned long last_ms;
    unsigned long expiry_ms;
    uint8_t  payload[MAX_PACKET_PAYLOAD];
  };

  mesh::LocalIdentity& _self;
  mesh::RNG& _rng;
  bool _enabled;
  uint8_t _mode;             // SHADOW_MODE_AUTO or a forced mode
  bool _unwrap_all;          // true on a normal node, false on a repeater
  bool _forward_envelopes;   // repeater-capable endpoint: forward original envelopes
  uint32_t _sig_id;
  uint32_t _frag_id;
  unsigned long _frag_ttl_ms;
  uint8_t _scope_key[16];
  bool _scope_valid;
  FragEntry _frags[SHADOW_FRAG_MAX];

  // Saved outer envelope for prepareForward(). Only the wire fields are kept;
  // the packet's path/path_len stay as updated by Mesh::routeRecvPacket().
  bool     _saved_valid;
  uint8_t  _saved_header;
  uint16_t _saved_payload_len;
  uint16_t _saved_transport_codes[2];
  uint8_t  _saved_flags;
  bool     _saved_auth_ok;
  uint8_t  _saved_payload[MAX_PACKET_PAYLOAD];

  uint32_t _sent, _recv, _frags_recv, _dropped;

  bool drop(const char* reason, const mesh::Packet* packet, const uint8_t* tag = NULL);
  bool shouldWrap(const mesh::Packet* packet) const;
  void nextSigId(uint8_t* dest);
  void nextFragId(uint8_t* dest);
  void prepareOuter(mesh::Packet* out, const mesh::Packet* inner, uint8_t mode);
  void sendShadow(mesh::Mesh& mesh, mesh::Packet* out, uint8_t priority, uint32_t delay_millis);
  uint16_t calcOuterCode(const mesh::Packet* out) const;
  bool wrapEmbedded(mesh::Mesh& mesh, mesh::Packet* packet, uint8_t priority, uint32_t delay_millis);
  bool wrapDetached(mesh::Mesh& mesh, mesh::Packet* packet, uint8_t priority, uint32_t delay_millis);
  bool wrapFragment(mesh::Mesh& mesh, mesh::Packet* packet, uint8_t priority, uint32_t delay_millis);

  int findFrag(const uint8_t* tag, const uint8_t* frag_id);
  int allocFrag(unsigned long now_ms);
  void saveEnvelope(const mesh::Packet* packet);
  bool unwrapLocal(mesh::Packet* packet, uint8_t inner_type, const uint8_t* inner, uint16_t inner_len);
  bool processFragment(mesh::Mesh& mesh, mesh::Packet* packet, const uint8_t* tag,
                       uint8_t inner_type, const uint8_t* frag_payload, uint16_t frag_len,
                       unsigned long now_ms);

public:
  ShadowNode(mesh::LocalIdentity& self, mesh::RNG& rng);

  void setEnabled(bool en) { _enabled = en; }
  bool enabled() const { return _enabled; }
  void setMode(uint8_t mode);
  uint8_t mode() const { return _mode; }
  void setUnwrapAll(bool all) { _unwrap_all = all; }
  void setForwardEnvelopes(bool en) { _forward_envelopes = en; }
  void setFragTtl(unsigned long ms) { _frag_ttl_ms = ms; }

  /**
   * Set the transport key for the next sendFlood() call, so shadow envelopes
   * get a valid region code computed over the OUTER payload. Pass NULL to
   * clear. sendFloodScoped() wrappers call this around the send.
   */
  void setTransportKey(const uint8_t* key);

  void poll(unsigned long now_ms);

  bool wrapAndSend(mesh::Mesh& mesh, mesh::Packet* packet, uint8_t priority,
                   uint32_t delay_millis) override;
  bool unwrapAndProcess(mesh::Mesh& mesh, mesh::Packet* packet) override;
  void prepareForward(mesh::Packet* packet) override;

  void formatStatus(char* reply, size_t reply_len) const;
  bool handleCommand(const char* command, char* reply, size_t reply_len);
};

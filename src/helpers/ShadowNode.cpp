#include "ShadowNode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <SHA256.h>

namespace {

/**
 * Payload types that can be a locally generated reply to a received packet.
 * Replies mirror the envelope of their triggering request: a legacy or
 * shadow-off peer sent a plain request and cannot unwrap a shadow reply.
 * MULTIPART is gated only for ACK sequences; an app-initiated multipart
 * message is not a reply.
 */
bool isReplyPayload(const mesh::Packet* packet) {
  switch (packet->getPayloadType()) {
    case PAYLOAD_TYPE_RESPONSE:
    case PAYLOAD_TYPE_ACK:
    case PAYLOAD_TYPE_PATH:
    case PAYLOAD_TYPE_TXT_MSG:
      return true;
    case PAYLOAD_TYPE_MULTIPART:
      return packet->payload_len > 0
          && (packet->payload[0] & 0x0F) == PAYLOAD_TYPE_ACK;
    default:
      return false;
  }
}

} // namespace

ShadowNode::ShadowNode(mesh::LocalIdentity& self, mesh::RNG& rng)
  : _self(self), _rng(rng), _tx_enabled(true), _rx_enabled(true), _mode(SHADOW_MODE_AUTO),
    _unwrap_all(true), _forward_envelopes(false), _sig_id(0), _frag_id(0),
    _frag_ttl_ms(SHADOW_FRAG_TTL_DEFAULT_MS),
    _scope_valid(false), _saved_valid(false), _saved_header(0), _saved_payload_len(0),
    _saved_flags(0), _saved_auth_ok(false),
    _sent(0), _recv(0), _frags_recv(0), _dropped(0) {
  memset(_scope_key, 0, sizeof(_scope_key));
  memset(_frags, 0, sizeof(_frags));
  memset(_saved_transport_codes, 0, sizeof(_saved_transport_codes));
  memset(_saved_payload, 0, sizeof(_saved_payload));
  _rng.random((uint8_t*)&_sig_id, sizeof(_sig_id));
  _rng.random((uint8_t*)&_frag_id, sizeof(_frag_id));
}

bool ShadowNode::drop(const char* reason, const mesh::Packet* packet, const uint8_t* tag) {
  _dropped++;
  char tag_buf[2 * SHADOW_TAG_SIZE + 1];
  if (tag != NULL) {
    mesh::Utils::toHex(tag_buf, tag, SHADOW_TAG_SIZE);
  } else {
    snprintf(tag_buf, sizeof(tag_buf), "---");
  }
  MESH_DEBUG_PRINTLN("SHADOW RX DROP reason=%s type=%d route=%c len=%d tag=%s",
                     reason, packet->getPayloadType(), packet->isRouteDirect() ? 'D' : 'F',
                     packet->payload_len, tag_buf);
  return true;
}

void ShadowNode::setMode(uint8_t mode) {
  if (mode > SHADOW_MODE_FRAGMENT || mode == SHADOW_MODE_SIGNATURE) mode = SHADOW_MODE_AUTO;
  if (mode != _mode) {
    SHADOW_TRACE_PRINTLN("SHADOW: mode %s -> %s", shadow::modeName(_mode), shadow::modeName(mode));
    _mode = mode;
  }
}

void ShadowNode::setTransportKey(const uint8_t* key) {
  bool was_valid = _scope_valid;
  if (key == NULL) {
    _scope_valid = false;
    memset(_scope_key, 0, sizeof(_scope_key));
  } else {
    memcpy(_scope_key, key, sizeof(_scope_key));
    _scope_valid = true;
    for (int i = 0; i < (int)sizeof(_scope_key); i++) {
      if (_scope_key[i] != 0) break;
      if (i == (int)sizeof(_scope_key) - 1) _scope_valid = false;   // all-zero key means unscoped
    }
  }
  if (was_valid != _scope_valid) {
    MESH_DEBUG_PRINTLN("SHADOW: transport scope %s", _scope_valid ? "set" : "cleared");
  }
}

uint16_t ShadowNode::calcOuterCode(const mesh::Packet* out) const {
  uint16_t code = 0;
  SHA256 sha;
  sha.resetHMAC(_scope_key, sizeof(_scope_key));
  uint8_t type = out->getPayloadType();
  sha.update(&type, 1);
  sha.update(out->payload, out->payload_len);
  sha.finalizeHMAC(_scope_key, sizeof(_scope_key), (uint8_t*)&code, 2);
  if (code == 0) code = 1;
  else if (code == 0xFFFF) code = 0xFFFE;
  SHADOW_TRACE_PRINTLN("SHADOW TX transport code=%04X type=%d len=%d",
                       (unsigned)code, out->getPayloadType(), out->payload_len);
  return code;
}

void ShadowNode::nextSigId(uint8_t* dest) {
  if (++_sig_id == 0) _sig_id = 1;
  memcpy(dest, &_sig_id, SHADOW_SIG_ID_SIZE);
}

void ShadowNode::nextFragId(uint8_t* dest) {
  if (++_frag_id == 0) _frag_id = 1;
  memcpy(dest, &_frag_id, SHADOW_SIG_ID_SIZE);
}

bool ShadowNode::shouldWrap(const mesh::Packet* packet) const {
  if (packet->shadow_wrapped) return false;
  uint8_t type = packet->getPayloadType();
  // These are the login exception (ANON_REQ) or have local zero-hop
  // semantics (CONTROL / TRACE). ADVERT is wrapped: the inner advert keeps
  // its own Ed25519 signature and is verified by Mesh after unwrapping.
  if (type == PAYLOAD_TYPE_ANON_REQ
      || type == PAYLOAD_TYPE_CONTROL || type == PAYLOAD_TYPE_TRACE) {
    return false;
  }
  return packet->payload_len <= MAX_PACKET_PAYLOAD;
}

void ShadowNode::prepareOuter(mesh::Packet* out, const mesh::Packet* inner, uint8_t mode) {
  out->header = (uint8_t)((PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT) | (inner->header & PH_ROUTE_MASK));
  out->path_len = inner->path_len;
  memcpy(out->path, inner->path, inner->getPathByteLen());
  out->transport_codes[0] = inner->transport_codes[0];
  out->transport_codes[1] = inner->transport_codes[1];
  out->shadow = true;
  out->shadow_wrapped = true;
  out->auth_ok = true;
  out->shadow_flags = shadow::makeFlags(mode);
}

void ShadowNode::sendShadow(mesh::Mesh& mesh, mesh::Packet* out, uint8_t priority, uint32_t delay_millis) {
  SHADOW_TRACE_PRINTLN("SHADOW TX send mode=%s len=%d priority=%d delay=%lu tag=%02X%02X%02X",
                       shadow::modeName(shadow::modeOf(out->shadow_flags)),
                       out->payload_len, (int)priority, (unsigned long)delay_millis,
                       out->payload[SHADOW_CH_SIZE + SHADOW_MAGIC_SIZE],
                       out->payload[SHADOW_CH_SIZE + SHADOW_MAGIC_SIZE + 1],
                       out->payload[SHADOW_CH_SIZE + SHADOW_MAGIC_SIZE + 2]);
  mesh.packetTables()->markSeen(out);   // ignore our own transmission if it loops back
  mesh.sendPacketRaw(out, priority, delay_millis);
  _sent++;
}

bool ShadowNode::wrapEmbedded(mesh::Mesh& mesh, mesh::Packet* packet,
                              uint8_t priority, uint32_t delay_millis) {
  uint16_t inner_len = packet->payload_len;
  if (inner_len > SHADOW_MAX_INNER_EMBEDDED) {
    MESH_DEBUG_PRINTLN("SHADOW TX FAIL reason=embedded-oversize len=%u max=%u",
                       (unsigned)inner_len, (unsigned)SHADOW_MAX_INNER_EMBEDDED);
    return false;
  }

  mesh::Packet* out = mesh.obtainNewPacket();
  if (out == NULL) {
    MESH_DEBUG_PRINTLN("SHADOW TX FAIL reason=alloc-fail mode=EMB len=%u", (unsigned)inner_len);
    return false;
  }

  prepareOuter(out, packet, SHADOW_MODE_EMBEDDED);
  uint8_t tag[SHADOW_TAG_SIZE];
  shadow::tagOf(_self.pub_key, tag);
  shadow::writeCommon(out->payload, tag, SHADOW_MODE_EMBEDDED);

  uint16_t n = SHADOW_COMMON_SIZE;
  out->payload[n++] = packet->getPayloadType();
  memcpy(&out->payload[n], packet->payload, inner_len); n += inner_len;
  uint8_t* signature = &out->payload[n];
  out->payload_len = n + SIGNATURE_SIZE;

  uint8_t digest[SHADOW_DIGEST_SIZE];
  if (!shadow::digestEmbedded(digest, out->header, shadow::pathModeOf(out),
                              out->payload, out->payload_len)) {
    MESH_DEBUG_PRINTLN("SHADOW TX FAIL reason=digest mode=EMB len=%u", (unsigned)out->payload_len);
    mesh.releasePacket(out);
    return false;
  }
  _self.sign(signature, digest, SHADOW_DIGEST_SIZE);

  // Must be computed over the final packet, including the signature: legacy
  // region-aware repeaters calculate the same code from the wire payload.
  if (_scope_valid && packet->hasTransportCodes()) {
    out->transport_codes[0] = calcOuterCode(out);
  }
  SHADOW_TRACE_PRINTLN("SHADOW TX embedded tag=%02X%02X%02X inner_type=%d inner_len=%u wire_len=%u",
                       tag[0], tag[1], tag[2], packet->getPayloadType(),
                       (unsigned)inner_len, (unsigned)out->payload_len);
  sendShadow(mesh, out, priority, delay_millis);
  return true;
}

bool ShadowNode::wrapDetached(mesh::Mesh& mesh, mesh::Packet* packet,
                              uint8_t priority, uint32_t delay_millis) {
  uint16_t inner_len = packet->payload_len;
  if (inner_len > SHADOW_MAX_INNER_MSG) {
    MESH_DEBUG_PRINTLN("SHADOW TX FAIL reason=message-oversize len=%u max=%u",
                       (unsigned)inner_len, (unsigned)SHADOW_MAX_INNER_MSG);
    return false;
  }

  mesh::Packet* msg = mesh.obtainNewPacket();
  if (msg == NULL) {
    MESH_DEBUG_PRINTLN("SHADOW TX FAIL reason=alloc-fail mode=MSG stage=msg");
    return false;
  }
  mesh::Packet* sig = mesh.obtainNewPacket();
  if (sig == NULL) {
    MESH_DEBUG_PRINTLN("SHADOW TX FAIL reason=alloc-fail mode=MSG stage=sig");
    mesh.releasePacket(msg);
    return false;
  }

  uint8_t tag[SHADOW_TAG_SIZE];
  shadow::tagOf(_self.pub_key, tag);
  uint8_t sig_id[SHADOW_SIG_ID_SIZE];
  nextSigId(sig_id);

  // Message packet (unsigned).
  prepareOuter(msg, packet, SHADOW_MODE_MESSAGE);
  shadow::writeCommon(msg->payload, tag, SHADOW_MODE_MESSAGE);
  memcpy(&msg->payload[SHADOW_COMMON_SIZE], sig_id, SHADOW_SIG_ID_SIZE);
  uint16_t n = SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE;
  msg->payload[n++] = packet->getPayloadType();
  memcpy(&msg->payload[n], packet->payload, inner_len); n += inner_len;
  msg->payload_len = n;

  if (_scope_valid && packet->hasTransportCodes()) {
    msg->transport_codes[0] = calcOuterCode(msg);
  }
  uint8_t msg_digest[SHADOW_DIGEST_SIZE];
  if (!shadow::digestMessage(msg_digest, msg->header, shadow::pathModeOf(msg),
                             msg->payload, msg->payload_len)) {
    MESH_DEBUG_PRINTLN("SHADOW TX FAIL reason=digest mode=MSG len=%u", (unsigned)msg->payload_len);
    mesh.releasePacket(msg);
    mesh.releasePacket(sig);
    return false;
  }

  // Signature packet.
  prepareOuter(sig, packet, SHADOW_MODE_SIGNATURE);
  shadow::writeCommon(sig->payload, tag, SHADOW_MODE_SIGNATURE);
  memcpy(&sig->payload[SHADOW_COMMON_SIZE], sig_id, SHADOW_SIG_ID_SIZE);
  memcpy(&sig->payload[SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE],
         msg_digest, SHADOW_MSG_HASH_SIZE);
  sig->payload_len = SHADOW_SIG_PACKET_SIZE;
  uint8_t* signature = &sig->payload[SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE + SHADOW_MSG_HASH_SIZE];

  uint8_t sig_digest[SHADOW_DIGEST_SIZE];
  if (!shadow::digestSignature(sig_digest, sig->header, shadow::pathModeOf(sig),
                               sig->payload, sig->payload_len)) {
    MESH_DEBUG_PRINTLN("SHADOW TX FAIL reason=digest mode=SIG len=%u", (unsigned)sig->payload_len);
    mesh.releasePacket(msg);
    mesh.releasePacket(sig);
    return false;
  }
  _self.sign(signature, sig_digest, SHADOW_DIGEST_SIZE);

  // Outer transport code must match the final wire packet (see wrapEmbedded).
  if (_scope_valid && packet->hasTransportCodes()) {
    sig->transport_codes[0] = calcOuterCode(sig);
  }

  SHADOW_TRACE_PRINTLN("SHADOW TX detached tag=%02X%02X%02X id=%02X%02X%02X%02X inner_type=%d inner_len=%u hash=%02X%02X%02X%02X",
                       tag[0], tag[1], tag[2],
                       sig_id[0], sig_id[1], sig_id[2], sig_id[3],
                       packet->getPayloadType(), (unsigned)inner_len,
                       msg_digest[0], msg_digest[1], msg_digest[2], msg_digest[3]);
  sendShadow(mesh, sig, priority, delay_millis);
  sendShadow(mesh, msg, priority, delay_millis + SHADOW_SIG_MSG_DELAY_MS);
  return true;
}

bool ShadowNode::wrapFragment(mesh::Mesh& mesh, mesh::Packet* packet,
                              uint8_t priority, uint32_t delay_millis) {
  uint16_t inner_len = packet->payload_len;
  uint8_t count = (uint8_t)((inner_len + SHADOW_MAX_FRAG_PAYLOAD - 1) / SHADOW_MAX_FRAG_PAYLOAD);
  if (count == 0) count = 1;
  if (count > SHADOW_MAX_FRAGMENTS) {
    MESH_DEBUG_PRINTLN("SHADOW TX FAIL reason=frag-count len=%u count=%u max=%u",
                       (unsigned)inner_len, (unsigned)count, (unsigned)SHADOW_MAX_FRAGMENTS);
    return false;
  }

  uint8_t tag[SHADOW_TAG_SIZE];
  shadow::tagOf(_self.pub_key, tag);
  uint8_t frag_id[SHADOW_SIG_ID_SIZE];
  nextFragId(frag_id);

  for (uint8_t i = 0; i < count; i++) {
    uint16_t offset = (uint16_t)i * SHADOW_MAX_FRAG_PAYLOAD;
    uint16_t chunk = inner_len - offset;
    if (chunk > SHADOW_MAX_FRAG_PAYLOAD) chunk = SHADOW_MAX_FRAG_PAYLOAD;

    mesh::Packet* out = mesh.obtainNewPacket();
    if (out == NULL) {
      MESH_DEBUG_PRINTLN("SHADOW TX FAIL reason=alloc-fail mode=FRAG sent=%u/%u",
                         (unsigned)i, (unsigned)count);
      return false;   // receiver will time out the partial set
    }

    prepareOuter(out, packet, SHADOW_MODE_FRAGMENT);
    shadow::writeCommon(out->payload, tag, SHADOW_MODE_FRAGMENT);
    memcpy(&out->payload[SHADOW_COMMON_SIZE], frag_id, SHADOW_SIG_ID_SIZE);
    uint16_t n = SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE;
    out->payload[n++] = i;
    out->payload[n++] = count;
    out->payload[n++] = packet->getPayloadType();
    memcpy(&out->payload[n], &packet->payload[offset], chunk); n += chunk;
    uint8_t* signature = &out->payload[n];
    out->payload_len = n + SIGNATURE_SIZE;

    uint8_t digest[SHADOW_DIGEST_SIZE];
    if (!shadow::digestFragment(digest, out->header, shadow::pathModeOf(out),
                                out->payload, out->payload_len)) {
      MESH_DEBUG_PRINTLN("SHADOW TX FAIL reason=digest mode=FRAG frag=%u/%u",
                         (unsigned)i, (unsigned)count);
      mesh.releasePacket(out);
      return false;
    }
    _self.sign(signature, digest, SHADOW_DIGEST_SIZE);

    if (_scope_valid && packet->hasTransportCodes()) {
      out->transport_codes[0] = calcOuterCode(out);
    }
    SHADOW_TRACE_PRINTLN("SHADOW TX fragment tag=%02X%02X%02X id=%02X%02X%02X%02X frag=%u/%u inner_type=%d chunk=%u wire_len=%u",
                         tag[0], tag[1], tag[2],
                         frag_id[0], frag_id[1], frag_id[2], frag_id[3],
                         (unsigned)i, (unsigned)count, packet->getPayloadType(),
                         (unsigned)chunk, (unsigned)out->payload_len);
    sendShadow(mesh, out, priority, delay_millis + (uint32_t)i * SHADOW_FRAG_GAP_MS);
  }
  return true;
}

bool ShadowNode::wrapAndSend(mesh::Mesh& mesh, mesh::Packet* packet,
                             uint8_t priority, uint32_t delay_millis) {
  if (!_tx_enabled) {
    SHADOW_TRACE_PRINTLN("SHADOW TX SKIP reason=disabled type=%d len=%d",
                         packet->getPayloadType(), packet->payload_len);
    return false;
  }
  if (!shouldWrap(packet)) {
    SHADOW_TRACE_PRINTLN("SHADOW TX SKIP reason=not-wrappable type=%d len=%d",
                         packet->getPayloadType(), packet->payload_len);
    return false;
  }

  // A locally generated reply mirrors the transport envelope of the request
  // that triggered it. A plain request comes from a legacy or shadow-off peer
  // that cannot unwrap a shadow reply. ANON_REQ login is the exception: its
  // reply stays wrapped so it can traverse enforcing repeaters.
  if (isReplyPayload(packet) && mesh.recvDispatchActive()
      && mesh.recvDispatchType() != PAYLOAD_TYPE_ANON_REQ
      && !mesh.recvDispatchWasShadow()) {
    SHADOW_TRACE_PRINTLN("SHADOW TX SKIP reason=reply-to-plain type=%d recv_type=%d",
                         packet->getPayloadType(), mesh.recvDispatchType());
    return false;
  }

  uint16_t inner_len = packet->payload_len;
  uint8_t mode;

  // Adverts are self-authenticating (their own Ed25519 signature lives in the
  // inner payload). Never fragment them: embedded or detached only, so any
  // repeater can apply shd.allow.advert without reassembly.
  if (packet->getPayloadType() == PAYLOAD_TYPE_ADVERT) {
    mode = (inner_len <= SHADOW_MAX_INNER_EMBEDDED) ? SHADOW_MODE_EMBEDDED
                                                    : SHADOW_MODE_MESSAGE;
  } else if (_mode == SHADOW_MODE_EMBEDDED && inner_len <= SHADOW_MAX_INNER_EMBEDDED) {
    mode = SHADOW_MODE_EMBEDDED;
  } else if (_mode == SHADOW_MODE_MESSAGE && inner_len <= SHADOW_MAX_INNER_MSG) {
    mode = SHADOW_MODE_MESSAGE;
  } else if (_mode == SHADOW_MODE_FRAGMENT) {
    mode = SHADOW_MODE_FRAGMENT;
  } else if (inner_len <= SHADOW_MAX_INNER_EMBEDDED) {
    mode = SHADOW_MODE_EMBEDDED;
  } else if (inner_len <= SHADOW_MAX_INNER_MSG) {
    mode = SHADOW_MODE_MESSAGE;
  } else {
    mode = SHADOW_MODE_FRAGMENT;
  }

  SHADOW_TRACE_PRINTLN("SHADOW TX wrap type=%d inner_len=%u mode=%s",
                       packet->getPayloadType(), (unsigned)inner_len,
                       shadow::modeName(mode));

  bool ok;
  if (mode == SHADOW_MODE_EMBEDDED) {
    ok = wrapEmbedded(mesh, packet, priority, delay_millis);
  } else if (mode == SHADOW_MODE_MESSAGE) {
    ok = wrapDetached(mesh, packet, priority, delay_millis);
  } else {
    ok = wrapFragment(mesh, packet, priority, delay_millis);
  }

  if (!ok) {
    _dropped++;
    MESH_DEBUG_PRINTLN("SHADOW TX DROP reason=wrap-fail type=%d len=%u mode=%s",
                       packet->getPayloadType(), (unsigned)inner_len,
                       shadow::modeName(mode));
  }
  mesh.releasePacket(packet);   // original is never transmitted
  return true;                  // consumed either way (fail-closed)
}

void ShadowNode::saveEnvelope(const mesh::Packet* packet) {
  _saved_header = packet->header;
  _saved_payload_len = packet->payload_len;
  memcpy(_saved_payload, packet->payload, packet->payload_len);
  _saved_transport_codes[0] = packet->transport_codes[0];
  _saved_transport_codes[1] = packet->transport_codes[1];
  _saved_flags = packet->shadow_flags;
  _saved_auth_ok = packet->auth_ok;
  _saved_valid = true;
  SHADOW_TRACE_PRINTLN("SHADOW RX saved envelope mode=%s len=%u",
                       shadow::modeName(shadow::modeOf(_saved_flags)),
                       (unsigned)_saved_payload_len);
}

void ShadowNode::prepareForward(mesh::Packet* packet) {
  if (!_saved_valid) {
    MESH_DEBUG_PRINTLN("SHADOW: prepareForward without saved envelope type=%d len=%d",
                       packet->getPayloadType(), packet->payload_len);
    return;
  }

  // Restore only the wire fields of the envelope. packet->path/path_len keep
  // the value Mesh::routeRecvPacket() produced for the retransmission; the
  // shadow signature does not cover path bytes.
  packet->header = _saved_header;
  packet->payload_len = _saved_payload_len;
  memcpy(packet->payload, _saved_payload, _saved_payload_len);
  packet->transport_codes[0] = _saved_transport_codes[0];
  packet->transport_codes[1] = _saved_transport_codes[1];
  packet->shadow = true;
  packet->shadow_wrapped = true;
  packet->shadow_flags = _saved_flags;
  packet->auth_ok = _saved_auth_ok;
  packet->shadow_unwrapped = false;
  _saved_valid = false;
}

bool ShadowNode::unwrapLocal(mesh::Packet* packet, uint8_t inner_type,
                             const uint8_t* inner, uint16_t inner_len) {
  if (inner_len > MAX_PACKET_PAYLOAD) {
    MESH_DEBUG_PRINTLN("SHADOW RX DROP reason=unwrap-oversize type=%d len=%u max=%u",
                       inner_type, (unsigned)inner_len, (unsigned)MAX_PACKET_PAYLOAD);
    return false;
  }
  uint8_t mode = shadow::modeOf(packet->shadow_flags);
  memmove(packet->payload, inner, inner_len);
  packet->payload_len = inner_len;
  packet->header = (uint8_t)((inner_type << PH_TYPE_SHIFT) | (packet->header & PH_ROUTE_MASK));
  packet->shadow = false;
  packet->shadow_wrapped = false;
  packet->auth_ok = false;
  packet->shadow_flags = 0;
  packet->shadow_unwrapped = true;
  _recv++;
  MESH_DEBUG_PRINTLN("SHADOW RX UNWRAP OK mode=%s type=%d len=%u",
                     shadow::modeName(mode), inner_type, (unsigned)inner_len);
  return false;
}

int ShadowNode::findFrag(const uint8_t* tag, const uint8_t* frag_id) {
  for (int i = 0; i < SHADOW_FRAG_MAX; i++) {
    FragEntry& e = _frags[i];
    if (e.used && memcmp(e.tag, tag, SHADOW_TAG_SIZE) == 0
        && memcmp(e.frag_id, frag_id, SHADOW_SIG_ID_SIZE) == 0) {
      return i;
    }
  }
  return -1;
}

int ShadowNode::allocFrag(unsigned long now_ms) {
  for (int i = 0; i < SHADOW_FRAG_MAX; i++) {
    if (!_frags[i].used) return i;
  }
  int oldest = 0;
  for (int i = 1; i < SHADOW_FRAG_MAX; i++) {
    if ((long)(_frags[i].last_ms - _frags[oldest].last_ms) < 0) oldest = i;
  }
  FragEntry& old = _frags[oldest];
  MESH_DEBUG_PRINTLN("SHADOW RX EVICT frag tag=%02X%02X%02X id=%02X%02X%02X%02X age=%lu mask=%04X",
                     old.tag[0], old.tag[1], old.tag[2],
                     old.frag_id[0], old.frag_id[1], old.frag_id[2], old.frag_id[3],
                     (unsigned long)(now_ms - old.last_ms), (unsigned)old.mask);
  memset(&old, 0, sizeof(old));
  return oldest;
}

bool ShadowNode::processFragment(mesh::Mesh& mesh, mesh::Packet* packet, const uint8_t* tag,
                                 uint8_t inner_type, const uint8_t* frag_payload, uint16_t frag_len,
                                 unsigned long now_ms) {
  (void)mesh;
  uint8_t frag_id_buf[SHADOW_SIG_ID_SIZE];
  memcpy(frag_id_buf, &packet->payload[SHADOW_COMMON_SIZE], SHADOW_SIG_ID_SIZE);
  const uint8_t* frag_id = frag_id_buf;
  uint8_t index = packet->payload[SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE];
  uint8_t count = packet->payload[SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE + 1];

  if (count == 0 || count > SHADOW_MAX_FRAGMENTS || index >= count) {
    SHADOW_TRACE_PRINTLN("SHADOW: frag bad index id=%02X%02X%02X%02X index=%u count=%u",
                         frag_id[0], frag_id[1], frag_id[2], frag_id[3],
                         (unsigned)index, (unsigned)count);
    return drop("frag-bad-index", packet, tag);
  }
  if (frag_len > SHADOW_MAX_FRAG_PAYLOAD) {
    SHADOW_TRACE_PRINTLN("SHADOW: frag oversize id=%02X%02X%02X%02X len=%u max=%u",
                         frag_id[0], frag_id[1], frag_id[2], frag_id[3],
                         (unsigned)frag_len, (unsigned)SHADOW_MAX_FRAG_PAYLOAD);
    return drop("frag-oversize", packet, tag);
  }
  if (index < count - 1 && frag_len != SHADOW_MAX_FRAG_PAYLOAD) {
    SHADOW_TRACE_PRINTLN("SHADOW: frag bad len id=%02X%02X%02X%02X index=%u/%u len=%u",
                         frag_id[0], frag_id[1], frag_id[2], frag_id[3],
                         (unsigned)index, (unsigned)count, (unsigned)frag_len);
    return drop("frag-bad-len", packet, tag);
  }

  int slot = findFrag(tag, frag_id);
  if (slot < 0) {
    slot = allocFrag(now_ms);
    FragEntry& e = _frags[slot];
    memset(&e, 0, sizeof(e));
    e.used = true;
    memcpy(e.tag, tag, SHADOW_TAG_SIZE);
    memcpy(e.frag_id, frag_id, SHADOW_SIG_ID_SIZE);
    e.inner_type = inner_type;
    e.count = count;
    e.last_ms = now_ms;
    e.expiry_ms = now_ms + _frag_ttl_ms;
    MESH_DEBUG_PRINTLN("SHADOW RX FRAG start tag=%02X%02X%02X id=%02X%02X%02X%02X type=%d count=%u slot=%d ttl=%lu",
                       tag[0], tag[1], tag[2],
                       frag_id[0], frag_id[1], frag_id[2], frag_id[3],
                       inner_type, (unsigned)count, slot, (unsigned long)_frag_ttl_ms);
  }

  FragEntry& e = _frags[slot];
  if (e.inner_type != inner_type || e.count != count) {
    SHADOW_TRACE_PRINTLN("SHADOW: frag mismatch id=%02X%02X%02X%02X type=%d/%d count=%u/%u",
                         frag_id[0], frag_id[1], frag_id[2], frag_id[3],
                         inner_type, e.inner_type, (unsigned)count, (unsigned)e.count);
    e.used = false;
    return drop("frag-mismatch", packet, tag);
  }
  uint16_t bit = (uint16_t)1 << index;
  if (e.mask & bit) {
    SHADOW_TRACE_PRINTLN("SHADOW: frag duplicate id=%02X%02X%02X%02X index=%u/%u mask=%04X",
                         frag_id[0], frag_id[1], frag_id[2], frag_id[3],
                         (unsigned)index, (unsigned)count, (unsigned)e.mask);
    return true;   // duplicate fragment
  }

  uint16_t offset = (uint16_t)index * SHADOW_MAX_FRAG_PAYLOAD;
  if (offset + frag_len > MAX_PACKET_PAYLOAD) {
    SHADOW_TRACE_PRINTLN("SHADOW: frag overflow id=%02X%02X%02X%02X index=%u offset=%u len=%u",
                         frag_id[0], frag_id[1], frag_id[2], frag_id[3],
                         (unsigned)index, (unsigned)offset, (unsigned)frag_len);
    e.used = false;
    return drop("frag-overflow", packet, tag);
  }
  memcpy(&e.payload[offset], frag_payload, frag_len);
  e.mask |= bit;
  if (index == count - 1) e.last_len = (uint8_t)frag_len;

  unsigned long prev_last = e.last_ms;
  e.last_ms = now_ms;
  e.expiry_ms = now_ms + _frag_ttl_ms;

  uint16_t complete_mask = (uint16_t)(((uint32_t)1 << count) - 1);
  if (e.mask == complete_mask) {
    uint16_t total = (uint16_t)(count - 1) * SHADOW_MAX_FRAG_PAYLOAD + e.last_len;
    if (total > MAX_PACKET_PAYLOAD) {
      SHADOW_TRACE_PRINTLN("SHADOW: frag total overflow id=%02X%02X%02X%02X total=%u",
                           frag_id[0], frag_id[1], frag_id[2], frag_id[3], (unsigned)total);
      e.used = false;
      return drop("frag-total", packet, tag);
    }
    memcpy(packet->payload, e.payload, total);
    packet->payload_len = total;
    packet->header = (uint8_t)((inner_type << PH_TYPE_SHIFT) | (packet->header & PH_ROUTE_MASK));
    packet->shadow = false;
    packet->shadow_wrapped = false;
    packet->auth_ok = false;
    packet->shadow_flags = 0;
    packet->shadow_unwrapped = true;
    e.used = false;
    _frags_recv++;
    _recv++;
    MESH_DEBUG_PRINTLN("SHADOW RX FRAG complete tag=%02X%02X%02X id=%02X%02X%02X%02X type=%d total=%u gap=%lu",
                       tag[0], tag[1], tag[2],
                       frag_id[0], frag_id[1], frag_id[2], frag_id[3],
                       inner_type, (unsigned)total, (unsigned long)(now_ms - prev_last));
    return false;
  }
  return true;
}

bool ShadowNode::unwrapAndProcess(mesh::Mesh& mesh, mesh::Packet* packet) {
  _saved_valid = false;   // only valid for the packet currently being processed
  if (!_rx_enabled) return false;
  if (!shadow::hasShadowMarker(packet)) return false;

  uint8_t tag[SHADOW_TAG_SIZE];
  uint8_t flags = 0;
  if (!shadow::parseHeader(packet, tag, &flags)) {
    // Correct marker but an unsupported future version. A repeater must
    // forward it unchanged; an endpoint has nothing to do with it.
    if (!_unwrap_all) {
      SHADOW_TRACE_PRINTLN("SHADOW RX FORWARD reason=bad-version type=%d route=%c len=%d",
                           packet->getPayloadType(), packet->isRouteDirect() ? 'D' : 'F',
                           packet->payload_len);
      return false;
    }
    return drop("bad-version", packet, tag);
  }

  uint8_t mode = shadow::modeOf(flags);
  unsigned long now_ms = mesh.getMillis();
  SHADOW_TRACE_PRINTLN("SHADOW RX shadow mode=%s tag=%02X%02X%02X type=%d route=%c len=%d",
                       shadow::modeName(mode), tag[0], tag[1], tag[2],
                       packet->getPayloadType(), packet->isRouteDirect() ? 'D' : 'F',
                       packet->payload_len);

  if (mode == SHADOW_MODE_SIGNATURE) {
    // Nodes do not need signature packets; leaving them to normal Mesh
    // processing lets a repeater-capable node forward them unchanged.
    SHADOW_TRACE_PRINTLN("SHADOW RX FORWARD reason=signature-packet tag=%02X%02X%02X",
                         tag[0], tag[1], tag[2]);
    return false;
  }
  if (mode == SHADOW_MODE_FRAGMENT) {
    if (!_unwrap_all) {   // repeater forwards fragments unchanged
      SHADOW_TRACE_PRINTLN("SHADOW RX FORWARD reason=repeater-fragment tag=%02X%02X%02X",
                           tag[0], tag[1], tag[2]);
      return false;
    }
    if (packet->payload_len < SHADOW_FRAG_OVERHEAD) {
      return drop("frag-short", packet, tag);
    }
    uint8_t inner_type = packet->payload[SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE + 2];
    uint16_t frag_len = packet->payload_len - SHADOW_FRAG_OVERHEAD;
    const uint8_t* frag_payload = &packet->payload[SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE + 3];

    if (_forward_envelopes) {
      // Repeater-capable endpoint: keep and forward the original signed
      // fragment, while reassembling a copy for local delivery. The
      // reassembled packet is marked local_only so Mesh never retransmits
      // the inner payload as ordinary traffic.
      saveEnvelope(packet);
      bool consumed = processFragment(mesh, packet, tag, inner_type, frag_payload, frag_len, now_ms);
      if (!consumed) {
        mesh::Packet* local = mesh.obtainNewPacket();
        if (local != NULL) {
          *local = *packet;
          local->local_only = true;
          mesh.queueInboundPacket(local, 0);
          SHADOW_TRACE_PRINTLN("SHADOW RX local deliver tag=%02X%02X%02X type=%d len=%d",
                               tag[0], tag[1], tag[2], local->getPayloadType(), local->payload_len);
        } else {
          _dropped++;
          MESH_DEBUG_PRINTLN("SHADOW RX DROP reason=local-alloc-fail tag=%02X%02X%02X",
                             tag[0], tag[1], tag[2]);
        }
      }
      prepareForward(packet);
      return false;   // forward this fragment unchanged
    }

    return processFragment(mesh, packet, tag, inner_type, frag_payload, frag_len, now_ms);
  }

  uint8_t inner_type;
  const uint8_t* inner;
  uint16_t inner_len;

  if (mode == SHADOW_MODE_EMBEDDED) {
    if (packet->payload_len < SHADOW_EMBEDDED_OVERHEAD) {
      return drop("embedded-short", packet, tag);
    }
    inner_type = packet->payload[SHADOW_COMMON_SIZE];
    inner = &packet->payload[SHADOW_COMMON_SIZE + 1];
    inner_len = packet->payload_len - SHADOW_EMBEDDED_OVERHEAD;
  } else if (mode == SHADOW_MODE_MESSAGE) {
    if (packet->payload_len < SHADOW_MSG_OVERHEAD) {
      return drop("msg-short", packet, tag);
    }
    inner_type = packet->payload[SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE];
    inner = &packet->payload[SHADOW_MSG_OVERHEAD];
    inner_len = packet->payload_len - SHADOW_MSG_OVERHEAD;
  } else {
    return drop("bad-mode", packet, tag);
  }

  if (inner_type == PAYLOAD_TYPE_ADVERT) {
    // A repeater unwraps only zero-hop adverts (neighbour discovery); flood
    // adverts and direct transit adverts keep the envelope for forwarding.
    if (!_unwrap_all
        && !(packet->isRouteDirect() && packet->getPathHashCount() == 0)) {
      SHADOW_TRACE_PRINTLN("SHADOW RX FORWARD reason=advert-transit tag=%02X%02X%02X route=%c path=%d",
                           tag[0], tag[1], tag[2],
                           packet->isRouteDirect() ? 'D' : 'F', (int)packet->getPathHashCount());
      return false;
    }
    if (_unwrap_all && _forward_envelopes && packet->isRouteFlood()
        && inner_len <= MAX_PACKET_PAYLOAD) {
      saveEnvelope(packet);
    }
    MESH_DEBUG_PRINTLN("SHADOW RX UNWRAP advert tag=%02X%02X%02X inner_len=%u route=%c",
                       tag[0], tag[1], tag[2], (unsigned)inner_len,
                       packet->isRouteDirect() ? 'D' : 'F');
    return unwrapLocal(packet, inner_type, inner, inner_len);
  }

  bool direct_type = inner_type == PAYLOAD_TYPE_TXT_MSG || inner_type == PAYLOAD_TYPE_REQ
                  || inner_type == PAYLOAD_TYPE_RESPONSE || inner_type == PAYLOAD_TYPE_PATH;
  if (direct_type) {
    // Direct payloads carry a destination hash as their first inner byte.
    // Never unwrap someone else's transit packet: leave the envelope intact
    // so a repeater-capable node can forward it.
    if (inner_len < 1 || !_self.isHashMatch(inner)) {
      SHADOW_TRACE_PRINTLN("SHADOW RX FORWARD reason=not-for-us tag=%02X%02X%02X type=%d len=%u",
                           tag[0], tag[1], tag[2], inner_type, (unsigned)inner_len);
      return false;
    }
    if (packet->isRouteDirect() && packet->getPathHashCount() > 0) {
      SHADOW_TRACE_PRINTLN("SHADOW RX FORWARD reason=direct-transit tag=%02X%02X%02X type=%d path=%d",
                           tag[0], tag[1], tag[2], inner_type, (int)packet->getPathHashCount());
      return false;
    }
  } else if (!_unwrap_all) {
    // A repeater only unwraps direct traffic addressed to itself; group
    // traffic stays wrapped and is forwarded.
    SHADOW_TRACE_PRINTLN("SHADOW RX FORWARD reason=group-transit tag=%02X%02X%02X type=%d",
                         tag[0], tag[1], tag[2], inner_type);
    return false;
  }

  if (_unwrap_all && _forward_envelopes && packet->isRouteFlood()
      && inner_len <= MAX_PACKET_PAYLOAD) {
    saveEnvelope(packet);
  }
  MESH_DEBUG_PRINTLN("SHADOW RX UNWRAP type=%d tag=%02X%02X%02X inner_len=%u mode=%s",
                     inner_type, tag[0], tag[1], tag[2], (unsigned)inner_len,
                     shadow::modeName(mode));
  return unwrapLocal(packet, inner_type, inner, inner_len);
}

void ShadowNode::poll(unsigned long now_ms) {
  for (int i = 0; i < SHADOW_FRAG_MAX; i++) {
    FragEntry& e = _frags[i];
    if (e.used && (long)(now_ms - e.expiry_ms) >= 0) {
      MESH_DEBUG_PRINTLN("SHADOW RX DROP reason=frag-expired tag=%02X%02X%02X id=%02X%02X%02X%02X mask=%04X age=%lu",
                         e.tag[0], e.tag[1], e.tag[2],
                         e.frag_id[0], e.frag_id[1], e.frag_id[2], e.frag_id[3],
                         (unsigned)e.mask, (unsigned long)(now_ms - e.last_ms));
      e.used = false;
      _dropped++;
    }
  }
}

void ShadowNode::formatStatus(char* reply, size_t reply_len) const {
  const char* mode_name = "auto";
  if (_mode == SHADOW_MODE_EMBEDDED) mode_name = "embedded";
  else if (_mode == SHADOW_MODE_MESSAGE) mode_name = "detached";
  else if (_mode == SHADOW_MODE_FRAGMENT) mode_name = "fragment";
  int frags = 0;
  for (int i = 0; i < SHADOW_FRAG_MAX; i++) if (_frags[i].used) frags++;

  snprintf(reply, reply_len,
           "enabled=%d rx=%d mode=%s frag=%d/%d\n"
           "sig_id=%lu frag_id=%lu\n"
           "sent=%lu recv=%lu frags=%lu dropped=%lu",
           (int)_tx_enabled, (int)_rx_enabled, mode_name, frags, SHADOW_FRAG_MAX,
           (unsigned long)_sig_id, (unsigned long)_frag_id,
           (unsigned long)_sent, (unsigned long)_recv,
           (unsigned long)_frags_recv, (unsigned long)_dropped);
}

static bool parseOnOff(const char* value, bool* out) {
  if (strcmp(value, "on") == 0 || strcmp(value, "1") == 0) { *out = true; return true; }
  if (strcmp(value, "off") == 0 || strcmp(value, "0") == 0) { *out = false; return true; }
  return false;
}

bool ShadowNode::handleCommand(const char* command, char* reply, size_t reply_len) {
  if (strncmp(command, "shd.", 4) != 0) return false;

  char name[32];
  const char* args = "";
  const char* sp = strchr(command, ' ');
  if (sp != NULL) {
    size_t n = sp - command;
    if (n >= sizeof(name)) n = sizeof(name) - 1;
    memcpy(name, command, n);
    name[n] = 0;
    args = sp + 1;
    while (*args == ' ') args++;
  } else {
    strncpy(name, command, sizeof(name) - 1);
    name[sizeof(name) - 1] = 0;
  }

  bool b;
  if (strcmp(name, "shd.enabled") == 0) {
    if (!parseOnOff(args, &b)) { snprintf(reply, reply_len, "Err - on|off"); return true; }
    _tx_enabled = b;
    MESH_DEBUG_PRINTLN("shd.enabled -> %s", b ? "on" : "off");
    snprintf(reply, reply_len, "OK - shadow %s", b ? "enabled" : "disabled");
    return true;
  }
  if (strcmp(name, "shd.mode") == 0) {
    if (strcmp(args, "auto") == 0) _mode = SHADOW_MODE_AUTO;
    else if (strcmp(args, "embedded") == 0) _mode = SHADOW_MODE_EMBEDDED;
    else if (strcmp(args, "detached") == 0) _mode = SHADOW_MODE_MESSAGE;
    else if (strcmp(args, "fragment") == 0) _mode = SHADOW_MODE_FRAGMENT;
    else { snprintf(reply, reply_len, "Err - auto|embedded|detached|fragment"); return true; }
    MESH_DEBUG_PRINTLN("shd.mode -> %s", args);
    snprintf(reply, reply_len, "OK");
    return true;
  }
  if (strcmp(name, "shd.status") == 0) {
    formatStatus(reply, reply_len);
    return true;
  }

  snprintf(reply, reply_len, "Err - unknown shd command");
  return true;
}

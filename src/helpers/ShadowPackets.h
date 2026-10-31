#pragma once

#include <Packet.h>
#include <Utils.h>
#include <string.h>

namespace shadow {

// Domain separation strings. Never reuse a prefix for a different packet role.
static const char DOMAIN_EMB[]  = "MC-SHADOW-EMB";
static const char DOMAIN_SIG[]  = "MC-SHADOW-SIG";
static const char DOMAIN_MSG[]  = "MC-SHADOW-MSG";
static const char DOMAIN_FRAG[] = "MC-SHADOW-FRAG";

inline void tagOf(const uint8_t* pub_key, uint8_t* tag) {
  memcpy(tag, pub_key, SHADOW_TAG_SIZE);
}

inline uint8_t modeOf(uint8_t shadow_flags) {
  return shadow_flags & SHADOW_FLAG_MODE_MASK;
}

inline uint8_t versionOf(uint8_t shadow_flags) {
  return (shadow_flags >> SHADOW_FLAG_VERSION_SHIFT) & SHADOW_FLAG_VERSION_MASK;
}

inline uint8_t makeFlags(uint8_t mode) {
  return (uint8_t)((SHADOW_VERSION << SHADOW_FLAG_VERSION_SHIFT) | (mode & SHADOW_FLAG_MODE_MASK));
}

inline bool hasShadowMarker(const mesh::Packet* packet) {
  return packet->getPayloadType() == PAYLOAD_TYPE_GRP_TXT
      && packet->payload_len >= SHADOW_COMMON_SIZE
      && packet->payload[0] == SHADOW_CHANNEL_HASH
      && packet->payload[1] == (uint8_t)(SHADOW_MAGIC & 0xFF)
      && packet->payload[2] == (uint8_t)((SHADOW_MAGIC >> 8) & 0xFF);
}

inline bool parseHeader(const mesh::Packet* packet, uint8_t* tag, uint8_t* flags) {
  if (!hasShadowMarker(packet)) return false;
  memcpy(tag, &packet->payload[SHADOW_CH_SIZE + SHADOW_MAGIC_SIZE], SHADOW_TAG_SIZE);
  *flags = packet->payload[SHADOW_COMMON_SIZE - 1];
  return versionOf(*flags) == SHADOW_VERSION;
}

inline void writeCommon(uint8_t* dest, const uint8_t* tag, uint8_t mode) {
  dest[0] = SHADOW_CHANNEL_HASH;
  dest[1] = (uint8_t)(SHADOW_MAGIC & 0xFF);
  dest[2] = (uint8_t)((SHADOW_MAGIC >> 8) & 0xFF);
  memcpy(&dest[3], tag, SHADOW_TAG_SIZE);
  dest[SHADOW_COMMON_SIZE - 1] = makeFlags(mode);
}

inline uint8_t pathModeOf(const mesh::Packet* packet) {
  return (uint8_t)((packet->path_len >> 6) & 0x03);
}

// Builds: domain || outer_header || path_mode || shadow_common
//
// Transport codes are intentionally NOT part of the signed digest. The wire
// code has to equal the standard TransportKey::calcTransportCode() over the
// final packet so that legacy region-aware repeaters can route scoped floods;
// that code depends on the shadow signature, so it cannot itself be signed.
// Like the path, it is routing metadata rather than source authorization.
inline size_t addPrefix(uint8_t* buf, const char* domain, uint8_t header,
                        uint8_t path_mode, const uint8_t* shadow_common) {
  size_t n = 0;
  size_t dlen = strlen(domain);
  memcpy(&buf[n], domain, dlen); n += dlen;
  buf[n++] = header;
  buf[n++] = path_mode;
  memcpy(&buf[n], shadow_common, SHADOW_COMMON_SIZE); n += SHADOW_COMMON_SIZE;
  return n;
}

inline void sha256Digest(uint8_t out[SHADOW_DIGEST_SIZE], const uint8_t* buf, size_t len) {
  mesh::Utils::sha256(out, SHADOW_DIGEST_SIZE, buf, (int)len);
}

// Embedded: common(6) + inner_type(1) + inner_payload + signature(64)
inline bool digestEmbedded(uint8_t out[SHADOW_DIGEST_SIZE], uint8_t header, uint8_t path_mode,
                           const uint8_t* payload, uint16_t payload_len) {
  if (payload_len < SHADOW_EMBEDDED_OVERHEAD) return false;
  uint8_t buf[SHADOW_COMMON_SIZE + 1 + SHADOW_DIGEST_SIZE + MAX_PACKET_PAYLOAD + 1];
  size_t n = addPrefix(buf, DOMAIN_EMB, header, path_mode, payload);
  uint16_t signed_len = payload_len - SIGNATURE_SIZE - SHADOW_COMMON_SIZE;
  memcpy(&buf[n], &payload[SHADOW_COMMON_SIZE], signed_len); n += signed_len;
  sha256Digest(out, buf, n);
  return true;
}

// Signature packet: common(6) + sig_id(4) + msg_hash(16) + signature(64)
inline bool digestSignature(uint8_t out[SHADOW_DIGEST_SIZE], uint8_t header, uint8_t path_mode,
                            const uint8_t* payload, uint16_t payload_len) {
  if (payload_len != SHADOW_SIG_PACKET_SIZE) return false;
  uint8_t buf[SHADOW_COMMON_SIZE + 1 + SHADOW_DIGEST_SIZE + SHADOW_SIG_ID_SIZE + SHADOW_MSG_HASH_SIZE + 1];
  size_t n = addPrefix(buf, DOMAIN_SIG, header, path_mode, payload);
  uint16_t signed_len = SHADOW_SIG_ID_SIZE + SHADOW_MSG_HASH_SIZE;
  memcpy(&buf[n], &payload[SHADOW_COMMON_SIZE], signed_len); n += signed_len;
  sha256Digest(out, buf, n);
  return true;
}

// Message packet: common(6) + sig_id(4) + inner_type(1) + inner_payload
inline bool digestMessage(uint8_t out[SHADOW_DIGEST_SIZE], uint8_t header, uint8_t path_mode,
                          const uint8_t* payload, uint16_t payload_len) {
  if (payload_len < SHADOW_MSG_OVERHEAD) return false;
  uint8_t buf[SHADOW_COMMON_SIZE + 1 + SHADOW_DIGEST_SIZE + MAX_PACKET_PAYLOAD + 1];
  size_t n = addPrefix(buf, DOMAIN_MSG, header, path_mode, payload);
  memcpy(&buf[n], payload, payload_len); n += payload_len;
  sha256Digest(out, buf, n);
  return true;
}

// Fragment: common(6) + frag_id(4) + index(1) + count(1) + inner_type(1)
//           + frag_payload + signature(64)
inline bool digestFragment(uint8_t out[SHADOW_DIGEST_SIZE], uint8_t header, uint8_t path_mode,
                           const uint8_t* payload, uint16_t payload_len) {
  if (payload_len < SHADOW_FRAG_OVERHEAD) return false;
  uint8_t buf[SHADOW_COMMON_SIZE + 1 + SHADOW_DIGEST_SIZE + MAX_PACKET_PAYLOAD + 1];
  size_t n = addPrefix(buf, DOMAIN_FRAG, header, path_mode, payload);
  uint16_t signed_len = payload_len - SIGNATURE_SIZE - SHADOW_COMMON_SIZE;
  memcpy(&buf[n], &payload[SHADOW_COMMON_SIZE], signed_len); n += signed_len;
  sha256Digest(out, buf, n);
  return true;
}

inline bool digestForMode(uint8_t out[SHADOW_DIGEST_SIZE], uint8_t mode, const mesh::Packet* packet) {
  uint8_t path_mode = pathModeOf(packet);
  switch (mode) {
    case SHADOW_MODE_EMBEDDED:
      return digestEmbedded(out, packet->header, path_mode, packet->payload, packet->payload_len);
    case SHADOW_MODE_SIGNATURE:
      return digestSignature(out, packet->header, path_mode, packet->payload, packet->payload_len);
    case SHADOW_MODE_MESSAGE:
      return digestMessage(out, packet->header, path_mode, packet->payload, packet->payload_len);
    case SHADOW_MODE_FRAGMENT:
      return digestFragment(out, packet->header, path_mode, packet->payload, packet->payload_len);
    default:
      return false;
  }
}

} // namespace shadow

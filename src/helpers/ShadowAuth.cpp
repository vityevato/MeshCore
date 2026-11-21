#include "ShadowAuth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if SHADOW_AUTH_HAS_FS
static File shadowOpenWrite(FILESYSTEM* fs, const char* filename) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  fs->remove(filename);
  return fs->open(filename, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  return fs->open(filename, "w");
#else
  return fs->open(filename, "w", true);
#endif
}

static File shadowOpenRead(FILESYSTEM* fs, const char* filename) {
#if defined(RP2040_PLATFORM)
  return fs->open(filename, "r");
#else
  return fs->open(filename);
#endif
}
#endif

void ShadowPrefs::structure() {
  // ConfigSerializer keys accept only [A-Za-z0-9_]. The dotted names are CLI
  // command names, not persisted keys; dots here make the whole file unreadable.
  def("shd_enabled", enabled);
  def("shd_enforce", enforce);
  def("shd_allow_anon", allow_anon);
  def("shd_allow_advert", allow_advert);
  def("shd_auto_add", auto_add);
  def("shd_pending_max", pending_max);
  def("shd_hold_min", hold_min_ms);
  def("shd_hold_max", hold_max_ms);
  def("shd_hold_default", hold_default_ms);
  def("shd_margin", margin_ms);
  def("shd_max_msg_wait", max_msg_wait_ms);
  def("shd_max_sig_wait", max_sig_wait_ms);
  def("shd_max_frag_gap", max_frag_gap_ms);
  def("shd_saved", saved_at);
  def("shd_acl_migrated", acl_migrated);
}

// ---------------------------------------------------------------------------
// ShadowVerifiedCache
// ---------------------------------------------------------------------------

void ShadowVerifiedCache::clear() {
  memset(_hashes, 0, sizeof(_hashes));
  memset(_used, 0, sizeof(_used));
  _next = 0;
}

bool ShadowVerifiedCache::contains(const uint8_t* hash) const {
  for (int i = 0; i < SHADOW_VERIFIED_CACHE_SIZE; i++) {
    if (_used[i] && memcmp(_hashes[i], hash, SHADOW_MSG_HASH_SIZE) == 0) return true;
  }
  return false;
}

void ShadowVerifiedCache::insert(const uint8_t* hash) {
  memcpy(_hashes[_next], hash, SHADOW_MSG_HASH_SIZE);
  _used[_next] = true;
  _next = (_next + 1) % SHADOW_VERIFIED_CACHE_SIZE;
}

// ---------------------------------------------------------------------------
// ShadowTtlTracker
// ---------------------------------------------------------------------------

void ShadowTtlTracker::reset() {
  memset(_msg, 0, sizeof(_msg));
  memset(_sig, 0, sizeof(_sig));
  memset(_frag, 0, sizeof(_frag));
  _msg_n = _msg_i = 0;
  _sig_n = _sig_i = 0;
  _frag_n = _frag_i = 0;
}

void ShadowTtlTracker::addMsgWait(uint32_t ms) {
  _msg[_msg_i] = ms;
  _msg_i = (_msg_i + 1) % SHADOW_TTL_SAMPLES;
  if (_msg_n < SHADOW_TTL_SAMPLES) _msg_n++;
}
void ShadowTtlTracker::addSigWait(uint32_t ms) {
  _sig[_sig_i] = ms;
  _sig_i = (_sig_i + 1) % SHADOW_TTL_SAMPLES;
  if (_sig_n < SHADOW_TTL_SAMPLES) _sig_n++;
}
void ShadowTtlTracker::addFragGap(uint32_t ms) {
  _frag[_frag_i] = ms;
  _frag_i = (_frag_i + 1) % SHADOW_TTL_SAMPLES;
  if (_frag_n < SHADOW_TTL_SAMPLES) _frag_n++;
}

uint32_t ShadowTtlTracker::maxMsgWait() const {
  uint32_t m = 0;
  for (int i = 0; i < _msg_n; i++) if (_msg[i] > m) m = _msg[i];
  return m;
}
uint32_t ShadowTtlTracker::maxSigWait() const {
  uint32_t m = 0;
  for (int i = 0; i < _sig_n; i++) if (_sig[i] > m) m = _sig[i];
  return m;
}
uint32_t ShadowTtlTracker::maxFragGap() const {
  uint32_t m = 0;
  for (int i = 0; i < _frag_n; i++) if (_frag[i] > m) m = _frag[i];
  return m;
}

// ---------------------------------------------------------------------------
// ShadowAuth
// ---------------------------------------------------------------------------

static uint32_t clampU32(uint32_t v, uint32_t lo, uint32_t hi) {
  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;
}

ShadowAuth::ShadowAuth()
  : _dropped(0), _dup_fast(0), _bad_sig(0), _would_drop(0), _pending_evicted(0),
    _prefs_dirty(false), _allow_dirty(false), _last_persist_ms(0),
    _hold_ttl_ms(SHADOW_HOLD_DEFAULT_MS), _sig_ttl_ms(SHADOW_SIG_TTL_DEFAULT_MS),
    _frag_ttl_ms(SHADOW_FRAG_TTL_DEFAULT_MS)
#if SHADOW_AUTH_HAS_FS
    , _fs(NULL)
#endif
{
  memset(_allow, 0, sizeof(_allow));
  memset(_sig, 0, sizeof(_sig));
  memset(_pending, 0, sizeof(_pending));
  memset(_rate, 0, sizeof(_rate));
  memset(_advert_rate, 0, sizeof(_advert_rate));
}

bool ShadowAuth::drop(const char* reason, const mesh::Packet* pkt, const uint8_t* tag) {
  _dropped++;
  char tag_buf[2 * SHADOW_TAG_SIZE + 1];
  if (tag != NULL) {
    mesh::Utils::toHex(tag_buf, tag, SHADOW_TAG_SIZE);
  } else {
    snprintf(tag_buf, sizeof(tag_buf), "---");
  }
  MESH_DEBUG_PRINTLN("SHADOW RX DROP reason=%s type=%d route=%c len=%d tag=%s",
                     reason, pkt->getPayloadType(), pkt->isRouteDirect() ? 'D' : 'F',
                     pkt->payload_len, tag_buf);
  return true;
}

bool ShadowAuth::wouldDrop(const char* reason, const mesh::Packet* pkt, const uint8_t* tag) {
  _would_drop++;
  char tag_buf[2 * SHADOW_TAG_SIZE + 1];
  if (tag != NULL) {
    mesh::Utils::toHex(tag_buf, tag, SHADOW_TAG_SIZE);
  } else {
    snprintf(tag_buf, sizeof(tag_buf), "---");
  }
  MESH_DEBUG_PRINTLN("SHADOW RX WOULD-DROP reason=%s type=%d route=%c len=%d tag=%s",
                     reason, pkt->getPayloadType(), pkt->isRouteDirect() ? 'D' : 'F',
                     pkt->payload_len, tag_buf);
  return false;
}

void ShadowAuth::begin(ShadowFs* fs, uint32_t now_epoch) {
#if SHADOW_AUTH_HAS_FS
  _fs = fs;
  loadPrefs(fs);
  loadAllowList(fs);

  // Sanitise persisted values.
  prefs.pending_max = (uint8_t)clampU32(prefs.pending_max, 1, SHADOW_PENDING_MAX);
  prefs.hold_min_ms = clampU32(prefs.hold_min_ms, 1000, SHADOW_HOLD_MAX_MS);
  prefs.hold_max_ms = clampU32(prefs.hold_max_ms, prefs.hold_min_ms, SHADOW_HOLD_MAX_MS);
  prefs.hold_default_ms = clampU32(prefs.hold_default_ms, prefs.hold_min_ms, prefs.hold_max_ms);
  prefs.margin_ms = clampU32(prefs.margin_ms, 0, 60000);

  // Stale delay observations are worse than none: reset them after 24h.
  if (prefs.saved_at != 0 && now_epoch != 0 && now_epoch > prefs.saved_at + 86400UL) {
    prefs.max_msg_wait_ms = prefs.max_sig_wait_ms = prefs.max_frag_gap_ms = 0;
  }

  // Restore the observation window from persisted maxima.
  if (prefs.max_msg_wait_ms) _ttl.addMsgWait(prefs.max_msg_wait_ms);
  if (prefs.max_sig_wait_ms) _ttl.addSigWait(prefs.max_sig_wait_ms);
  if (prefs.max_frag_gap_ms) _ttl.addFragGap(prefs.max_frag_gap_ms);

  updateTtls();
  _last_persist_ms = 0;
#else
  (void)fs;
  (void)now_epoch;
  prefs.enabled = 1;
  prefs.enforce = 0;
  updateTtls();
#endif
  MESH_DEBUG_PRINTLN("SHADOW: begin enabled=%d enforce=%d anon=%d advert=%d auto_add=%d pending=%d allow=%d/%d ttl=%lu/%lu/%lu",
                     (int)prefs.enabled, (int)prefs.enforce, (int)prefs.allow_anon,
                     (int)prefs.allow_advert, (int)prefs.auto_add, (int)prefs.pending_max,
                     getNumAllowed(), SHADOW_MAX_ALLOW,
                     (unsigned long)_hold_ttl_ms, (unsigned long)_sig_ttl_ms,
                     (unsigned long)_frag_ttl_ms);
}

bool ShadowAuth::loadPrefs(ShadowFs* fs) {
#if SHADOW_AUTH_HAS_FS
  if (fs == NULL || !fs->exists("/shadow_prefs")) {
    MESH_DEBUG_PRINTLN("SHADOW: /shadow_prefs not found, using defaults");
    return false;
  }
  File f = shadowOpenRead(fs, "/shadow_prefs");
  if (!f) {
    MESH_DEBUG_PRINTLN("SHADOW: /shadow_prefs open failed");
    return false;
  }
  bool ok = prefs.loadSerial(f);
  f.close();
  MESH_DEBUG_PRINTLN("SHADOW: /shadow_prefs %s", ok ? "loaded" : "parse failed");
  return ok;
#else
  (void)fs;
  return false;
#endif
}

bool ShadowAuth::savePrefs(ShadowFs* fs) {
#if SHADOW_AUTH_HAS_FS
  if (fs == NULL) return false;
  prefs.max_msg_wait_ms = _ttl.maxMsgWait();
  prefs.max_sig_wait_ms = _ttl.maxSigWait();
  prefs.max_frag_gap_ms = _ttl.maxFragGap();
  File f = shadowOpenWrite(fs, "/shadow_prefs");
  if (!f) {
    MESH_DEBUG_PRINTLN("SHADOW: /shadow_prefs write open failed");
    return false;
  }
  bool ok = prefs.saveSerial(f);
  f.close();
  if (ok) {
    _prefs_dirty = false;
    SHADOW_TRACE_PRINTLN("SHADOW: /shadow_prefs saved");
  } else {
    MESH_DEBUG_PRINTLN("SHADOW: /shadow_prefs save failed");
  }
  return ok;
#else
  (void)fs;
  _prefs_dirty = false;
  return true;
#endif
}

bool ShadowAuth::loadAllowList(ShadowFs* fs) {
#if SHADOW_AUTH_HAS_FS
  memset(_allow, 0, sizeof(_allow));
  if (fs == NULL || !fs->exists("/shadow_acl")) {
    MESH_DEBUG_PRINTLN("SHADOW: /shadow_acl not found");
    return false;
  }
  File f = shadowOpenRead(fs, "/shadow_acl");
  if (!f) {
    MESH_DEBUG_PRINTLN("SHADOW: /shadow_acl open failed");
    return false;
  }

  int n = 0;
  while (n < SHADOW_MAX_ALLOW) {
    ShadowAllowEntry e;
    if (f.read(e.pub_key, PUB_KEY_SIZE) != PUB_KEY_SIZE) break;
    if (f.read(&e.flags, 1) != 1) break;
    if (f.read((uint8_t*)&e.last_seen, 4) != 4) break;
    if (e.flags & 1) _allow[n++] = e;
  }
  f.close();
  MESH_DEBUG_PRINTLN("SHADOW: /shadow_acl loaded %d keys", n);
  return n > 0;
#else
  (void)fs;
  return false;
#endif
}

bool ShadowAuth::saveAllowList(ShadowFs* fs) {
#if SHADOW_AUTH_HAS_FS
  if (fs == NULL) return false;
  File f = shadowOpenWrite(fs, "/shadow_acl");
  if (!f) {
    MESH_DEBUG_PRINTLN("SHADOW: /shadow_acl write open failed");
    return false;
  }
  bool ok = true;
  for (int i = 0; i < SHADOW_MAX_ALLOW; i++) {
    ShadowAllowEntry& e = _allow[i];
    if (!(e.flags & 1)) continue;
    if (f.write(e.pub_key, PUB_KEY_SIZE) != PUB_KEY_SIZE) { ok = false; break; }
    if (f.write(&e.flags, 1) != 1) { ok = false; break; }
    if (f.write((uint8_t*)&e.last_seen, 4) != 4) { ok = false; break; }
  }
  f.close();
  if (!ok) {
    MESH_DEBUG_PRINTLN("SHADOW: /shadow_acl save failed");
  } else {
    _allow_dirty = false;
    SHADOW_TRACE_PRINTLN("SHADOW: /shadow_acl saved");
  }
  return ok;
#else
  (void)fs;
  _allow_dirty = false;
  return true;
#endif
}

void ShadowAuth::updateTtls() {
  unsigned long old_hold = _hold_ttl_ms;
  unsigned long old_sig = _sig_ttl_ms;
  unsigned long old_frag = _frag_ttl_ms;

  uint32_t hold = prefs.hold_default_ms;
  uint32_t by_msg = _ttl.maxMsgWait() * 2UL + prefs.margin_ms;
  if (by_msg > hold) hold = by_msg;
  hold = clampU32(hold, prefs.hold_min_ms, prefs.hold_max_ms);
  _hold_ttl_ms = hold;

  uint32_t sig = hold + 30000UL;
  uint32_t by_sig = _ttl.maxSigWait() * 2UL + prefs.margin_ms;
  if (by_sig > sig) sig = by_sig;
  _sig_ttl_ms = clampU32(sig, SHADOW_SIG_TTL_MIN_MS, SHADOW_SIG_TTL_MAX_MS);

  uint32_t frag = hold;
  uint32_t by_frag = _ttl.maxFragGap() * 2UL + prefs.margin_ms;
  if (by_frag > frag) frag = by_frag;
  _frag_ttl_ms = clampU32(frag, SHADOW_FRAG_TTL_MIN_MS, SHADOW_FRAG_TTL_MAX_MS);

  if (old_hold != _hold_ttl_ms || old_sig != _sig_ttl_ms || old_frag != _frag_ttl_ms) {
    MESH_DEBUG_PRINTLN("SHADOW: ttl hold=%lu sig=%lu frag=%lu (max msg/sig/frag=%lu/%lu/%lu)",
                       (unsigned long)_hold_ttl_ms, (unsigned long)_sig_ttl_ms,
                       (unsigned long)_frag_ttl_ms,
                       (unsigned long)_ttl.maxMsgWait(), (unsigned long)_ttl.maxSigWait(),
                       (unsigned long)_ttl.maxFragGap());
  }
}

bool ShadowAuth::rateAllow(TagRate* table, const char* table_name, const uint8_t* tag,
                           unsigned long now_ms, uint16_t max_per_min) {
  int free_idx = -1;
  unsigned long oldest = now_ms;
  for (int i = 0; i < 16; i++) {
    TagRate& r = table[i];
    if (memcmp(r.tag, tag, SHADOW_TAG_SIZE) == 0) {
      if ((unsigned long)(now_ms - r.window_ms) >= 60000UL) {
        r.window_ms = now_ms;
        r.count = 1;
        return true;
      }
      if (r.count >= max_per_min) {
        SHADOW_TRACE_PRINTLN("SHADOW: rate limit table=%s tag=%02X%02X%02X count=%u/%u",
                             table_name, tag[0], tag[1], tag[2], (unsigned)r.count,
                             (unsigned)max_per_min);
        return false;
      }
      r.count++;
      return true;
    }
    if (r.count == 0) {
      free_idx = i;
      break;
    }
    if ((long)(oldest - r.window_ms) > 0) {
      oldest = r.window_ms;
      free_idx = i;
    }
  }
  if (free_idx < 0) {
    MESH_DEBUG_PRINTLN("SHADOW: rate table full table=%s", table_name);
    return false;
  }
  TagRate& r = table[free_idx];
  memcpy(r.tag, tag, SHADOW_TAG_SIZE);
  r.window_ms = now_ms;
  r.count = 1;
  return true;
}

bool ShadowAuth::hasAllowedTag(const uint8_t* tag) const {
  for (int i = 0; i < SHADOW_MAX_ALLOW; i++) {
    if ((_allow[i].flags & 1) && memcmp(_allow[i].pub_key, tag, SHADOW_TAG_SIZE) == 0) {
      return true;
    }
  }
  return false;
}

ShadowSigEntry* ShadowAuth::findSig(const uint8_t* tag, const uint8_t* sig_id, unsigned long now_ms) {
  for (int i = 0; i < SHADOW_SIG_CACHE_SIZE; i++) {
    ShadowSigEntry& e = _sig[i];
    if (!e.used) continue;
    if ((long)(now_ms - e.expiry_ms) >= 0) {
      SHADOW_TRACE_PRINTLN("SHADOW: sig-cache expired tag=%02X%02X%02X id=%02X%02X%02X%02X",
                           e.tag[0], e.tag[1], e.tag[2],
                           e.sig_id[0], e.sig_id[1], e.sig_id[2], e.sig_id[3]);
      e.used = false;
      continue;
    }
    if (memcmp(e.tag, tag, SHADOW_TAG_SIZE) == 0
        && memcmp(e.sig_id, sig_id, SHADOW_SIG_ID_SIZE) == 0) {
      return &e;
    }
  }
  return NULL;
}

int ShadowAuth::oldestSigSlot(const ShadowSigEntry* entries, int count) {
  int slot = -1;
  unsigned long oldest = 0;
  for (int i = 0; i < count; i++) {
    if (!entries[i].used) return i;
    if (slot < 0 || (long)(entries[i].expiry_ms - oldest) < 0) {
      oldest = entries[i].expiry_ms;
      slot = i;
    }
  }
  return slot < 0 ? 0 : slot;
}

void ShadowAuth::insertSig(const uint8_t* tag, const uint8_t* sig_id,
                           const uint8_t* msg_hash, unsigned long now_ms) {
  int slot = oldestSigSlot(_sig, SHADOW_SIG_CACHE_SIZE);
  ShadowSigEntry& e = _sig[slot];
  if (e.used) {
    MESH_DEBUG_PRINTLN("SHADOW: sig-cache EVICT slot=%d old_tag=%02X%02X%02X old_id=%02X%02X%02X%02X",
                       slot, e.tag[0], e.tag[1], e.tag[2],
                       e.sig_id[0], e.sig_id[1], e.sig_id[2], e.sig_id[3]);
  }
  e.used = true;
  memcpy(e.tag, tag, SHADOW_TAG_SIZE);
  memcpy(e.sig_id, sig_id, SHADOW_SIG_ID_SIZE);
  memcpy(e.msg_hash, msg_hash, SHADOW_MSG_HASH_SIZE);
  e.created_ms = now_ms;
  e.expiry_ms = now_ms + _sig_ttl_ms;
  SHADOW_TRACE_PRINTLN("SHADOW: sig-cache insert slot=%d tag=%02X%02X%02X id=%02X%02X%02X%02X hash=%02X%02X%02X%02X",
                       slot, tag[0], tag[1], tag[2],
                       sig_id[0], sig_id[1], sig_id[2], sig_id[3],
                       msg_hash[0], msg_hash[1], msg_hash[2], msg_hash[3]);
}

bool ShadowAuth::verifyWithCandidates(const uint8_t* tag, const uint8_t* signature,
                                      const uint8_t digest[SHADOW_DIGEST_SIZE]) {
  int candidates = 0;
  for (int i = 0; i < SHADOW_MAX_ALLOW; i++) {
    if (!(_allow[i].flags & 1)) continue;
    if (memcmp(_allow[i].pub_key, tag, SHADOW_TAG_SIZE) != 0) continue;
    candidates++;
    mesh::Identity id(_allow[i].pub_key);
    if (id.verify(signature, digest, SHADOW_DIGEST_SIZE)) {
      SHADOW_TRACE_PRINTLN("SHADOW: verify ok tag=%02X%02X%02X candidate=%d/%d",
                           tag[0], tag[1], tag[2], candidates, getNumAllowed());
      return true;
    }
  }
  if (candidates > 1) {
    SHADOW_TRACE_PRINTLN("SHADOW: verify failed tag=%02X%02X%02X candidates=%d",
                         tag[0], tag[1], tag[2], candidates);
  }
  return false;
}

void ShadowAuth::releasePending(mesh::Mesh& mesh, int idx) {
  ShadowPendingEntry& e = _pending[idx];
  if (!e.used) return;

  mesh::Packet* p = mesh.obtainNewPacket();
  if (p == NULL) {
    _dropped++;
    MESH_DEBUG_PRINTLN("SHADOW: pending release DROP reason=alloc-fail tag=%02X%02X%02X id=%02X%02X%02X%02X",
                       e.tag[0], e.tag[1], e.tag[2],
                       e.sig_id[0], e.sig_id[1], e.sig_id[2], e.sig_id[3]);
  } else if (p->readFrom(e.data, (uint8_t)e.len)) {
    p->shadow = true;
    p->shadow_wrapped = true;
    p->shadow_flags = shadow::makeFlags(SHADOW_MODE_MESSAGE);
    p->auth_ok = true;
    mesh.queueInboundPacket(p, 0);
    MESH_DEBUG_PRINTLN("SHADOW: pending release tag=%02X%02X%02X id=%02X%02X%02X%02X len=%u",
                       e.tag[0], e.tag[1], e.tag[2],
                       e.sig_id[0], e.sig_id[1], e.sig_id[2], e.sig_id[3],
                       (unsigned)e.len);
  } else {
    mesh.releasePacket(p);
    _dropped++;
    MESH_DEBUG_PRINTLN("SHADOW: pending release DROP reason=read-fail tag=%02X%02X%02X id=%02X%02X%02X%02X",
                       e.tag[0], e.tag[1], e.tag[2],
                       e.sig_id[0], e.sig_id[1], e.sig_id[2], e.sig_id[3]);
  }
  e.used = false;
}

static bool shadowInner(const mesh::Packet* pkt, uint8_t mode,
                        uint8_t* inner_type, const uint8_t** inner, uint16_t* inner_len) {
  if (mode == SHADOW_MODE_EMBEDDED) {
    if (pkt->payload_len < SHADOW_EMBEDDED_OVERHEAD) return false;
    *inner_type = pkt->payload[SHADOW_COMMON_SIZE];
    *inner = &pkt->payload[SHADOW_COMMON_SIZE + 1];
    *inner_len = pkt->payload_len - SHADOW_EMBEDDED_OVERHEAD;
    return true;
  }
  if (mode == SHADOW_MODE_MESSAGE) {
    if (pkt->payload_len < SHADOW_MSG_OVERHEAD) return false;
    *inner_type = pkt->payload[SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE];
    *inner = &pkt->payload[SHADOW_MSG_OVERHEAD];
    *inner_len = pkt->payload_len - SHADOW_MSG_OVERHEAD;
    return true;
  }
  return false;
}

// Verifies the advert payload: [pubkey 32][timestamp 4][signature 64][app_data 0..32].
// This is the same check Mesh::onRecvPacket() performs for ordinary adverts.
static bool verifyAdvertPayload(const uint8_t* payload, uint16_t payload_len) {
  const uint16_t min_len = PUB_KEY_SIZE + 4 + SIGNATURE_SIZE;
  if (payload_len < min_len) return false;

  uint16_t app_len = payload_len - min_len;
  if (app_len > MAX_ADVERT_DATA_SIZE) app_len = MAX_ADVERT_DATA_SIZE;

  uint8_t message[PUB_KEY_SIZE + 4 + MAX_ADVERT_DATA_SIZE];
  memcpy(message, payload, PUB_KEY_SIZE);
  memcpy(&message[PUB_KEY_SIZE], &payload[PUB_KEY_SIZE], 4);
  memcpy(&message[PUB_KEY_SIZE + 4], &payload[min_len], app_len);

  mesh::Identity id(payload);
  return id.verify(&payload[PUB_KEY_SIZE + 4], message, PUB_KEY_SIZE + 4 + app_len);
}

static bool verifyAdvertInner(const uint8_t* inner, uint16_t inner_len) {
  return verifyAdvertPayload(inner, inner_len);
}

bool ShadowAuth::filterShadow(mesh::Mesh& mesh, mesh::Packet* pkt, const uint8_t* tag,
                              uint8_t flags, unsigned long now_ms) {
  uint8_t mode = shadow::modeOf(flags);
  if (mode > SHADOW_MODE_FRAGMENT) {
    return enforce() ? drop("bad-mode", pkt, tag) : wouldDrop("bad-mode", pkt, tag);
  }

  uint8_t digest[SHADOW_DIGEST_SIZE];
  if (!shadow::digestForMode(digest, mode, pkt)) {
    return enforce() ? drop("bad-digest", pkt, tag) : wouldDrop("bad-digest", pkt, tag);
  }

  uint8_t hash16[SHADOW_MSG_HASH_SIZE];
  memcpy(hash16, digest, SHADOW_MSG_HASH_SIZE);

  // Dedup-before-verify. Only successfully verified packets enter this cache.
  if (_verified.contains(hash16)) {
    _dup_fast++;
    SHADOW_TRACE_PRINTLN("SHADOW RX ACCEPT dup-cache mode=%s tag=%02X%02X%02X hash=%02X%02X%02X%02X",
                         shadow::modeName(mode), tag[0], tag[1], tag[2],
                         hash16[0], hash16[1], hash16[2], hash16[3]);
    if (mode == SHADOW_MODE_SIGNATURE) {
      // Refresh the signature association in case its cache entry expired.
      uint8_t sig_id[SHADOW_SIG_ID_SIZE];
      uint8_t msg_hash[SHADOW_MSG_HASH_SIZE];
      memcpy(sig_id, &pkt->payload[SHADOW_COMMON_SIZE], SHADOW_SIG_ID_SIZE);
      memcpy(msg_hash, &pkt->payload[SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE], SHADOW_MSG_HASH_SIZE);
      insertSig(tag, sig_id, msg_hash, now_ms);
    }
    // A cached ADVERT must still obey the current allow.advert policy: it may
    // have been verified while open discovery was enabled.
    if (mode == SHADOW_MODE_EMBEDDED || mode == SHADOW_MODE_MESSAGE) {
      uint8_t inner_type;
      const uint8_t* inner;
      uint16_t inner_len;
      if (shadowInner(pkt, mode, &inner_type, &inner, &inner_len)
          && inner_type == PAYLOAD_TYPE_ADVERT
          && !prefs.allow_advert
          && (inner_len < PUB_KEY_SIZE + 4 + SIGNATURE_SIZE
              || memcmp(tag, inner, SHADOW_TAG_SIZE) != 0
              || !contains(inner))) {
        return enforce() ? drop("advert-policy-cached", pkt, tag)
                         : wouldDrop("advert-policy-cached", pkt, tag);
      }
    }
    pkt->auth_ok = true;
    return false;
  }

  // Wrapped ADVERT is self-authenticating: the inner advert carries its own
  // Ed25519 signature. That signature is the trust anchor for both policies:
  //   shd.allow.advert off -> inner pubkey must be on the shadow allowlist;
  //   shd.allow.advert on  -> any valid signed advert is allowed.
  // The outer shadow signature is redundant for adverts and is not required.
  if (mode == SHADOW_MODE_EMBEDDED || mode == SHADOW_MODE_MESSAGE) {
    uint8_t inner_type;
    const uint8_t* inner;
    uint16_t inner_len;
    if (shadowInner(pkt, mode, &inner_type, &inner, &inner_len)
        && inner_type == PAYLOAD_TYPE_ADVERT) {
      if (inner_len < PUB_KEY_SIZE + 4 + SIGNATURE_SIZE
          || memcmp(tag, inner, SHADOW_TAG_SIZE) != 0) {
        _bad_sig++;
        return enforce() ? drop("advert-tag-mismatch", pkt, tag)
                         : wouldDrop("advert-tag-mismatch", pkt, tag);
      }
      // Strict mode: reject unknown advert keys before doing Ed25519 work.
      if (!prefs.allow_advert && !contains(inner)) {
        return enforce() ? drop("advert-unknown-key", pkt, tag)
                         : wouldDrop("advert-unknown-key", pkt, tag);
      }
      if (!rateAllow(_advert_rate, "advert", tag, now_ms, 8)) {
        return enforce() ? drop("advert-rate", pkt, tag)
                         : wouldDrop("advert-rate", pkt, tag);
      }
      if (!verifyAdvertInner(inner, inner_len)) {
        _bad_sig++;
        return enforce() ? drop("advert-badsig", pkt, tag)
                         : wouldDrop("advert-badsig", pkt, tag);
      }
      _verified.insert(hash16);
      pkt->auth_ok = true;
      MESH_DEBUG_PRINTLN("SHADOW RX ACCEPT advert tag=%02X%02X%02X inner_len=%u allow_advert=%d",
                         tag[0], tag[1], tag[2], (unsigned)inner_len, (int)prefs.allow_advert);
      return false;
    }
  }

  // Unknown tags are dropped before the expensive Ed25519 operation. A known
  // tag is rate-limited so one compromised node cannot monopolise the CPU.
  if (!hasAllowedTag(tag)) {
    return enforce() ? drop("unknown-tag", pkt, tag) : wouldDrop("unknown-tag", pkt, tag);
  }
  if (!rateAllow(_rate, "transit", tag, now_ms, 300)) {
    return enforce() ? drop("transit-rate", pkt, tag) : wouldDrop("transit-rate", pkt, tag);
  }

  if (mode == SHADOW_MODE_MESSAGE) {
    uint8_t sig_id[SHADOW_SIG_ID_SIZE];
    memcpy(sig_id, &pkt->payload[SHADOW_COMMON_SIZE], SHADOW_SIG_ID_SIZE);

    ShadowSigEntry* sig = findSig(tag, sig_id, now_ms);
    if (sig != NULL) {
      if (memcmp(sig->msg_hash, hash16, SHADOW_MSG_HASH_SIZE) == 0) {
        _verified.insert(hash16);
        pkt->auth_ok = true;
        uint32_t wait = (uint32_t)(now_ms - sig->created_ms);
        if (wait > 0) _ttl.addSigWait(wait);
        MESH_DEBUG_PRINTLN("SHADOW RX ACCEPT message tag=%02X%02X%02X id=%02X%02X%02X%02X wait=%lu",
                           tag[0], tag[1], tag[2],
                           sig_id[0], sig_id[1], sig_id[2], sig_id[3], (unsigned long)wait);
        return false;
      }
      _bad_sig++;
      return enforce() ? drop("sig-mismatch", pkt, tag) : wouldDrop("sig-mismatch", pkt, tag);
    }

    // Transitional mode: verify and count, but never hold/drop ordinary
    // traffic while enforcement is off.
    if (!enforce()) {
      return wouldDrop("no-sig", pkt, tag);
    }

    // Message arrived before its signature: hold it in a compact buffer.
    uint8_t pending_limit = prefs.pending_max;
    if (pending_limit > SHADOW_PENDING_MAX) pending_limit = SHADOW_PENDING_MAX;
    if (pending_limit == 0) {
      return drop("pending-full", pkt, tag);
    }

    for (int i = 0; i < pending_limit; i++) {
      if (_pending[i].used
          && memcmp(_pending[i].msg_hash, hash16, SHADOW_MSG_HASH_SIZE) == 0) {
        SHADOW_TRACE_PRINTLN("SHADOW RX DROP reason=pending-duplicate tag=%02X%02X%02X id=%02X%02X%02X%02X",
                             tag[0], tag[1], tag[2],
                             sig_id[0], sig_id[1], sig_id[2], sig_id[3]);
        return true;   // duplicate already waiting for the same signature
      }
    }

    int slot = -1;
    int oldest = -1;
    unsigned long oldest_created = now_ms;
    for (int i = 0; i < pending_limit; i++) {
      if (!_pending[i].used) { slot = i; break; }
      if ((long)(_pending[i].created_ms - oldest_created) < 0) {
        oldest_created = _pending[i].created_ms;
        oldest = i;
      }
    }
    if (slot < 0) {
      slot = oldest;
      if (slot < 0) slot = 0;
      _pending_evicted++;
      ShadowPendingEntry& old = _pending[slot];
      MESH_DEBUG_PRINTLN("SHADOW RX EVICT pending slot=%d old_tag=%02X%02X%02X old_id=%02X%02X%02X%02X age=%lu",
                         slot, old.tag[0], old.tag[1], old.tag[2],
                         old.sig_id[0], old.sig_id[1], old.sig_id[2], old.sig_id[3],
                         (unsigned long)(now_ms - old.created_ms));
    }
    ShadowPendingEntry& e = _pending[slot];
    memset(&e, 0, sizeof(e));
    e.len = pkt->writeTo(e.data);
    if (e.len == 0) {
      return drop("hold-write-fail", pkt, tag);
    }
    e.used = true;
    memcpy(e.tag, tag, SHADOW_TAG_SIZE);
    memcpy(e.sig_id, sig_id, SHADOW_SIG_ID_SIZE);
    memcpy(e.msg_hash, hash16, SHADOW_MSG_HASH_SIZE);
    e.created_ms = now_ms;
    e.deadline_ms = now_ms + _hold_ttl_ms;
    MESH_DEBUG_PRINTLN("SHADOW RX HOLD tag=%02X%02X%02X id=%02X%02X%02X%02X slot=%d ttl=%lu",
                       tag[0], tag[1], tag[2],
                       sig_id[0], sig_id[1], sig_id[2], sig_id[3],
                       slot, (unsigned long)_hold_ttl_ms);
    return true;   // held, not forwarded yet
  }

  const uint8_t* signature = &pkt->payload[pkt->payload_len - SIGNATURE_SIZE];
  if (!verifyWithCandidates(tag, signature, digest)) {
    _bad_sig++;
    return enforce() ? drop("badsig", pkt, tag) : wouldDrop("badsig", pkt, tag);
  }

  _verified.insert(hash16);
  pkt->auth_ok = true;
  MESH_DEBUG_PRINTLN("SHADOW RX ACCEPT verified mode=%s tag=%02X%02X%02X hash=%02X%02X%02X%02X",
                     shadow::modeName(mode), tag[0], tag[1], tag[2],
                     hash16[0], hash16[1], hash16[2], hash16[3]);

  if (mode == SHADOW_MODE_SIGNATURE) {
    uint8_t sig_id[SHADOW_SIG_ID_SIZE];
    uint8_t msg_hash[SHADOW_MSG_HASH_SIZE];
    memcpy(sig_id, &pkt->payload[SHADOW_COMMON_SIZE], SHADOW_SIG_ID_SIZE);
    memcpy(msg_hash, &pkt->payload[SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE], SHADOW_MSG_HASH_SIZE);
    insertSig(tag, sig_id, msg_hash, now_ms);

    // Release a Message packet that was waiting for this signature.
    for (int i = 0; i < SHADOW_PENDING_MAX; i++) {
      ShadowPendingEntry& e = _pending[i];
      if (!e.used) continue;
      if (memcmp(e.tag, tag, SHADOW_TAG_SIZE) != 0) continue;
      if (memcmp(e.sig_id, sig_id, SHADOW_SIG_ID_SIZE) != 0) continue;
      if (memcmp(e.msg_hash, msg_hash, SHADOW_MSG_HASH_SIZE) != 0) continue;
      uint32_t wait = (uint32_t)(now_ms - e.created_ms);
      if (wait > 0) _ttl.addMsgWait(wait);
      MESH_DEBUG_PRINTLN("SHADOW RX RELEASE pending tag=%02X%02X%02X id=%02X%02X%02X%02X wait=%lu",
                         tag[0], tag[1], tag[2],
                         sig_id[0], sig_id[1], sig_id[2], sig_id[3], (unsigned long)wait);
      releasePending(mesh, i);
      break;
    }
    updateTtls();
  }

  return false;
}

bool ShadowAuth::filterOrdinary(mesh::Mesh& mesh, mesh::Packet* pkt, unsigned long now_ms) {
  (void)mesh;
  if (!enforce()) {
    SHADOW_TRACE_PRINTLN("SHADOW RX PASS ordinary type=%d route=%c len=%d enforce=0",
                         pkt->getPayloadType(), pkt->isRouteDirect() ? 'D' : 'F',
                         pkt->payload_len);
    return false;
  }

  uint8_t type = pkt->getPayloadType();

  if (type == PAYLOAD_TYPE_ANON_REQ) {
    if (!prefs.allow_anon) return drop("anon-disabled", pkt, NULL);
    if (pkt->payload_len < 1 + PUB_KEY_SIZE) return drop("anon-short", pkt, NULL);
    const uint8_t* tag = &pkt->payload[1];
    if (!rateAllow(_rate, "anon", tag, now_ms, 8)) return drop("anon-rate", pkt, tag);
    pkt->auth_ok = true;   // explicit login/admin exception
    SHADOW_TRACE_PRINTLN("SHADOW RX ACCEPT anon tag=%02X%02X%02X",
                         tag[0], tag[1], tag[2]);
    return false;
  }

  if (type == PAYLOAD_TYPE_ADVERT) {
    const uint16_t min_len = PUB_KEY_SIZE + 4 + SIGNATURE_SIZE;
    if (pkt->payload_len < min_len) return drop("advert-short", pkt, NULL);
    const uint8_t* pub = pkt->payload;
    if (!rateAllow(_advert_rate, "advert", pub, now_ms, 8)) return drop("advert-rate", pkt, pub);
    if (!prefs.allow_advert && !contains(pub)) {
      return drop("advert-policy", pkt, pub);
    }
    // Flood and zero-hop adverts are verified by Mesh::onRecvPacket(). A
    // direct transit advert is retransmitted by Mesh before the payload
    // switch, so its signature would otherwise never be checked. Verify it
    // here before granting auth_ok.
    if (pkt->isRouteDirect() && pkt->getPathHashCount() > 0
        && !verifyAdvertPayload(pub, pkt->payload_len)) {
      _bad_sig++;
      return drop("advert-badsig", pkt, pub);
    }
    pkt->auth_ok = true;   // advert's own Ed25519 signature is checked by Mesh
    SHADOW_TRACE_PRINTLN("SHADOW RX ACCEPT advert tag=%02X%02X%02X len=%d",
                         pub[0], pub[1], pub[2], pkt->payload_len);
    return false;
  }

  if (type == PAYLOAD_TYPE_CONTROL) {
    // Discovery is not exempt: under enforcement it must arrive as a signed
    // shadow envelope, so unknown nodes cannot probe for repeaters.
    return drop("control-requires-shadow", pkt, NULL);
  }

  // ACK and every other ordinary payload require a shadow envelope.
  return drop("no-envelope", pkt, NULL);
}

bool ShadowAuth::filter(mesh::Mesh& mesh, mesh::Packet* pkt) {
  if (!prefs.enabled) {
    SHADOW_TRACE_PRINTLN("SHADOW RX PASS disabled type=%d route=%c len=%d",
                         pkt->getPayloadType(), pkt->isRouteDirect() ? 'D' : 'F',
                         pkt->payload_len);
    return false;
  }

  unsigned long now_ms = mesh.getMillis();
  uint8_t tag[SHADOW_TAG_SIZE];
  uint8_t flags = 0;

  if (shadow::hasShadowMarker(pkt)) {
    pkt->shadow = true;
    pkt->shadow_wrapped = true;
    memcpy(tag, &pkt->payload[SHADOW_CH_SIZE + SHADOW_MAGIC_SIZE], SHADOW_TAG_SIZE);
    flags = pkt->payload[SHADOW_COMMON_SIZE - 1];
    pkt->shadow_flags = flags;
    SHADOW_TRACE_PRINTLN("SHADOW RX shadow mode=%s tag=%02X%02X%02X type=%d route=%c len=%d",
                         shadow::modeName(shadow::modeOf(flags)),
                         tag[0], tag[1], tag[2], pkt->getPayloadType(),
                         pkt->isRouteDirect() ? 'D' : 'F', pkt->payload_len);

    if (shadow::versionOf(flags) != SHADOW_VERSION) {
      return enforce() ? drop("bad-version", pkt, tag) : wouldDrop("bad-version", pkt, tag);
    }
    return filterShadow(mesh, pkt, tag, flags, now_ms);
  }

  return filterOrdinary(mesh, pkt, now_ms);
}

void ShadowAuth::sweep(unsigned long now_ms) {
  for (int i = 0; i < SHADOW_PENDING_MAX; i++) {
    ShadowPendingEntry& e = _pending[i];
    if (e.used && (long)(now_ms - e.deadline_ms) >= 0) {
      unsigned long age = now_ms - e.created_ms;
      unsigned long ttl = e.deadline_ms - e.created_ms;
      MESH_DEBUG_PRINTLN("SHADOW RX DROP reason=pending-expired tag=%02X%02X%02X id=%02X%02X%02X%02X age=%lu ttl=%lu",
                         e.tag[0], e.tag[1], e.tag[2],
                         e.sig_id[0], e.sig_id[1], e.sig_id[2], e.sig_id[3],
                         age, ttl);
      e.used = false;
      _dropped++;
    }
  }
  for (int i = 0; i < SHADOW_SIG_CACHE_SIZE; i++) {
    ShadowSigEntry& e = _sig[i];
    if (e.used && (long)(now_ms - e.expiry_ms) >= 0) {
      SHADOW_TRACE_PRINTLN("SHADOW: sig-cache sweep expired tag=%02X%02X%02X id=%02X%02X%02X%02X",
                           e.tag[0], e.tag[1], e.tag[2],
                           e.sig_id[0], e.sig_id[1], e.sig_id[2], e.sig_id[3]);
      e.used = false;
    }
  }
}

void ShadowAuth::poll(mesh::Mesh& mesh, unsigned long now_ms) {
  (void)mesh;
  sweep(now_ms);
  updateTtls();

  if ((unsigned long)(now_ms - _last_persist_ms) >= 3600000UL) {
    _last_persist_ms = now_ms;
    _prefs_dirty = true;
    SHADOW_TRACE_PRINTLN("SHADOW: hourly prefs persist requested");
  }
}

bool ShadowAuth::allow(const uint8_t* pub_key, uint32_t now_epoch) {
  for (int i = 0; i < SHADOW_MAX_ALLOW; i++) {
    if ((_allow[i].flags & 1) && memcmp(_allow[i].pub_key, pub_key, PUB_KEY_SIZE) == 0) {
      _allow[i].last_seen = now_epoch;
      _allow_dirty = true;
      SHADOW_TRACE_PRINTLN("SHADOW ACL refresh tag=%02X%02X%02X count=%d",
                           pub_key[0], pub_key[1], pub_key[2], getNumAllowed());
      return true;
    }
  }
  for (int i = 0; i < SHADOW_MAX_ALLOW; i++) {
    if (!(_allow[i].flags & 1)) {
      memcpy(_allow[i].pub_key, pub_key, PUB_KEY_SIZE);
      _allow[i].flags = 1;
      _allow[i].last_seen = now_epoch;
      _allow_dirty = true;
      MESH_DEBUG_PRINTLN("SHADOW ACL add tag=%02X%02X%02X count=%d",
                         pub_key[0], pub_key[1], pub_key[2], getNumAllowed());
      return true;
    }
  }
  MESH_DEBUG_PRINTLN("SHADOW ACL full tag=%02X%02X%02X",
                     pub_key[0], pub_key[1], pub_key[2]);
  return false;
}

bool ShadowAuth::remove(const uint8_t* pub_key) {
  for (int i = 0; i < SHADOW_MAX_ALLOW; i++) {
    if ((_allow[i].flags & 1) && memcmp(_allow[i].pub_key, pub_key, PUB_KEY_SIZE) == 0) {
      memset(&_allow[i], 0, sizeof(_allow[i]));
      _allow_dirty = true;

      // Revocation must not leave already-verified packets usable.
      _verified.clear();
      for (int k = 0; k < SHADOW_SIG_CACHE_SIZE; k++) {
        if (_sig[k].used && memcmp(_sig[k].tag, pub_key, SHADOW_TAG_SIZE) == 0) _sig[k].used = false;
      }
      for (int k = 0; k < SHADOW_PENDING_MAX; k++) {
        if (_pending[k].used && memcmp(_pending[k].tag, pub_key, SHADOW_TAG_SIZE) == 0) _pending[k].used = false;
      }
      MESH_DEBUG_PRINTLN("SHADOW ACL remove tag=%02X%02X%02X count=%d",
                         pub_key[0], pub_key[1], pub_key[2], getNumAllowed());
      return true;
    }
  }
  SHADOW_TRACE_PRINTLN("SHADOW ACL remove not-found tag=%02X%02X%02X",
                       pub_key[0], pub_key[1], pub_key[2]);
  return false;
}

bool ShadowAuth::contains(const uint8_t* pub_key) const {
  for (int i = 0; i < SHADOW_MAX_ALLOW; i++) {
    if ((_allow[i].flags & 1) && memcmp(_allow[i].pub_key, pub_key, PUB_KEY_SIZE) == 0) return true;
  }
  return false;
}

int ShadowAuth::getNumAllowed() const {
  int n = 0;
  for (int i = 0; i < SHADOW_MAX_ALLOW; i++) if (_allow[i].flags & 1) n++;
  return n;
}

const uint8_t* ShadowAuth::getAllowedKey(int idx) const {
  int n = 0;
  for (int i = 0; i < SHADOW_MAX_ALLOW; i++) {
    if (!(_allow[i].flags & 1)) continue;
    if (n++ == idx) return _allow[i].pub_key;
  }
  return NULL;
}

void ShadowAuth::formatStatus(char* reply, size_t reply_len) const {
  int pending = 0, sigs = 0;
  for (int i = 0; i < SHADOW_PENDING_MAX; i++) if (_pending[i].used) pending++;
  for (int i = 0; i < SHADOW_SIG_CACHE_SIZE; i++) if (_sig[i].used) sigs++;

  snprintf(reply, reply_len,
           "enabled=%d enforce=%d pend=%d/%d sig=%d/%d allow=%d/%d\n"
           "ttl hold=%lu sig=%lu frag=%lu\n"
           "max msg=%lu sig=%lu frag=%lu",
           (int)prefs.enabled, (int)prefs.enforce,
           pending, (int)prefs.pending_max, sigs, SHADOW_SIG_CACHE_SIZE,
           getNumAllowed(), SHADOW_MAX_ALLOW,
           (unsigned long)_hold_ttl_ms, (unsigned long)_sig_ttl_ms,
           (unsigned long)_frag_ttl_ms,
           (unsigned long)_ttl.maxMsgWait(), (unsigned long)_ttl.maxSigWait(),
           (unsigned long)_ttl.maxFragGap());
}

void ShadowAuth::formatStats(char* reply, size_t reply_len) const {
  formatCounters(reply, reply_len, _dropped, _dup_fast, _bad_sig,
                 _would_drop, _pending_evicted);
}

void ShadowAuth::formatCounters(char* reply, size_t reply_len,
                                uint32_t dropped, uint32_t dup_fast,
                                uint32_t bad_sig, uint32_t would_drop,
                                uint32_t pending_evicted) {
  snprintf(reply, reply_len,
           "drop=%lu dup=%lu bad=%lu would=%lu evict=%lu",
           (unsigned long)dropped, (unsigned long)dup_fast,
           (unsigned long)bad_sig, (unsigned long)would_drop,
           (unsigned long)pending_evicted);
}

static bool parseOnOff(const char* value, bool* out) {
  if (strcmp(value, "on") == 0 || strcmp(value, "1") == 0) { *out = true; return true; }
  if (strcmp(value, "off") == 0 || strcmp(value, "0") == 0) { *out = false; return true; }
  return false;
}

bool ShadowAuth::handleCommand(mesh::Mesh& mesh, const char* command, char* reply, size_t reply_len) {
  (void)mesh;
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
    prefs.enabled = b;
    _prefs_dirty = true;
    MESH_DEBUG_PRINTLN("shd.enabled -> %s", b ? "on" : "off");
    snprintf(reply, reply_len, "OK - shadow %s", b ? "enabled" : "disabled");
    return true;
  }
  if (strcmp(name, "shd.enforce") == 0) {
    if (!parseOnOff(args, &b)) { snprintf(reply, reply_len, "Err - on|off"); return true; }
    prefs.enforce = b;
    _prefs_dirty = true;
    MESH_DEBUG_PRINTLN("shd.enforce -> %s", b ? "on" : "off");
    snprintf(reply, reply_len, "OK - enforce %s", b ? "on" : "off");
    return true;
  }
  if (strcmp(name, "shd.allow.anon") == 0) {
    if (!parseOnOff(args, &b)) { snprintf(reply, reply_len, "Err - on|off"); return true; }
    prefs.allow_anon = b;
    _prefs_dirty = true;
    MESH_DEBUG_PRINTLN("shd.allow.anon -> %s", b ? "on" : "off");
    snprintf(reply, reply_len, "OK");
    return true;
  }
  if (strcmp(name, "shd.allow.advert") == 0) {
    if (!parseOnOff(args, &b)) { snprintf(reply, reply_len, "Err - on|off"); return true; }
    prefs.allow_advert = b;
    _prefs_dirty = true;
    MESH_DEBUG_PRINTLN("shd.allow.advert -> %s", b ? "on" : "off");
    snprintf(reply, reply_len, "OK");
    return true;
  }
  if (strcmp(name, "shd.auto.add") == 0) {
    if (!parseOnOff(args, &b)) { snprintf(reply, reply_len, "Err - on|off"); return true; }
    prefs.auto_add = b;
    _prefs_dirty = true;
    MESH_DEBUG_PRINTLN("shd.auto.add -> %s", b ? "on" : "off");
    snprintf(reply, reply_len, "OK");
    return true;
  }
  if (strcmp(name, "shd.pending.max") == 0) {
    unsigned long v = strtoul(args, NULL, 10);
    if (v < 1 || v > SHADOW_PENDING_MAX) { snprintf(reply, reply_len, "Err - 1..%d", SHADOW_PENDING_MAX); return true; }
    prefs.pending_max = (uint8_t)v;
    _prefs_dirty = true;
    MESH_DEBUG_PRINTLN("shd.pending.max -> %u", (unsigned)prefs.pending_max);
    snprintf(reply, reply_len, "OK");
    return true;
  }
  if (strcmp(name, "shd.hold.min") == 0) {
    prefs.hold_min_ms = clampU32(strtoul(args, NULL, 10), 1000, SHADOW_HOLD_MAX_MS);
    if (prefs.hold_max_ms < prefs.hold_min_ms) prefs.hold_max_ms = prefs.hold_min_ms;
    if (prefs.hold_default_ms < prefs.hold_min_ms) prefs.hold_default_ms = prefs.hold_min_ms;
    _prefs_dirty = true;
    updateTtls();
    MESH_DEBUG_PRINTLN("shd.hold.min -> %lu ms (max=%lu default=%lu)",
                       (unsigned long)prefs.hold_min_ms, (unsigned long)prefs.hold_max_ms,
                       (unsigned long)prefs.hold_default_ms);
    snprintf(reply, reply_len, "OK");
    return true;
  }
  if (strcmp(name, "shd.hold.max") == 0) {
    prefs.hold_max_ms = clampU32(strtoul(args, NULL, 10), prefs.hold_min_ms, SHADOW_HOLD_MAX_MS);
    if (prefs.hold_default_ms > prefs.hold_max_ms) prefs.hold_default_ms = prefs.hold_max_ms;
    _prefs_dirty = true;
    updateTtls();
    MESH_DEBUG_PRINTLN("shd.hold.max -> %lu ms (default=%lu)",
                       (unsigned long)prefs.hold_max_ms, (unsigned long)prefs.hold_default_ms);
    snprintf(reply, reply_len, "OK");
    return true;
  }
  if (strcmp(name, "shd.hold.default") == 0) {
    prefs.hold_default_ms = clampU32(strtoul(args, NULL, 10), prefs.hold_min_ms, prefs.hold_max_ms);
    _prefs_dirty = true;
    updateTtls();
    MESH_DEBUG_PRINTLN("shd.hold.default -> %lu ms", (unsigned long)prefs.hold_default_ms);
    snprintf(reply, reply_len, "OK");
    return true;
  }
  if (strcmp(name, "shd.margin") == 0) {
    prefs.margin_ms = clampU32(strtoul(args, NULL, 10), 0, 60000);
    _prefs_dirty = true;
    updateTtls();
    MESH_DEBUG_PRINTLN("shd.margin -> %lu ms", (unsigned long)prefs.margin_ms);
    snprintf(reply, reply_len, "OK");
    return true;
  }
  if (strcmp(name, "shd.status") == 0) {
    formatStatus(reply, reply_len);
    return true;
  }
  if (strcmp(name, "shd.stats") == 0) {
    formatStats(reply, reply_len);
    return true;
  }
  if (strcmp(name, "shd.list") == 0) {
    // The full listing is printed only by the local serial CLI; a mesh reply
    // is too small to carry the whole allowlist.
    snprintf(reply, reply_len, "%d keys", getNumAllowed());
    return true;
  }
  if (strcmp(name, "shd.allow") == 0) {
    uint8_t pub[PUB_KEY_SIZE];
    if (strlen(args) < PUB_KEY_SIZE * 2 || !mesh::Utils::fromHex(pub, PUB_KEY_SIZE, args)) {
      snprintf(reply, reply_len, "Err - bad pubkey");
      return true;
    }
    if (!allow(pub)) { snprintf(reply, reply_len, "Err - allowlist full"); return true; }
    _allow_dirty = true;
    snprintf(reply, reply_len, "OK");
    return true;
  }
  if (strcmp(name, "shd.remove") == 0) {
    uint8_t pub[PUB_KEY_SIZE];
    if (strlen(args) < PUB_KEY_SIZE * 2 || !mesh::Utils::fromHex(pub, PUB_KEY_SIZE, args)) {
      snprintf(reply, reply_len, "Err - bad pubkey");
      return true;
    }
    if (!remove(pub)) { snprintf(reply, reply_len, "Err - not found"); return true; }
    _allow_dirty = true;
    snprintf(reply, reply_len, "OK");
    return true;
  }

  snprintf(reply, reply_len, "Err - unknown shd command");
  return true;
}

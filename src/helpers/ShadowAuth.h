#pragma once

#include <Mesh.h>
#include <helpers/ConfigSerializer.h>
#include <helpers/ShadowPackets.h>

#if defined(ESP32) || defined(RP2040_PLATFORM) || defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  #include <helpers/IdentityStore.h>
  #define SHADOW_AUTH_HAS_FS 1
  typedef FILESYSTEM ShadowFs;
#else
  #define SHADOW_AUTH_HAS_FS 0
  typedef void ShadowFs;
#endif

/**
 * Persisted repeater settings. TTL estimate fields are written once an hour so
 * a reboot starts close to the observed network delays.
 */
class ShadowPrefs : public ConfigSerializer {
public:
  uint8_t  enabled = 1;
  uint8_t  enforce = 0;
  uint8_t  allow_anon = 1;
  uint8_t  allow_advert = 0;
  uint8_t  auto_add = 1;
  uint8_t  pending_max = SHADOW_PENDING_MAX;
  uint32_t hold_min_ms = SHADOW_HOLD_MIN_MS;
  uint32_t hold_max_ms = SHADOW_HOLD_MAX_MS;
  uint32_t hold_default_ms = SHADOW_HOLD_DEFAULT_MS;
  uint32_t margin_ms = SHADOW_MARGIN_MS;
  uint32_t max_msg_wait_ms = 0;
  uint32_t max_sig_wait_ms = 0;
  uint32_t max_frag_gap_ms = 0;
  uint32_t saved_at = 0;
  uint8_t  acl_migrated = 0;   // existing ACL clients already imported

protected:
  void structure() override;
};

struct ShadowAllowEntry {
  uint8_t  pub_key[PUB_KEY_SIZE];
  uint8_t  flags;       // bit 0 = active
  uint32_t last_seen;
};

struct ShadowSigEntry {
  bool     used;
  uint8_t  tag[SHADOW_TAG_SIZE];
  uint8_t  sig_id[SHADOW_SIG_ID_SIZE];
  uint8_t  msg_hash[SHADOW_MSG_HASH_SIZE];
  unsigned long created_ms;
  unsigned long expiry_ms;
};

struct ShadowPendingEntry {
  bool     used;
  uint8_t  tag[SHADOW_TAG_SIZE];
  uint8_t  sig_id[SHADOW_SIG_ID_SIZE];
  uint8_t  msg_hash[SHADOW_MSG_HASH_SIZE];
  unsigned long created_ms;
  unsigned long deadline_ms;
  uint16_t len;
  uint8_t  data[MAX_TRANS_UNIT];
};

class ShadowVerifiedCache {
  uint8_t _hashes[SHADOW_VERIFIED_CACHE_SIZE][SHADOW_MSG_HASH_SIZE];
  bool    _used[SHADOW_VERIFIED_CACHE_SIZE];
  int     _next;
public:
  ShadowVerifiedCache() { clear(); }
  void clear();
  bool contains(const uint8_t* hash) const;
  void insert(const uint8_t* hash);
  int size() const { return SHADOW_VERIFIED_CACHE_SIZE; }
};

/**
 * Sliding window of the largest observed positive delay for each metric.
 */
class ShadowTtlTracker {
  uint32_t _msg[SHADOW_TTL_SAMPLES];
  uint32_t _sig[SHADOW_TTL_SAMPLES];
  uint32_t _frag[SHADOW_TTL_SAMPLES];
  uint8_t  _msg_n, _msg_i;
  uint8_t  _sig_n, _sig_i;
  uint8_t  _frag_n, _frag_i;
public:
  ShadowTtlTracker() { reset(); }
  void reset();
  void addMsgWait(uint32_t ms);
  void addSigWait(uint32_t ms);
  void addFragGap(uint32_t ms);
  uint32_t maxMsgWait() const;
  uint32_t maxSigWait() const;
  uint32_t maxFragGap() const;
};

/**
 * Repeater-side shadow policy: allowlist, signature verification, verified
 * hash cache, detached signature cache, pending message queue and dynamic TTLs.
 */
class ShadowAuth {
  ShadowPrefs prefs;
  ShadowAllowEntry _allow[SHADOW_MAX_ALLOW];
  ShadowVerifiedCache _verified;
  ShadowSigEntry _sig[SHADOW_SIG_CACHE_SIZE];
  ShadowPendingEntry _pending[SHADOW_PENDING_MAX];
  ShadowTtlTracker _ttl;

  struct TagRate {
    uint8_t  tag[SHADOW_TAG_SIZE];
    uint16_t count;
    unsigned long window_ms;
  } _rate[16], _advert_rate[16];

  uint32_t _dropped, _dup_fast, _bad_sig, _would_drop, _pending_evicted;
  bool _prefs_dirty, _allow_dirty;
  unsigned long _last_persist_ms;
  unsigned long _hold_ttl_ms, _sig_ttl_ms, _frag_ttl_ms;
#if SHADOW_AUTH_HAS_FS
  FILESYSTEM* _fs;
#endif

  void updateTtls();
  bool rateAllow(TagRate* table, const uint8_t* tag, unsigned long now_ms, uint16_t max_per_min);
  int  findByTag(const uint8_t* tag, int* idxs, int max_idx) const;
  ShadowSigEntry* findSig(const uint8_t* tag, const uint8_t* sig_id, unsigned long now_ms);
  void insertSig(const uint8_t* tag, const uint8_t* sig_id, const uint8_t* msg_hash, unsigned long now_ms);
  void releasePending(mesh::Mesh& mesh, int idx);
  void sweep(unsigned long now_ms);
  bool verifyWithCandidates(const uint8_t* tag, const uint8_t* signature,
                            const uint8_t digest[SHADOW_DIGEST_SIZE]);
  bool filterShadow(mesh::Mesh& mesh, mesh::Packet* pkt, const uint8_t* tag, uint8_t flags, unsigned long now_ms);
  bool filterOrdinary(mesh::Mesh& mesh, mesh::Packet* pkt, unsigned long now_ms);

  bool loadPrefs(ShadowFs* fs);
  bool loadAllowList(ShadowFs* fs);
  bool saveAllowList(ShadowFs* fs);

public:
  ShadowAuth();

  void begin(ShadowFs* fs, uint32_t now_epoch);
  void begin() { begin((ShadowFs*)NULL, 0); }
  bool savePrefs(ShadowFs* fs);
  bool saveAllowListNow(ShadowFs* fs) { return saveAllowList(fs); }

  bool enabled() const { return prefs.enabled != 0; }
  bool enforce() const { return prefs.enforce != 0; }
  ShadowPrefs& getPrefs() { return prefs; }

  /**
   * Early receive filter. Return true to DROP the packet before it enters the
   * delayed inbound queue. Verified packets get Packet::auth_ok = true.
   */
  bool filter(mesh::Mesh& mesh, mesh::Packet* pkt);

  /**
   * Housekeeping: expire pending/signature entries, refresh TTLs and mark
   * persisted estimates dirty once an hour.
   */
  void poll(mesh::Mesh& mesh, unsigned long now_ms);

  bool needsSave() const { return _prefs_dirty || _allow_dirty; }
  void clearSaveFlag() { _prefs_dirty = _allow_dirty = false; }
  void markPrefsDirty() { _prefs_dirty = true; }

  bool allow(const uint8_t* pub_key, uint32_t now_epoch = 0);
  bool remove(const uint8_t* pub_key);
  bool contains(const uint8_t* pub_key) const;
  int  getNumAllowed() const;
  const uint8_t* getAllowedKey(int idx) const;

  void formatStatus(char* reply, size_t reply_len) const;
  bool handleCommand(mesh::Mesh& mesh, const char* command, char* reply, size_t reply_len);
};

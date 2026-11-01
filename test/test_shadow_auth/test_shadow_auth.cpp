#include <gtest/gtest.h>
#include <helpers/ShadowAuth.h>
#include <helpers/ShadowNode.h>
#include <helpers/SimpleMeshTables.h>
#include <helpers/TransportKeyStore.h>
#include <helpers/RegionMap.h>

#include <string.h>
#include <stdio.h>
#include <stdint.h>

using namespace mesh;

namespace {

class TestClock : public MillisecondClock {
public:
  unsigned long now = 1000;
  unsigned long getMillis() override { return now; }
};

class TestRng : public RNG {
  uint32_t state = 0x12345678;
public:
  void random(uint8_t* dest, size_t sz) override {
    for (size_t i = 0; i < sz; i++) {
      state = state * 1664525u + 1013904223u;
      dest[i] = (uint8_t)(state >> 24);
    }
  }
};

class TestRtc : public RTCClock {
public:
  uint32_t getCurrentTime() override { return 1000; }
  void setCurrentTime(uint32_t) override { }
};

class TestRadio : public Radio {
public:
  int recvRaw(uint8_t*, int) override { return 0; }
  uint32_t getEstAirtimeFor(int) override { return 10; }
  float packetScore(float, int) override { return 1.0f; }
  bool startSendRaw(const uint8_t*, int) override { return true; }
  bool isSendComplete() override { return true; }
  void onSendFinished() override { }
  bool isInRecvMode() const override { return true; }
};

class TestPacketManager : public PacketManager {
  static const int POOL = 64;
  Packet _pool[POOL];
  bool _used[POOL];
  Packet* _out[POOL];
  uint32_t _due[POOL];
  int _out_n;
  Packet* _in[16];
  uint32_t _in_due[16];
  int _in_n;

public:
  TestPacketManager() : _out_n(0), _in_n(0) {
    memset(_used, 0, sizeof(_used));
    memset(_out, 0, sizeof(_out));
    memset(_in, 0, sizeof(_in));
  }

  Packet* allocNew() override {
    for (int i = 0; i < POOL; i++) {
      if (!_used[i]) {
        _used[i] = true;
        Packet* p = &_pool[i];
        p->header = 0; p->payload_len = 0; p->path_len = 0;
        p->shadow = false; p->shadow_wrapped = false; p->auth_ok = false;
        p->recv_filtered = false; p->local_only = false; p->shadow_unwrapped = false;
        p->shadow_flags = 0;
        return p;
      }
    }
    return NULL;
  }
  void free(Packet* p) override {
    for (int i = 0; i < POOL; i++) if (&_pool[i] == p) { _used[i] = false; return; }
  }
  void queueOutbound(Packet* p, uint8_t, uint32_t due) override {
    if (_out_n < POOL) { _out[_out_n] = p; _due[_out_n] = due; _out_n++; }
  }
  Packet* getNextOutbound(uint32_t now) override {
    for (int i = 0; i < _out_n; i++) {
      if ((long)(now - _due[i]) >= 0) {
        Packet* p = _out[i];
        for (int k = i + 1; k < _out_n; k++) { _out[k-1] = _out[k]; _due[k-1] = _due[k]; }
        _out_n--;
        return p;
      }
    }
    return NULL;
  }
  int getOutboundCount(uint32_t now) const override {
    int n = 0;
    for (int i = 0; i < _out_n; i++) if ((long)(now - _due[i]) >= 0) n++;
    return n;
  }
  int getOutboundTotal() const override { return _out_n; }
  int getFreeCount() const override {
    int n = 0;
    for (int i = 0; i < POOL; i++) if (!_used[i]) n++;
    return n;
  }
  Packet* getOutboundByIdx(int i) override { return i < _out_n ? _out[i] : NULL; }
  Packet* removeOutboundByIdx(int i) override {
    if (i >= _out_n) return NULL;
    Packet* p = _out[i];
    for (int k = i + 1; k < _out_n; k++) { _out[k-1] = _out[k]; _due[k-1] = _due[k]; }
    _out_n--;
    return p;
  }
  void queueInbound(Packet* p, uint32_t due) override {
    if (_in_n < 16) { _in[_in_n] = p; _in_due[_in_n] = due; _in_n++; }
  }
  Packet* getNextInbound(uint32_t now) override {
    for (int i = 0; i < _in_n; i++) {
      if ((long)(now - _in_due[i]) >= 0) {
        Packet* p = _in[i];
        for (int k = i + 1; k < _in_n; k++) { _in[k-1] = _in[k]; _in_due[k-1] = _in_due[k]; }
        _in_n--;
        return p;
      }
    }
    return NULL;
  }
  int inboundCount() const { return _in_n; }
  int outboundCount() const { return _out_n; }
};

class TestMesh : public Mesh {
public:
  TestMesh(TestRadio& radio, TestClock& clock, TestRng& rng, TestRtc& rtc, TestPacketManager& mgr, SimpleMeshTables& tables)
    : Mesh(radio, clock, rng, rtc, mgr, tables), _mgr(&mgr) {
    for (int i = 0; i < PUB_KEY_SIZE; i++) self_id.pub_key[i] = (uint8_t)(0x40 + i);
  }

  DispatcherAction recv(mesh::Packet* p) { return Mesh::onRecvPacket(p); }

private:
  TestPacketManager* _mgr;
};

// A node that also repeats: used to verify that local processing does not
// cause the unwrapped payload to be retransmitted instead of the envelope.
class ForwardingTestMesh : public TestMesh {
public:
  int adverts = 0;

  ForwardingTestMesh(TestRadio& radio, TestClock& clock, TestRng& rng, TestRtc& rtc,
                     TestPacketManager& mgr, SimpleMeshTables& tables)
    : TestMesh(radio, clock, rng, rtc, mgr, tables) {}

  bool allowPacketForward(const mesh::Packet*) override { return true; }
  DispatcherAction recv(mesh::Packet* p) { return Mesh::onRecvPacket(p); }

  void onAdvertRecv(mesh::Packet*, const mesh::Identity&, uint32_t,
                    const uint8_t*, size_t) override {
    adverts++;
  }
};

class GroupForwardingTestMesh : public TestMesh {
public:
  GroupChannel channel;
  int groups = 0;

  GroupForwardingTestMesh(TestRadio& radio, TestClock& clock, TestRng& rng, TestRtc& rtc,
                          TestPacketManager& mgr, SimpleMeshTables& tables)
    : TestMesh(radio, clock, rng, rtc, mgr, tables) {}

  bool allowPacketForward(const mesh::Packet*) override { return true; }
  DispatcherAction recv(mesh::Packet* p) { return Mesh::onRecvPacket(p); }

  int searchChannelsByHash(const uint8_t* hash, GroupChannel channels[], int max_matches) override {
    if (max_matches < 1 || memcmp(hash, channel.hash, PATH_HASH_SIZE) != 0) return 0;
    channels[0] = channel;
    return 1;
  }

  void onGroupDataRecv(mesh::Packet*, uint8_t, const GroupChannel&, uint8_t*, size_t) override {
    groups++;
  }
};

// Endpoint that answers an incoming request with a locally generated reply.
// Used to verify which transport envelope ShadowNode picks for that reply.
class ReplyTestMesh : public TestMesh {
public:
  uint8_t peer_secret[PUB_KEY_SIZE];
  mesh::Identity reply_dest;
  uint8_t reply_path[1] = { 0 };
  uint8_t reply_type = PAYLOAD_TYPE_RESPONSE;
  int replies = 0;

  ReplyTestMesh(TestRadio& radio, TestClock& clock, TestRng& rng, TestRtc& rtc,
                TestPacketManager& mgr, SimpleMeshTables& tables)
    : TestMesh(radio, clock, rng, rtc, mgr, tables) {
    memset(peer_secret, 0x5A, sizeof(peer_secret));
  }

  int searchPeersByHash(const uint8_t*) override { return 1; }

  void getPeerSharedSecret(uint8_t* dest_secret, int) override {
    memcpy(dest_secret, peer_secret, PUB_KEY_SIZE);
  }

  void onPeerDataRecv(mesh::Packet*, uint8_t type, int, const uint8_t* secret,
                      uint8_t*, size_t) override {
    if (type == PAYLOAD_TYPE_REQ || type == PAYLOAD_TYPE_TXT_MSG) {
      sendReply(secret);
    }
  }

  void onAnonDataRecv(mesh::Packet*, const uint8_t* secret,
                      const mesh::Identity&, uint8_t*, size_t) override {
    sendReply(secret);
  }

private:
  void sendReply(const uint8_t* secret) {
    uint8_t data[4] = { 0x42, 0x43, 0x44, 0x45 };
    mesh::Packet* reply = createDatagram(reply_type, reply_dest, secret, data, sizeof(data));
    if (reply != NULL) {
      sendDirect(reply, reply_path, 0);
      replies++;
    }
  }
};

static Packet* wrapOne(TestMesh& mesh, TestPacketManager& mgr, const uint8_t* payload, uint16_t len,
                       uint8_t type = PAYLOAD_TYPE_RAW_CUSTOM) {
  Packet* inner = mesh.createRawData(payload, len);
  if (inner == NULL) return NULL;
  inner->header = (uint8_t)((type << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  mesh.sendPacket(inner, 0, 0);
  Packet* out = mgr.getNextOutbound(100000);
  return out;
}

static void copyRaw(const Packet* src, Packet* dst) {
  uint8_t raw[MAX_TRANS_UNIT];
  uint8_t len = src->writeTo(raw);
  ASSERT_TRUE(dst->readFrom(raw, len));
}

class PrefsWriteStream : public Stream {
  char _buf[1024];
  size_t _len = 0;

  size_t printSigned(long long value) {
    char text[24];
    snprintf(text, sizeof(text), "%lld", value);
    return Print::print(text);
  }

  size_t printUnsigned(unsigned long long value) {
    char text[24];
    snprintf(text, sizeof(text), "%llu", value);
    return Print::print(text);
  }

public:
  size_t write(uint8_t b) override {
    if (_len + 1 >= sizeof(_buf)) return 0;
    _buf[_len++] = (char)b;
    _buf[_len] = 0;
    return 1;
  }

  size_t print(unsigned char v, int) override { return printUnsigned(v); }
  size_t print(int v, int) override { return printSigned(v); }
  size_t print(unsigned int v, int) override { return printUnsigned(v); }
  size_t print(long v, int) override { return printSigned(v); }
  size_t print(unsigned long v, int) override { return printUnsigned(v); }
  size_t print(long long v, int) override { return printSigned(v); }
  size_t print(unsigned long long v, int) override { return printUnsigned(v); }
  size_t print(double v, int p = 2) override {
    char text[32];
    snprintf(text, sizeof(text), "%.*f", p, v);
    return Print::print(text);
  }

  const char* data() const { return _buf; }
};

class PrefsReadStream : public Stream {
  const char* _text;
  int _pos = 0;
  int _len;

public:
  explicit PrefsReadStream(const char* text) : _text(text), _len((int)strlen(text)) { }
  int available() override { return _len - _pos; }
  int read() override { return _pos < _len ? (uint8_t)_text[_pos++] : -1; }
  int peek() override { return _pos < _len ? (uint8_t)_text[_pos] : -1; }
};

} // namespace

TEST(ShadowConstants, SizesMatchPlan) {
  EXPECT_EQ(SHADOW_TAG_SIZE, 3);
  EXPECT_EQ(SHADOW_VERSION, 1);
  EXPECT_EQ(SHADOW_MAX_ALLOW, 128);
  EXPECT_EQ(SHADOW_PENDING_MAX, 24);
  EXPECT_EQ(SHADOW_VERIFIED_CACHE_SIZE, 256);
  EXPECT_EQ(SHADOW_COMMON_SIZE, 7);
  EXPECT_EQ(SHADOW_EMBEDDED_OVERHEAD, 72);
  EXPECT_EQ(SHADOW_SIG_PACKET_SIZE, 91);
  EXPECT_EQ(SHADOW_MSG_OVERHEAD, 12);
  EXPECT_EQ(SHADOW_FRAG_OVERHEAD, 78);
  EXPECT_EQ(SHADOW_MAX_INNER_EMBEDDED, 112);
  EXPECT_EQ(SHADOW_MAX_INNER_MSG, 172);
  EXPECT_EQ(SHADOW_MAX_FRAG_PAYLOAD, 106);
}

TEST(ShadowPrefs, SerializationRoundTrip) {
  ShadowPrefs saved;
  saved.enabled = 1;
  saved.enforce = 1;
  saved.allow_anon = 0;
  saved.allow_advert = 1;
  saved.auto_add = 0;
  saved.pending_max = 7;
  saved.hold_min_ms = 5000;
  saved.hold_max_ms = 120000;
  saved.hold_default_ms = 45000;
  saved.margin_ms = 3000;
  saved.max_msg_wait_ms = 4200;
  saved.max_sig_wait_ms = 9100;
  saved.max_frag_gap_ms = 1500;
  saved.saved_at = 123456789;
  saved.acl_migrated = 1;

  PrefsWriteStream out;
  ASSERT_TRUE(saved.saveSerial(out));

  // Persisted keys must use the ConfigSerializer charset; a dotted key makes
  // the whole file unreadable after a reboot.
  EXPECT_NE(strstr(out.data(), "shd_enforce:1"), nullptr);
  EXPECT_EQ(strchr(out.data(), '.'), nullptr);

  ShadowPrefs loaded;
  PrefsReadStream in(out.data());
  ASSERT_TRUE(loaded.loadSerial(in));

  EXPECT_EQ(loaded.enabled, saved.enabled);
  EXPECT_EQ(loaded.enforce, saved.enforce);
  EXPECT_EQ(loaded.allow_anon, saved.allow_anon);
  EXPECT_EQ(loaded.allow_advert, saved.allow_advert);
  EXPECT_EQ(loaded.auto_add, saved.auto_add);
  EXPECT_EQ(loaded.pending_max, saved.pending_max);
  EXPECT_EQ(loaded.hold_min_ms, saved.hold_min_ms);
  EXPECT_EQ(loaded.hold_max_ms, saved.hold_max_ms);
  EXPECT_EQ(loaded.hold_default_ms, saved.hold_default_ms);
  EXPECT_EQ(loaded.margin_ms, saved.margin_ms);
  EXPECT_EQ(loaded.max_msg_wait_ms, saved.max_msg_wait_ms);
  EXPECT_EQ(loaded.max_sig_wait_ms, saved.max_sig_wait_ms);
  EXPECT_EQ(loaded.max_frag_gap_ms, saved.max_frag_gap_ms);
  EXPECT_EQ(loaded.saved_at, saved.saved_at);
  EXPECT_EQ(loaded.acl_migrated, saved.acl_migrated);
}

TEST(ShadowVerifiedCache, InsertContainsEvicts) {
  ShadowVerifiedCache cache;
  uint8_t h[SHADOW_MSG_HASH_SIZE];
  memset(h, 0xEE, sizeof(h));
  EXPECT_FALSE(cache.contains(h));
  cache.insert(h);
  EXPECT_TRUE(cache.contains(h));

  for (int i = 0; i < SHADOW_VERIFIED_CACHE_SIZE + 3; i++) {
    uint8_t x[SHADOW_MSG_HASH_SIZE];
    memset(x, 0xAB, sizeof(x));
    x[0] = (uint8_t)i;
    x[1] = (uint8_t)(i >> 8);
    cache.insert(x);
  }
  EXPECT_FALSE(cache.contains(h));   // evicted
}

TEST(ShadowTtlTracker, DefaultsAndClampMath) {
  ShadowTtlTracker t;
  EXPECT_EQ(t.maxMsgWait(), 0u);
  t.addMsgWait(4200);
  t.addMsgWait(1800);
  EXPECT_EQ(t.maxMsgWait(), 4200u);
  t.addSigWait(900);
  EXPECT_EQ(t.maxSigWait(), 900u);
  t.addFragGap(700);
  EXPECT_EQ(t.maxFragGap(), 700u);
  t.reset();
  EXPECT_EQ(t.maxMsgWait(), 0u);
}

TEST(ShadowAuth, AllowListAddRemove) {
  ShadowAuth auth;
  auth.begin();
  uint8_t pub[PUB_KEY_SIZE];
  memset(pub, 0x22, sizeof(pub));
  EXPECT_FALSE(auth.contains(pub));
  EXPECT_TRUE(auth.allow(pub));
  EXPECT_TRUE(auth.contains(pub));
  EXPECT_EQ(auth.getNumAllowed(), 1);
  EXPECT_TRUE(auth.remove(pub));
  EXPECT_FALSE(auth.contains(pub));
}

TEST(ShadowAuth, AllowListCapacity) {
  ShadowAuth auth;
  auth.begin();

  uint8_t pub[PUB_KEY_SIZE];
  for (int i = 0; i < SHADOW_MAX_ALLOW; i++) {
    memset(pub, 0, sizeof(pub));
    pub[0] = (uint8_t)(i >> 8);
    pub[1] = (uint8_t)i;
    pub[2] = 0x5A;
    ASSERT_TRUE(auth.allow(pub)) << "slot " << i;
  }
  EXPECT_EQ(auth.getNumAllowed(), SHADOW_MAX_ALLOW);

  uint8_t extra[PUB_KEY_SIZE];
  memset(extra, 0xFF, sizeof(extra));
  EXPECT_FALSE(auth.allow(extra));
  EXPECT_EQ(auth.getNumAllowed(), SHADOW_MAX_ALLOW);

  uint8_t first[PUB_KEY_SIZE];
  memset(first, 0, sizeof(first));
  first[2] = 0x5A;
  ASSERT_TRUE(auth.remove(first));
  EXPECT_EQ(auth.getNumAllowed(), SHADOW_MAX_ALLOW - 1);
  EXPECT_TRUE(auth.allow(extra));
  EXPECT_EQ(auth.getNumAllowed(), SHADOW_MAX_ALLOW);
}

TEST(ShadowAuth, StatusIncludesAllowListAndFits) {
  ShadowAuth auth;
  auth.begin();
  uint8_t pub[PUB_KEY_SIZE];
  memset(pub, 0x42, sizeof(pub));
  ASSERT_TRUE(auth.allow(pub));

  char buf[160];
  memset(buf, 0, sizeof(buf));
  auth.formatStatus(buf, sizeof(buf));

  EXPECT_LT(strlen(buf), sizeof(buf));
  EXPECT_NE(strstr(buf, "enabled=1"), nullptr);
  char expected[32];
  snprintf(expected, sizeof(expected), "allow=1/%d", SHADOW_MAX_ALLOW);
  EXPECT_NE(strstr(buf, expected), nullptr);
  // Counters live in shd.stats now; status must stay short and stable.
  EXPECT_EQ(strstr(buf, "drop="), nullptr);
  EXPECT_EQ(strstr(buf, "evict="), nullptr);
}

TEST(ShadowAuth, StatusReportsEnabledState) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc;
  TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);

  ShadowAuth auth;
  auth.begin();
  char buf[160];

  ASSERT_TRUE(auth.handleCommand(mesh, "shd.enabled off", buf, sizeof(buf)));
  auth.formatStatus(buf, sizeof(buf));
  EXPECT_NE(strstr(buf, "enabled=0"), nullptr);

  ASSERT_TRUE(auth.handleCommand(mesh, "shd.enabled on", buf, sizeof(buf)));
  auth.formatStatus(buf, sizeof(buf));
  EXPECT_NE(strstr(buf, "enabled=1"), nullptr);
}

TEST(ShadowAuth, StatsFitLargeCounters) {
  char buf[160];
  ShadowAuth::formatCounters(buf, sizeof(buf),
                             UINT32_MAX, UINT32_MAX, UINT32_MAX,
                             UINT32_MAX, UINT32_MAX);
  EXPECT_LT(strlen(buf), sizeof(buf));
  EXPECT_NE(strstr(buf, "drop=4294967295"), nullptr);
  EXPECT_NE(strstr(buf, "evict=4294967295"), nullptr);
}

TEST(ShadowAuth, StatsCommandReportsCounters) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc;
  TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);

  ShadowAuth auth;
  auth.begin();
  char buf[160];
  ASSERT_TRUE(auth.handleCommand(mesh, "shd.stats", buf, sizeof(buf)));
  EXPECT_NE(strstr(buf, "drop=0"), nullptr);
  EXPECT_NE(strstr(buf, "evict=0"), nullptr);
}

TEST(ShadowAuth, TagCollisionTriesAllCandidates) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;

  // Add a fake key sharing the sender's 3-byte tag *before* the real key, so
  // verification has to iterate past the first candidate.
  uint8_t fake[PUB_KEY_SIZE];
  memcpy(fake, mesh.self_id.pub_key, PUB_KEY_SIZE);
  fake[PUB_KEY_SIZE - 1] ^= 0xFF;
  ASSERT_EQ(memcmp(fake, mesh.self_id.pub_key, SHADOW_TAG_SIZE), 0);
  ASSERT_TRUE(auth.allow(fake));
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  const uint8_t payload[] = "tag collision";
  Packet* out = wrapOne(mesh, mgr, payload, sizeof(payload));
  ASSERT_NE(out, nullptr);

  Packet parsed;
  copyRaw(out, &parsed);
  EXPECT_FALSE(auth.filter(mesh, &parsed));
  EXPECT_TRUE(parsed.auth_ok);
}

TEST(ShadowAuth, EmbeddedPacketAcceptedAndMarkedAuth) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  const uint8_t payload[] = "hello shadow";
  Packet* out = wrapOne(mesh, mgr, payload, sizeof(payload));
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(out->getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_EQ(out->payload_len, SHADOW_EMBEDDED_OVERHEAD + sizeof(payload));

  Packet parsed;
  copyRaw(out, &parsed);
  EXPECT_FALSE(auth.filter(mesh, &parsed));
  EXPECT_TRUE(parsed.auth_ok);
}

TEST(ShadowAuth, BadSignatureDroppedWhenEnforcing) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  const uint8_t payload[] = "hello";
  Packet* out = wrapOne(mesh, mgr, payload, sizeof(payload));
  ASSERT_NE(out, nullptr);
  out->payload[out->payload_len - 1] ^= 0xFF;   // corrupt signature

  Packet parsed;
  copyRaw(out, &parsed);
  EXPECT_TRUE(auth.filter(mesh, &parsed));
}

TEST(ShadowAuth, DetachedSignatureFirstThenMessage) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  uint8_t payload[140];
  memset(payload, 0x5A, sizeof(payload));

  Packet* inner = mesh.createRawData(payload, sizeof(payload));
  ASSERT_NE(inner, nullptr);
  inner->header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  mesh.sendPacket(inner, 0, 0);

  // Detached sends the signature first, message 300ms later.
  Packet* sig = mgr.getNextOutbound(100000);
  Packet* msg = mgr.getNextOutbound(100000);
  ASSERT_NE(sig, nullptr);
  ASSERT_NE(msg, nullptr);

  Packet p;
  copyRaw(sig, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));
  EXPECT_TRUE(p.auth_ok);
  copyRaw(msg, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));
  EXPECT_TRUE(p.auth_ok);
}

TEST(ShadowAuth, MessageBeforeSignatureIsHeldThenReleased) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  uint8_t payload[140];
  memset(payload, 0xA5, sizeof(payload));

  Packet* inner = mesh.createRawData(payload, sizeof(payload));
  ASSERT_NE(inner, nullptr);
  inner->header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  mesh.sendPacket(inner, 0, 0);

  Packet* sig = mgr.getNextOutbound(100000);
  Packet* msg = mgr.getNextOutbound(100000);
  ASSERT_NE(sig, nullptr);
  ASSERT_NE(msg, nullptr);

  Packet p;
  copyRaw(msg, &p);
  EXPECT_TRUE(auth.filter(mesh, &p));       // held in pending
  EXPECT_EQ(mgr.inboundCount(), 0);

  copyRaw(sig, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));      // signature verifies and releases pending
  EXPECT_EQ(mgr.inboundCount(), 1);

  Packet* held = mgr.getNextInbound(100000);
  ASSERT_NE(held, nullptr);
  EXPECT_TRUE(held->auth_ok);
  EXPECT_TRUE(held->shadow);
  EXPECT_EQ(held->getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_EQ(held->payload_len, SHADOW_MSG_OVERHEAD + sizeof(payload));
}

static mesh::Packet* makeWrappedAdvert(TestMesh& mesh, TestPacketManager& mgr, uint8_t app_len) {
  uint8_t app[MAX_ADVERT_DATA_SIZE];
  memset(app, 0x7A, app_len);
  mesh::Packet* adv = mesh.createAdvert(mesh.self_id, app, app_len);
  if (adv == nullptr) return nullptr;
  adv->header = (uint8_t)((adv->header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  adv->path_len = 0;
  mesh.sendPacket(adv, 0, 0);
  return mgr.getNextOutbound(100000);
}

static mesh::Packet* makeScopedAdvert(TestMesh& mesh, TestPacketManager& mgr, ShadowNode& node,
                                      const TransportKey& key, uint8_t app_len,
                                      uint8_t path_hash_size = 1) {
  uint8_t app[MAX_ADVERT_DATA_SIZE];
  memset(app, 0x6B, app_len);
  mesh::Packet* adv = mesh.createAdvert(mesh.self_id, app, app_len);
  if (adv == nullptr) return nullptr;
  adv->path_len = 0;

  uint16_t codes[2];
  codes[0] = key.calcTransportCode(adv);
  codes[1] = 0;
  node.setTransportKey(key.key);
  mesh.sendFlood(adv, codes, 0, path_hash_size);
  node.setTransportKey(NULL);
  return mgr.getNextOutbound(100000);
}

static mesh::Packet* makeScopedRaw(TestMesh& mesh, TestPacketManager& mgr, ShadowNode& node,
                                   const TransportKey& key, uint8_t path_hash_size,
                                   const uint8_t* payload, uint16_t len) {
  mesh::Packet* inner = mesh.createRawData(payload, len);
  if (inner == nullptr) return nullptr;
  inner->header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;

  uint16_t codes[2];
  codes[0] = key.calcTransportCode(inner);
  codes[1] = 0;
  node.setTransportKey(key.key);
  mesh.sendFlood(inner, codes, 0, path_hash_size);
  node.setTransportKey(NULL);
  return mgr.getNextOutbound(100000);
}

TEST(ShadowNode, AdvertUsesEmbeddedOrDetachedAndNeverFragments) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  node.setMode(SHADOW_MODE_FRAGMENT);   // must still not fragment adverts
  mesh.setShadowSendHook(&node);

  // Empty app data -> inner 100 -> embedded.
  Packet* out = makeWrappedAdvert(mesh, mgr, 0);
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(out->getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_EQ(shadow::modeOf(out->shadow_flags), SHADOW_MODE_EMBEDDED);
  EXPECT_EQ(out->payload_len, SHADOW_EMBEDDED_OVERHEAD + PUB_KEY_SIZE + 4 + SIGNATURE_SIZE);
  EXPECT_LE(out->payload_len, MAX_PACKET_PAYLOAD);
  EXPECT_LE(out->getRawLength(), MAX_TRANS_UNIT);
  EXPECT_EQ(mgr.getNextOutbound(100000), nullptr);

  // Full app data -> inner 132 -> detached (signature packet + message).
  Packet* sig = makeWrappedAdvert(mesh, mgr, MAX_ADVERT_DATA_SIZE);
  ASSERT_NE(sig, nullptr);
  EXPECT_EQ(shadow::modeOf(sig->shadow_flags), SHADOW_MODE_SIGNATURE);
  EXPECT_EQ(sig->payload_len, SHADOW_SIG_PACKET_SIZE);
  Packet* msg = mgr.getNextOutbound(100000);
  ASSERT_NE(msg, nullptr);
  EXPECT_EQ(shadow::modeOf(msg->shadow_flags), SHADOW_MODE_MESSAGE);
  EXPECT_EQ(msg->payload_len, SHADOW_MSG_OVERHEAD + PUB_KEY_SIZE + 4 + SIGNATURE_SIZE + MAX_ADVERT_DATA_SIZE);
  EXPECT_LE(sig->getRawLength(), MAX_TRANS_UNIT);
  EXPECT_LE(msg->getRawLength(), MAX_TRANS_UNIT);
  EXPECT_EQ(mgr.getNextOutbound(100000), nullptr);
}

TEST(ShadowAuth, OpenAdvertAllowsUnlistedSender) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 1;
  uint8_t other[PUB_KEY_SIZE];
  memset(other, 0x99, sizeof(other));
  ASSERT_TRUE(auth.allow(other));   // sender is intentionally not allowlisted

  Packet* sig = makeWrappedAdvert(mesh, mgr, MAX_ADVERT_DATA_SIZE);
  ASSERT_NE(sig, nullptr);
  Packet* msg = mgr.getNextOutbound(100000);
  ASSERT_NE(msg, nullptr);

  Packet p;
  copyRaw(sig, &p);
  EXPECT_TRUE(auth.filter(mesh, &p));    // unknown shadow signature packet: dropped
  copyRaw(msg, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));   // message is allowed by inner advert signature
  EXPECT_TRUE(p.auth_ok);
}

TEST(ShadowAuth, CachedOpenAdvertRespectsPolicyChange) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 1;
  uint8_t other[PUB_KEY_SIZE];
  memset(other, 0x99, sizeof(other));
  ASSERT_TRUE(auth.allow(other));

  Packet* out = makeWrappedAdvert(mesh, mgr, 0);
  ASSERT_NE(out, nullptr);

  Packet p;
  copyRaw(out, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));   // open discovery verifies and caches
  EXPECT_TRUE(p.auth_ok);

  auth.getPrefs().allow_advert = 0;
  copyRaw(out, &p);
  EXPECT_TRUE(auth.filter(mesh, &p));    // cached advert must now honour the allowlist
}

TEST(ShadowAuth, OpenAdvertRejectsBadInnerSignature) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 1;

  Packet* out = makeWrappedAdvert(mesh, mgr, 0);   // embedded
  ASSERT_NE(out, nullptr);
  // inner starts at payload[7]; advert signature is at inner+36.
  out->payload[SHADOW_COMMON_SIZE + 1 + PUB_KEY_SIZE + 4] ^= 0xFF;

  Packet p;
  copyRaw(out, &p);
  EXPECT_TRUE(auth.filter(mesh, &p));
}

TEST(ShadowAuth, AllowAdvertOffRejectsBadInnerSignatureFromAllowlisted) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 0;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  Packet* out = makeWrappedAdvert(mesh, mgr, 0);
  ASSERT_NE(out, nullptr);
  out->payload[SHADOW_COMMON_SIZE + 1 + PUB_KEY_SIZE + 4] ^= 0xFF;

  Packet p;
  copyRaw(out, &p);
  EXPECT_TRUE(auth.filter(mesh, &p));
}

TEST(ShadowAuth, AllowAdvertOffRequiresAllowlistForWrappedAdvert) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 0;
  uint8_t other[PUB_KEY_SIZE];
  memset(other, 0x99, sizeof(other));
  ASSERT_TRUE(auth.allow(other));

  Packet* out = makeWrappedAdvert(mesh, mgr, 0);
  ASSERT_NE(out, nullptr);
  Packet p;
  copyRaw(out, &p);
  EXPECT_TRUE(auth.filter(mesh, &p));
}

TEST(ShadowAuth, AllowAdvertOffAllowsAllowlistedWrappedAdvert) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 0;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  Packet* sig = makeWrappedAdvert(mesh, mgr, MAX_ADVERT_DATA_SIZE);
  ASSERT_NE(sig, nullptr);
  Packet* msg = mgr.getNextOutbound(100000);
  ASSERT_NE(msg, nullptr);

  Packet p;
  copyRaw(sig, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));
  EXPECT_TRUE(p.auth_ok);
  copyRaw(msg, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));
  EXPECT_TRUE(p.auth_ok);
}

TEST(ShadowNode, RepeaterUnwrapsOnlyZeroHopAdvert) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(mesh.self_id, rng);
  tx.setEnabled(true);
  mesh.setShadowSendHook(&tx);

  Packet* out = makeWrappedAdvert(mesh, mgr, 0);
  ASSERT_NE(out, nullptr);

  // Capture the original inner advert for comparison.
  uint8_t inner_payload[MAX_PACKET_PAYLOAD];
  uint16_t inner_len = out->payload_len - SHADOW_EMBEDDED_OVERHEAD;
  memcpy(inner_payload, &out->payload[SHADOW_COMMON_SIZE + 1], inner_len);

  ShadowNode rx(mesh.self_id, rng);
  rx.setEnabled(true);
  rx.setUnwrapAll(false);   // repeater behaviour

  Packet p;
  copyRaw(out, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT);
  p.path_len = 0;           // zero-hop
  EXPECT_FALSE(rx.unwrapAndProcess(mesh, &p));
  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_ADVERT);
  EXPECT_EQ(p.payload_len, inner_len);
  EXPECT_EQ(memcmp(p.payload, inner_payload, inner_len), 0);

  copyRaw(out, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  EXPECT_FALSE(rx.unwrapAndProcess(mesh, &p));
  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_GRP_TXT);   // flood advert stays wrapped

  copyRaw(out, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT);
  p.path_len = 1;
  p.path[0] = 0x42;
  EXPECT_FALSE(rx.unwrapAndProcess(mesh, &p));
  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_GRP_TXT);   // direct transit stays wrapped
}

TEST(ShadowNode, CompanionUnwrapsFloodAdvert) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(mesh.self_id, rng);
  tx.setEnabled(true);
  mesh.setShadowSendHook(&tx);

  Packet* out = makeWrappedAdvert(mesh, mgr, 0);
  ASSERT_NE(out, nullptr);

  ShadowNode rx(mesh.self_id, rng);
  rx.setEnabled(true);
  rx.setUnwrapAll(true);

  Packet p;
  copyRaw(out, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  EXPECT_FALSE(rx.unwrapAndProcess(mesh, &p));
  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_ADVERT);
}

TEST(ShadowAuth, OrdinaryAdvertPolicyUnchanged) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;

  uint8_t app[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  Packet* adv = mesh.createAdvert(mesh.self_id, app, sizeof(app));
  ASSERT_NE(adv, nullptr);
  adv->header = (uint8_t)((adv->header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  adv->path_len = 0;

  auth.getPrefs().allow_advert = 0;
  Packet p;
  copyRaw(adv, &p);
  EXPECT_TRUE(auth.filter(mesh, &p));   // not allowlisted

  auth.getPrefs().allow_advert = 1;
  copyRaw(adv, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));  // open discovery
  EXPECT_TRUE(p.auth_ok);

  mesh.releasePacket(adv);
}

TEST(ShadowAuth, UnknownTagDropped) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  uint8_t other[PUB_KEY_SIZE];
  memset(other, 0x99, sizeof(other));
  ASSERT_TRUE(auth.allow(other));

  const uint8_t payload[] = "not allowed";
  Packet* out = wrapOne(mesh, mgr, payload, sizeof(payload));
  ASSERT_NE(out, nullptr);

  Packet parsed;
  copyRaw(out, &parsed);
  EXPECT_TRUE(auth.filter(mesh, &parsed));   // sender tag is not on the allowlist
}

TEST(ShadowAuth, EnforceOffForwardsUnverified) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 0;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  uint8_t payload[140];
  memset(payload, 0x33, sizeof(payload));
  Packet* inner = mesh.createRawData(payload, sizeof(payload));
  ASSERT_NE(inner, nullptr);
  inner->header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  mesh.sendPacket(inner, 0, 0);

  Packet* sig = mgr.getNextOutbound(100000);
  Packet* msg = mgr.getNextOutbound(100000);
  ASSERT_NE(sig, nullptr);
  ASSERT_NE(msg, nullptr);

  Packet p;
  copyRaw(msg, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));   // no signature yet, but enforcement is off
  EXPECT_FALSE(p.auth_ok);
}

TEST(ShadowNode, OutOfOrderFragments) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  uint8_t payload[180];
  for (int i = 0; i < (int)sizeof(payload); i++) payload[i] = (uint8_t)(i ^ 0x5A);

  Packet* inner = sender.createRawData(payload, sizeof(payload));
  ASSERT_NE(inner, nullptr);
  inner->header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  sender.sendPacket(inner, 0, 0);

  ShadowNode rx(sender.self_id, rng);
  rx.setEnabled(true);
  rx.setUnwrapAll(true);

  Packet* f0 = mgr.getNextOutbound(100000);
  Packet* f1 = mgr.getNextOutbound(100000);
  ASSERT_NE(f0, nullptr);
  ASSERT_NE(f1, nullptr);

  Packet p;
  copyRaw(f1, &p);
  EXPECT_TRUE(rx.unwrapAndProcess(sender, &p));   // second fragment first
  copyRaw(f0, &p);
  EXPECT_FALSE(rx.unwrapAndProcess(sender, &p));  // complete
  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_RAW_CUSTOM);
  EXPECT_EQ(p.payload_len, sizeof(payload));
  EXPECT_EQ(memcmp(p.payload, payload, sizeof(payload)), 0);
}

TEST(ShadowNode, FragmentReassembly) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  uint8_t payload[180];
  for (int i = 0; i < (int)sizeof(payload); i++) payload[i] = (uint8_t)i;

  Packet* inner = sender.createRawData(payload, sizeof(payload));
  ASSERT_NE(inner, nullptr);
  inner->header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  sender.sendPacket(inner, 0, 0);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  ASSERT_TRUE(auth.allow(sender.self_id.pub_key));

  ShadowNode rx(sender.self_id, rng);
  rx.setEnabled(true);
  rx.setUnwrapAll(true);

  Packet p;
  Packet* frag = mgr.getNextOutbound(100000);
  ASSERT_NE(frag, nullptr);
  copyRaw(frag, &p);
  EXPECT_FALSE(auth.filter(sender, &p));   // repeater verifies fragment
  EXPECT_TRUE(p.auth_ok);
  EXPECT_TRUE(rx.unwrapAndProcess(sender, &p));  // partial fragment consumed

  frag = mgr.getNextOutbound(100000);
  ASSERT_NE(frag, nullptr);
  copyRaw(frag, &p);
  EXPECT_FALSE(auth.filter(sender, &p));
  EXPECT_TRUE(p.auth_ok);
  EXPECT_FALSE(rx.unwrapAndProcess(sender, &p)); // complete, packet rewritten
  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_RAW_CUSTOM);
  EXPECT_EQ(p.payload_len, sizeof(payload));
  EXPECT_EQ(memcmp(p.payload, payload, sizeof(payload)), 0);
}

TEST(ShadowNode, ScopedTransportCodeMatchesWirePayload) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  TransportKey key;
  for (int i = 0; i < (int)sizeof(key.key); i++) key.key[i] = (uint8_t)(0x30 + i);

  // Embedded advert: the outer code must match the standard region formula
  // over the final wire packet, including the shadow signature.
  Packet* out = makeScopedAdvert(mesh, mgr, node, key, 0);
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(out->getRouteType(), ROUTE_TYPE_TRANSPORT_FLOOD);
  EXPECT_EQ(key.calcTransportCode(out), out->transport_codes[0]);
  EXPECT_EQ(shadow::modeOf(out->shadow_flags), SHADOW_MODE_EMBEDDED);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 1;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  Packet p;
  copyRaw(out, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));
  EXPECT_TRUE(p.auth_ok);

  // Detached advert: both the signature packet and the message packet must
  // carry a code computed over their own final payload.
  Packet* sig = makeScopedAdvert(mesh, mgr, node, key, MAX_ADVERT_DATA_SIZE);
  ASSERT_NE(sig, nullptr);
  EXPECT_EQ(key.calcTransportCode(sig), sig->transport_codes[0]);
  Packet* msg = mgr.getNextOutbound(100000);
  ASSERT_NE(msg, nullptr);
  EXPECT_EQ(key.calcTransportCode(msg), msg->transport_codes[0]);

  // Fragments: each fragment has its own signature and therefore its own code.
  uint8_t payload[180];
  memset(payload, 0x55, sizeof(payload));
  Packet* inner = mesh.createRawData(payload, sizeof(payload));
  ASSERT_NE(inner, nullptr);
  inner->header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  uint16_t codes[2];
  codes[0] = key.calcTransportCode(inner);
  codes[1] = 0;
  node.setTransportKey(key.key);
  mesh.sendFlood(inner, codes, 0, 1);
  node.setTransportKey(NULL);

  Packet* f0 = mgr.getNextOutbound(100000);
  Packet* f1 = mgr.getNextOutbound(100000);
  ASSERT_NE(f0, nullptr);
  ASSERT_NE(f1, nullptr);
  EXPECT_EQ(key.calcTransportCode(f0), f0->transport_codes[0]);
  EXPECT_EQ(key.calcTransportCode(f1), f1->transport_codes[0]);
}

TEST(ShadowAuth, OpenAdvertAllowsEmbeddedUnlistedSender) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 1;

  Packet* out = makeWrappedAdvert(mesh, mgr, 0);
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(shadow::modeOf(out->shadow_flags), SHADOW_MODE_EMBEDDED);

  Packet p;
  copyRaw(out, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));
  EXPECT_TRUE(p.auth_ok);
}

TEST(ShadowAuth, OpenAdvertRejectsTagMismatch) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 1;

  Packet* out = makeWrappedAdvert(mesh, mgr, 0);
  ASSERT_NE(out, nullptr);

  Packet p;
  copyRaw(out, &p);
  p.payload[SHADOW_CH_SIZE + SHADOW_MAGIC_SIZE] ^= 0xFF;   // outer tag
  EXPECT_TRUE(auth.filter(mesh, &p));
}

TEST(ShadowAuth, AdvertRateLimitIsSeparateFromTransit) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  // Eight ordinary shadow messages exhaust the transit budget (max 300, but
  // the advert budget must stay independent).
  for (int i = 0; i < 8; i++) {
    uint8_t payload[8] = { (uint8_t)i, 1, 2, 3, 4, 5, 6, 7 };
    Packet* out = wrapOne(mesh, mgr, payload, sizeof(payload));
    ASSERT_NE(out, nullptr);
    Packet p;
    copyRaw(out, &p);
    EXPECT_FALSE(auth.filter(mesh, &p));
  }

  Packet* adv = makeWrappedAdvert(mesh, mgr, 0);
  ASSERT_NE(adv, nullptr);
  Packet p;
  copyRaw(adv, &p);
  EXPECT_FALSE(auth.filter(mesh, &p));
  EXPECT_TRUE(p.auth_ok);
}

TEST(ShadowAuth, AdvertRateLimitRejectsNinthAdvert) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 1;

  Packet first;
  for (int i = 0; i < 9; i++) {
    uint8_t app[1] = { (uint8_t)(0x30 + i) };
    mesh::Packet* adv = mesh.createAdvert(mesh.self_id, app, sizeof(app));
    ASSERT_NE(adv, nullptr);
    adv->header = (uint8_t)((adv->header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
    adv->path_len = 0;
    mesh.sendPacket(adv, 0, 0);
    Packet* out = mgr.getNextOutbound(100000);
    ASSERT_NE(out, nullptr);

    Packet p;
    copyRaw(out, &p);
    if (i == 0) first = p;
    if (i < 8) {
      EXPECT_FALSE(auth.filter(mesh, &p));
    } else {
      EXPECT_TRUE(auth.filter(mesh, &p));   // ninth advert exceeds 8/min
    }
  }

  // The fast-path cache is intentionally checked before the advert rate
  // limiter: an exact duplicate does not consume another advert slot.
  EXPECT_FALSE(auth.filter(mesh, &first));
}

TEST(ShadowAuth, DirectAdvertRequiresValidSignature) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 0;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  uint8_t app[1] = { 0x42 };
  Packet* adv = mesh.createAdvert(mesh.self_id, app, sizeof(app));
  ASSERT_NE(adv, nullptr);

  Packet valid;
  copyRaw(adv, &valid);
  valid.header = (uint8_t)((valid.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT);
  valid.path_len = 1;
  valid.path[0] = 0x42;
  EXPECT_FALSE(auth.filter(mesh, &valid));
  EXPECT_TRUE(valid.auth_ok);

  Packet bad;
  copyRaw(adv, &bad);
  bad.header = (uint8_t)((bad.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT);
  bad.path_len = 1;
  bad.path[0] = 0x42;
  bad.payload[PUB_KEY_SIZE + 4] ^= 0xFF;   // corrupt Ed25519 signature
  EXPECT_TRUE(auth.filter(mesh, &bad));

  mesh.releasePacket(adv);
}

TEST(ShadowNode, RepeatEnabledCompanionForwardsOriginalEnvelope) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  Packet* out = makeWrappedAdvert(sender, mgr, 0);
  ASSERT_NE(out, nullptr);

  SimpleMeshTables rx_tables;
  ForwardingTestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  for (int i = 0; i < PUB_KEY_SIZE; i++) rx.self_id.pub_key[i] = (uint8_t)(0xA0 + i);
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(true);
  rx_node.setUnwrapAll(true);
  rx_node.setForwardEnvelopes(true);
  rx.setShadowRecvHook(&rx_node);

  Packet p;
  copyRaw(out, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;

  DispatcherAction action = rx.recv(&p);
  EXPECT_NE(action, ACTION_RELEASE);
  EXPECT_EQ(rx.adverts, 1);                       // processed locally
  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_EQ(p.payload_len, out->payload_len);     // original envelope restored
  EXPECT_EQ(memcmp(p.payload, out->payload, out->payload_len), 0);
  EXPECT_EQ(p.getPathHashCount(), 1);             // forwarding path appended
}

TEST(Mesh, BaseRepeaterForwardsWrappedAdvert) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  Packet* out = makeWrappedAdvert(sender, mgr, 0);
  ASSERT_NE(out, nullptr);

  SimpleMeshTables base_tables;
  ForwardingTestMesh base(radio, clock, rng, rtc, mgr, base_tables);   // no shadow hook
  Packet p;
  copyRaw(out, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;

  DispatcherAction action = base.recv(&p);
  EXPECT_NE(action, ACTION_RELEASE);
  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_EQ(p.payload_len, out->payload_len);
  EXPECT_EQ(memcmp(p.payload, out->payload, out->payload_len), 0);
  EXPECT_LE(p.getRawLength(), MAX_TRANS_UNIT);
}

TEST(ShadowNode, RepeatCompanionForwardsFragments) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  uint8_t payload[180];
  for (int i = 0; i < (int)sizeof(payload); i++) payload[i] = (uint8_t)(i ^ 0x5A);
  Packet* inner = sender.createRawData(payload, sizeof(payload));
  ASSERT_NE(inner, nullptr);
  inner->header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  sender.sendPacket(inner, 0, 0);

  Packet* f0 = mgr.getNextOutbound(100000);
  Packet* f1 = mgr.getNextOutbound(100000);
  ASSERT_NE(f0, nullptr);
  ASSERT_NE(f1, nullptr);

  SimpleMeshTables rx_tables;
  ForwardingTestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  for (int i = 0; i < PUB_KEY_SIZE; i++) rx.self_id.pub_key[i] = (uint8_t)(0xA0 + i);
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(true);
  rx_node.setUnwrapAll(true);
  rx_node.setForwardEnvelopes(true);
  rx.setShadowRecvHook(&rx_node);

  Packet p;
  copyRaw(f0, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  DispatcherAction a0 = rx.recv(&p);
  EXPECT_NE(a0, ACTION_RELEASE);
  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_EQ(p.payload_len, f0->payload_len);
  EXPECT_EQ(memcmp(p.payload, f0->payload, f0->payload_len), 0);

  copyRaw(f1, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  DispatcherAction a1 = rx.recv(&p);
  EXPECT_NE(a1, ACTION_RELEASE);
  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_EQ(p.payload_len, f1->payload_len);
  EXPECT_EQ(memcmp(p.payload, f1->payload, f1->payload_len), 0);

  ASSERT_EQ(mgr.inboundCount(), 1);
  Packet* local = mgr.getNextInbound(100000);
  ASSERT_NE(local, nullptr);
  EXPECT_TRUE(local->local_only);
  EXPECT_EQ(local->getPayloadType(), PAYLOAD_TYPE_RAW_CUSTOM);
  EXPECT_EQ(local->payload_len, sizeof(payload));
  EXPECT_EQ(memcmp(local->payload, payload, sizeof(payload)), 0);

  // Local-only reassembled traffic must never be retransmitted.
  DispatcherAction local_action = rx.recv(local);
  EXPECT_EQ(local_action, ACTION_RELEASE);
  rx.releasePacket(local);
}

TEST(ShadowNode, RepeatCompanionForwardsFragmentsOutOfOrder) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  uint8_t payload[180];
  for (int i = 0; i < (int)sizeof(payload); i++) payload[i] = (uint8_t)(i ^ 0xA5);
  Packet* inner = sender.createRawData(payload, sizeof(payload));
  ASSERT_NE(inner, nullptr);
  inner->header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  sender.sendPacket(inner, 0, 0);
  Packet* f0 = mgr.getNextOutbound(100000);
  Packet* f1 = mgr.getNextOutbound(100000);
  ASSERT_NE(f0, nullptr);
  ASSERT_NE(f1, nullptr);

  SimpleMeshTables rx_tables;
  ForwardingTestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  for (int i = 0; i < PUB_KEY_SIZE; i++) rx.self_id.pub_key[i] = (uint8_t)(0xB0 + i);
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(true);
  rx_node.setUnwrapAll(true);
  rx_node.setForwardEnvelopes(true);
  rx.setShadowRecvHook(&rx_node);

  Packet p;
  copyRaw(f1, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  EXPECT_NE(rx.recv(&p), ACTION_RELEASE);
  EXPECT_EQ(mgr.inboundCount(), 0);
  EXPECT_EQ(p.payload_len, f1->payload_len);
  EXPECT_EQ(memcmp(p.payload, f1->payload, f1->payload_len), 0);

  copyRaw(f0, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  EXPECT_NE(rx.recv(&p), ACTION_RELEASE);
  EXPECT_EQ(p.payload_len, f0->payload_len);
  EXPECT_EQ(memcmp(p.payload, f0->payload, f0->payload_len), 0);

  ASSERT_EQ(mgr.inboundCount(), 1);
  Packet* local = mgr.getNextInbound(100000);
  ASSERT_NE(local, nullptr);
  EXPECT_TRUE(local->local_only);
  EXPECT_EQ(local->getPayloadType(), PAYLOAD_TYPE_RAW_CUSTOM);
  EXPECT_EQ(local->payload_len, sizeof(payload));
  EXPECT_EQ(memcmp(local->payload, payload, sizeof(payload)), 0);
  rx.releasePacket(local);
}

TEST(ShadowNode, RepeatCompanionForwardsDuplicateFragment) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  uint8_t payload[180];
  memset(payload, 0x3C, sizeof(payload));
  Packet* inner = sender.createRawData(payload, sizeof(payload));
  ASSERT_NE(inner, nullptr);
  inner->header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  sender.sendPacket(inner, 0, 0);
  Packet* f0 = mgr.getNextOutbound(100000);
  Packet* f1 = mgr.getNextOutbound(100000);
  ASSERT_NE(f0, nullptr);
  ASSERT_NE(f1, nullptr);

  SimpleMeshTables rx_tables;
  ForwardingTestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  for (int i = 0; i < PUB_KEY_SIZE; i++) rx.self_id.pub_key[i] = (uint8_t)(0xC0 + i);
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(true);
  rx_node.setUnwrapAll(true);
  rx_node.setForwardEnvelopes(true);

  Packet p;
  copyRaw(f0, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  EXPECT_FALSE(rx_node.unwrapAndProcess(rx, &p));
  EXPECT_EQ(p.payload_len, f0->payload_len);
  EXPECT_EQ(memcmp(p.payload, f0->payload, f0->payload_len), 0);
  EXPECT_EQ(mgr.inboundCount(), 0);

  // Same fragment again: no local delivery until the set is complete.
  EXPECT_FALSE(rx_node.unwrapAndProcess(rx, &p));
  EXPECT_EQ(p.payload_len, f0->payload_len);
  EXPECT_EQ(mgr.inboundCount(), 0);

  copyRaw(f1, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  EXPECT_FALSE(rx_node.unwrapAndProcess(rx, &p));
  EXPECT_EQ(mgr.inboundCount(), 1);

  Packet* local = mgr.getNextInbound(100000);
  ASSERT_NE(local, nullptr);
  EXPECT_TRUE(local->local_only);
  EXPECT_EQ(local->payload_len, sizeof(payload));
  EXPECT_EQ(memcmp(local->payload, payload, sizeof(payload)), 0);
  rx.releasePacket(local);
}

TEST(ShadowNode, RepeatCompanionForwardsDetachedAdvert) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  Packet* sig = makeWrappedAdvert(sender, mgr, MAX_ADVERT_DATA_SIZE);
  ASSERT_NE(sig, nullptr);
  Packet* msg = mgr.getNextOutbound(100000);
  ASSERT_NE(msg, nullptr);

  SimpleMeshTables rx_tables;
  ForwardingTestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  for (int i = 0; i < PUB_KEY_SIZE; i++) rx.self_id.pub_key[i] = (uint8_t)(0xA0 + i);
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(true);
  rx_node.setUnwrapAll(true);
  rx_node.setForwardEnvelopes(true);
  rx.setShadowRecvHook(&rx_node);

  Packet p;
  copyRaw(sig, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  EXPECT_NE(rx.recv(&p), ACTION_RELEASE);
  EXPECT_EQ(rx.adverts, 0);
  EXPECT_EQ(p.payload_len, sig->payload_len);
  EXPECT_EQ(memcmp(p.payload, sig->payload, sig->payload_len), 0);

  copyRaw(msg, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  EXPECT_NE(rx.recv(&p), ACTION_RELEASE);
  EXPECT_EQ(rx.adverts, 1);
  EXPECT_EQ(p.payload_len, msg->payload_len);
  EXPECT_EQ(memcmp(p.payload, msg->payload, msg->payload_len), 0);
}

TEST(ShadowNode, RepeatCompanionForwardsGroupMessage) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  GroupChannel channel;
  memset(channel.hash, 0, sizeof(channel.hash));
  channel.hash[0] = 0x42;
  memset(channel.secret, 0x33, sizeof(channel.secret));

  const uint8_t data[] = { 'h', 'e', 'l', 'l', 'o' };
  Packet* inner = sender.createGroupDatagram(PAYLOAD_TYPE_GRP_TXT, channel, data, sizeof(data));
  ASSERT_NE(inner, nullptr);
  inner->header = (uint8_t)((inner->header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  sender.sendPacket(inner, 0, 0);
  Packet* out = mgr.getNextOutbound(100000);
  ASSERT_NE(out, nullptr);

  SimpleMeshTables rx_tables;
  GroupForwardingTestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  rx.channel = channel;
  for (int i = 0; i < PUB_KEY_SIZE; i++) rx.self_id.pub_key[i] = (uint8_t)(0xA0 + i);
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(true);
  rx_node.setUnwrapAll(true);
  rx_node.setForwardEnvelopes(true);
  rx.setShadowRecvHook(&rx_node);

  Packet p;
  copyRaw(out, &p);
  p.header = (uint8_t)((p.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  EXPECT_NE(rx.recv(&p), ACTION_RELEASE);
  EXPECT_EQ(rx.groups, 1);
  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_EQ(p.payload_len, out->payload_len);
  EXPECT_EQ(memcmp(p.payload, out->payload, out->payload_len), 0);
}

TEST(Mesh, LocalOnlyPacketIsNotForwarded) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  ForwardingTestMesh mesh(radio, clock, rng, rtc, mgr, tables);

  Packet p;
  p.header = (uint8_t)((PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  p.payload_len = 3;
  p.payload[0] = 0x11;
  p.payload[1] = 0x22;
  p.payload[2] = 0x33;
  p.local_only = true;

  EXPECT_EQ(mesh.recv(&p), ACTION_RELEASE);
}

TEST(Mesh, LocalOnlyDirectPacketIsNotForwarded) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  ForwardingTestMesh mesh(radio, clock, rng, rtc, mgr, tables);

  uint8_t self_hash[PATH_HASH_SIZE];
  mesh.self_id.copyHashTo(self_hash);

  Packet p;
  p.header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_DIRECT);
  p.path_len = 1;
  p.path[0] = self_hash[0];
  p.payload_len = 1;
  p.payload[0] = 0x42;
  p.local_only = true;

  EXPECT_EQ(mesh.recv(&p), ACTION_RELEASE);
}

TEST(Mesh, LocalOnlyTraceIsNotForwarded) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  ForwardingTestMesh mesh(radio, clock, rng, rtc, mgr, tables);

  uint8_t self_hash[PATH_HASH_SIZE];
  mesh.self_id.copyHashTo(self_hash);

  Packet p;
  memset(&p, 0, sizeof(p));
  p.header = (uint8_t)((PAYLOAD_TYPE_TRACE << PH_TYPE_SHIFT) | ROUTE_TYPE_DIRECT);
  p.path_len = 0;
  p.payload_len = 10;
  p.payload[8] = 0;          // path hash size = 1
  p.payload[9] = self_hash[0];
  p.local_only = true;

  EXPECT_EQ(mesh.recv(&p), ACTION_RELEASE);
}

TEST(Mesh, ScopedShadowAdvertMatchesRegionMap) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  TransportKeyStore key_store;
  RegionMap map(key_store);
  RegionEntry* region_a = map.putRegion("alpha", 0);
  RegionEntry* region_b = map.putRegion("bravo", 0);
  ASSERT_NE(region_a, nullptr);
  ASSERT_NE(region_b, nullptr);
  region_a->flags = 0;
  region_b->flags = 0;

  TransportKey keys_a[1], keys_b[1];
  ASSERT_EQ(map.getTransportKeysFor(*region_a, keys_a, 1), 1);
  ASSERT_EQ(map.getTransportKeysFor(*region_b, keys_b, 1), 1);

  Packet* out_a = makeScopedAdvert(mesh, mgr, node, keys_a[0], 0);
  Packet* out_b = makeScopedAdvert(mesh, mgr, node, keys_b[0], 0);
  ASSERT_NE(out_a, nullptr);
  ASSERT_NE(out_b, nullptr);
  EXPECT_EQ(map.findMatch(out_a, REGION_DENY_FLOOD), region_a);
  EXPECT_EQ(map.findMatch(out_b, REGION_DENY_FLOOD), region_b);

  // A region that denies flood must not match even with a valid code.
  region_a->flags = REGION_DENY_FLOOD;
  EXPECT_EQ(map.findMatch(out_a, REGION_DENY_FLOOD), nullptr);
  EXPECT_EQ(map.findMatch(out_b, REGION_DENY_FLOOD), region_b);

  // Zero transport code selects the wildcard region.
  Packet wildcard_packet;
  memset(&wildcard_packet, 0, sizeof(wildcard_packet));
  wildcard_packet.transport_codes[0] = 0;
  EXPECT_EQ(map.findMatch(&wildcard_packet, REGION_DENY_FLOOD), &map.getWildcard());

  // Corrupted transport code must not match either region.
  Packet bad;
  copyRaw(out_a, &bad);
  bad.transport_codes[0] = (uint16_t)(bad.transport_codes[0] + 1);
  EXPECT_EQ(map.findMatch(&bad, REGION_DENY_FLOOD), nullptr);
}

TEST(ShadowAuth, SigCacheEvictionPicksOldest) {
  ShadowSigEntry entries[4];
  memset(entries, 0, sizeof(entries));
  for (int i = 0; i < 4; i++) {
    entries[i].used = true;
    entries[i].expiry_ms = (unsigned long)(30 - i * 10);   // 30, 20, 10, 0
  }
  EXPECT_EQ(ShadowAuth::oldestSigSlot(entries, 4), 3);

  entries[3].expiry_ms = 100;   // slot 0 is oldest again? 30,20,10,100 -> index 2
  EXPECT_EQ(ShadowAuth::oldestSigSlot(entries, 4), 2);

  entries[1].used = false;
  EXPECT_EQ(ShadowAuth::oldestSigSlot(entries, 4), 1);

  memset(entries, 0, sizeof(entries));
  EXPECT_EQ(ShadowAuth::oldestSigSlot(entries, 4), 0);
}

TEST(ShadowAuth, FragmentAdvertFromUnknownDropped) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 1;

  Packet p;
  memset(&p, 0, sizeof(p));
  p.header = (uint8_t)((PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  p.path_len = 0;
  p.payload_len = SHADOW_FRAG_OVERHEAD + 4;
  uint8_t tag[SHADOW_TAG_SIZE] = { 0xAA, 0xBB, 0xCC };
  shadow::writeCommon(p.payload, tag, SHADOW_MODE_FRAGMENT);

  EXPECT_TRUE(auth.filter(mesh, &p));
}

TEST(ShadowNode, RepeaterForwardsFragmentsUnchanged) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  uint8_t payload[180];
  memset(payload, 0x44, sizeof(payload));
  Packet* inner = sender.createRawData(payload, sizeof(payload));
  ASSERT_NE(inner, nullptr);
  inner->header = (uint8_t)((PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD);
  inner->path_len = 0;
  sender.sendPacket(inner, 0, 0);
  Packet* f0 = mgr.getNextOutbound(100000);
  Packet* f1 = mgr.getNextOutbound(100000);
  ASSERT_NE(f0, nullptr);
  ASSERT_NE(f1, nullptr);

  ShadowNode rx(sender.self_id, rng);
  rx.setEnabled(true);
  rx.setUnwrapAll(false);   // simple repeater

  Packet p;
  copyRaw(f0, &p);
  EXPECT_FALSE(rx.unwrapAndProcess(sender, &p));
  EXPECT_EQ(p.payload_len, f0->payload_len);
  EXPECT_EQ(memcmp(p.payload, f0->payload, f0->payload_len), 0);

  copyRaw(f1, &p);
  EXPECT_FALSE(rx.unwrapAndProcess(sender, &p));
  EXPECT_EQ(p.payload_len, f1->payload_len);
  EXPECT_EQ(memcmp(p.payload, f1->payload, f1->payload_len), 0);
}

TEST(ShadowNode, PathHashSizesPreserved) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  TransportKey key;
  for (int i = 0; i < (int)sizeof(key.key); i++) key.key[i] = (uint8_t)(0x60 + i);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 1;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  for (uint8_t size = 1; size <= 3; size++) {
    Packet* out = makeScopedAdvert(mesh, mgr, node, key, 0, size);
    ASSERT_NE(out, nullptr) << "size=" << (int)size;
    EXPECT_EQ(out->getPathHashSize(), size);
    EXPECT_EQ(out->getPathHashCount(), 0);
    EXPECT_EQ(key.calcTransportCode(out), out->transport_codes[0]);

    Packet parsed;
    copyRaw(out, &parsed);
    EXPECT_FALSE(auth.filter(mesh, &parsed)) << "size=" << (int)size;
    EXPECT_TRUE(parsed.auth_ok);

    // Detached advert: ensure both packets preserve the configured path size.
    Packet* sig = makeScopedAdvert(mesh, mgr, node, key, MAX_ADVERT_DATA_SIZE, size);
    ASSERT_NE(sig, nullptr);
    Packet* msg = mgr.getNextOutbound(100000);
    ASSERT_NE(msg, nullptr);
    EXPECT_EQ(sig->getPathHashSize(), size);
    EXPECT_EQ(msg->getPathHashSize(), size);
    EXPECT_EQ(key.calcTransportCode(sig), sig->transport_codes[0]);
    EXPECT_EQ(key.calcTransportCode(msg), msg->transport_codes[0]);
  }
}

TEST(ShadowAuth, PathModeTamperDropped) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  const uint8_t payload[] = "path-mode";
  Packet* out = wrapOne(mesh, mgr, payload, sizeof(payload));
  ASSERT_NE(out, nullptr);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  Packet p;
  copyRaw(out, &p);
  p.path_len = (uint8_t)((p.path_len & 0x3F) | (1 << 6));   // change 1-byte -> 2-byte hash size
  EXPECT_TRUE(auth.filter(mesh, &p));

  auth.getPrefs().enforce = 0;
  Packet q;
  copyRaw(out, &q);
  q.path_len = (uint8_t)((q.path_len & 0x3F) | (1 << 6));
  EXPECT_FALSE(auth.filter(mesh, &q));   // transitional mode: count, then forward
  EXPECT_FALSE(q.auth_ok);
}

TEST(ShadowAuth, PathBytesMutationStillAccepted) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  const uint8_t payload[] = "path-bytes";
  Packet* out = wrapOne(mesh, mgr, payload, sizeof(payload));
  ASSERT_NE(out, nullptr);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  Packet p;
  copyRaw(out, &p);
  p.path_len = 1;                 // one path hash, same 1-byte hash size
  p.path[0] = 0x5A;               // path bytes are not part of the signature
  EXPECT_FALSE(auth.filter(mesh, &p));
  EXPECT_TRUE(p.auth_ok);
}

TEST(Mesh, ForwardingPreservesPathHashSize) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(sender.self_id, rng);
  node.setEnabled(true);
  sender.setShadowSendHook(&node);

  TransportKey key;
  for (int i = 0; i < (int)sizeof(key.key); i++) key.key[i] = (uint8_t)(0x90 + i);

  const uint8_t payload[] = { 'p', 'a', 't', 'h' };
  for (uint8_t size = 1; size <= 3; size++) {
    Packet* out = makeScopedRaw(sender, mgr, node, key, size, payload, sizeof(payload));
    ASSERT_NE(out, nullptr) << "size=" << (int)size;

    SimpleMeshTables base_tables;
    ForwardingTestMesh base(radio, clock, rng, rtc, mgr, base_tables);
    Packet p;
    copyRaw(out, &p);
    EXPECT_NE(base.recv(&p), ACTION_RELEASE) << "size=" << (int)size;
    EXPECT_EQ(p.getPathHashSize(), size);
    EXPECT_EQ(p.getPathHashCount(), 1);
    EXPECT_EQ(p.path_len >> 6, (uint8_t)(size - 1));

    ShadowAuth auth;
    auth.begin();
    auth.getPrefs().enabled = 1;
    auth.getPrefs().enforce = 1;
    ASSERT_TRUE(auth.allow(sender.self_id.pub_key));
    EXPECT_FALSE(auth.filter(sender, &p)) << "size=" << (int)size;
    EXPECT_TRUE(p.auth_ok);
  }
}

TEST(ShadowAuth, AdvertPathModeMutationStillAccepted) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  TransportKey key;
  for (int i = 0; i < (int)sizeof(key.key); i++) key.key[i] = (uint8_t)(0xA0 + i);
  Packet* out = makeScopedAdvert(mesh, mgr, node, key, 0, 1);
  ASSERT_NE(out, nullptr);

  ShadowAuth auth;
  auth.begin();
  auth.getPrefs().enabled = 1;
  auth.getPrefs().enforce = 1;
  auth.getPrefs().allow_advert = 1;
  ASSERT_TRUE(auth.allow(mesh.self_id.pub_key));

  Packet p;
  copyRaw(out, &p);
  p.path_len = (uint8_t)((p.path_len & 0x3F) | (1 << 6));   // 1-byte -> 2-byte hash size

  // Wrapped adverts are authenticated by the inner advert signature only; the
  // outer shadow signature (and therefore path mode) is not checked.
  EXPECT_FALSE(auth.filter(mesh, &p));
  EXPECT_TRUE(p.auth_ok);
}

static void setTestPubKey(TestMesh& mesh, uint8_t base) {
  for (int i = 0; i < PUB_KEY_SIZE; i++) mesh.self_id.pub_key[i] = (uint8_t)(base + i);
}

TEST(ShadowNode, TxDisabledStillUnwrapsIncomingEnvelope) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  SimpleMeshTables rx_tables;
  TestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  setTestPubKey(rx, 0xA0);
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(false);       // shd.enabled off on a companion ...
  rx_node.setRxEnabled(true);      // ... but RX stays available
  rx_node.setUnwrapAll(true);
  rx.setShadowRecvHook(&rx_node);

  uint8_t secret[PUB_KEY_SIZE];
  memset(secret, 0x33, sizeof(secret));
  uint8_t data[4] = { 1, 2, 3, 4 };
  Packet* inner = sender.createDatagram(PAYLOAD_TYPE_RESPONSE, rx.self_id, secret, data, sizeof(data));
  ASSERT_NE(inner, nullptr);
  uint8_t path[1] = { 0 };
  sender.sendDirect(inner, path, 0);

  Packet* out = mgr.getNextOutbound(100000);
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(out->getPayloadType(), PAYLOAD_TYPE_GRP_TXT);

  Packet p;
  copyRaw(out, &p);
  rx.recv(&p);

  EXPECT_EQ(p.getPayloadType(), PAYLOAD_TYPE_RESPONSE);
  EXPECT_FALSE(p.shadow);
  EXPECT_TRUE(p.shadow_unwrapped);
}

TEST(ShadowNode, TxDisabledDoesNotWrapOutgoingPacket) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(false);
  node.setRxEnabled(true);
  mesh.setShadowSendHook(&node);

  uint8_t secret[PUB_KEY_SIZE];
  memset(secret, 0x44, sizeof(secret));
  Identity dest;
  memset(dest.pub_key, 0x77, sizeof(dest.pub_key));
  uint8_t data[4] = { 5, 6, 7, 8 };
  Packet* inner = mesh.createDatagram(PAYLOAD_TYPE_RESPONSE, dest, secret, data, sizeof(data));
  ASSERT_NE(inner, nullptr);
  uint8_t path[1] = { 0 };
  mesh.sendDirect(inner, path, 0);

  Packet* out = mgr.getNextOutbound(100000);
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(out->getPayloadType(), PAYLOAD_TYPE_RESPONSE);
  EXPECT_FALSE(out->shadow_wrapped);
}

TEST(ShadowNode, ReplyToPlainRequestIsPlain) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);

  SimpleMeshTables rx_tables;
  ReplyTestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  setTestPubKey(rx, 0xA0);
  rx.reply_dest = sender.self_id;
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(true);
  rx_node.setUnwrapAll(false);
  rx.setShadowSendHook(&rx_node);
  rx.setShadowRecvHook(&rx_node);

  uint8_t secret[PUB_KEY_SIZE];
  memset(secret, 0x5A, sizeof(secret));
  uint8_t data[4] = { 0x10, 0x11, 0x12, 0x13 };
  Packet* req = sender.createDatagram(PAYLOAD_TYPE_REQ, rx.self_id, secret, data, sizeof(data));
  ASSERT_NE(req, nullptr);
  uint8_t path[1] = { 0 };
  sender.sendDirect(req, path, 0);

  Packet* out = mgr.getNextOutbound(100000);
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(out->getPayloadType(), PAYLOAD_TYPE_REQ);

  Packet p;
  copyRaw(out, &p);
  rx.recv(&p);
  EXPECT_EQ(rx.replies, 1);

  Packet* reply = mgr.getNextOutbound(100000);
  ASSERT_NE(reply, nullptr);
  EXPECT_EQ(reply->getPayloadType(), PAYLOAD_TYPE_RESPONSE);
  EXPECT_FALSE(reply->shadow_wrapped);
}

TEST(ShadowNode, ReplyToWrappedRequestIsWrapped) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);
  ShadowNode tx(sender.self_id, rng);
  tx.setEnabled(true);
  sender.setShadowSendHook(&tx);

  SimpleMeshTables rx_tables;
  ReplyTestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  setTestPubKey(rx, 0xA0);
  rx.reply_dest = sender.self_id;
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(true);
  rx_node.setUnwrapAll(false);
  rx.setShadowSendHook(&rx_node);
  rx.setShadowRecvHook(&rx_node);

  uint8_t secret[PUB_KEY_SIZE];
  memset(secret, 0x5A, sizeof(secret));
  uint8_t data[4] = { 0x20, 0x21, 0x22, 0x23 };
  Packet* req = sender.createDatagram(PAYLOAD_TYPE_REQ, rx.self_id, secret, data, sizeof(data));
  ASSERT_NE(req, nullptr);
  uint8_t path[1] = { 0 };
  sender.sendDirect(req, path, 0);

  Packet* out = mgr.getNextOutbound(100000);
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(out->getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_TRUE(Mesh::isShadowPacket(out));

  Packet p;
  copyRaw(out, &p);
  rx.recv(&p);
  EXPECT_EQ(rx.replies, 1);

  Packet* reply = mgr.getNextOutbound(100000);
  ASSERT_NE(reply, nullptr);
  EXPECT_EQ(reply->getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_TRUE(reply->shadow_wrapped);
  ASSERT_GT(reply->payload_len, SHADOW_COMMON_SIZE);
  EXPECT_EQ(reply->payload[SHADOW_COMMON_SIZE], PAYLOAD_TYPE_RESPONSE);
}

TEST(ShadowNode, LoginReplyStaysWrapped) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);

  SimpleMeshTables rx_tables;
  ReplyTestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  setTestPubKey(rx, 0xA0);
  rx.reply_dest = sender.self_id;
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(true);
  rx_node.setUnwrapAll(false);
  rx.setShadowSendHook(&rx_node);
  rx.setShadowRecvHook(&rx_node);

  uint8_t secret[PUB_KEY_SIZE];
  sender.self_id.calcSharedSecret(secret, rx.self_id);
  uint8_t data[4] = { 0x30, 0x31, 0x32, 0x33 };
  Packet* req = sender.createAnonDatagram(PAYLOAD_TYPE_ANON_REQ, sender.self_id, rx.self_id,
                                          secret, data, sizeof(data));
  ASSERT_NE(req, nullptr);
  uint8_t path[1] = { 0 };
  sender.sendDirect(req, path, 0);

  Packet* out = mgr.getNextOutbound(100000);
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(out->getPayloadType(), PAYLOAD_TYPE_ANON_REQ);

  Packet p;
  copyRaw(out, &p);
  rx.recv(&p);
  EXPECT_EQ(rx.replies, 1);

  Packet* reply = mgr.getNextOutbound(100000);
  ASSERT_NE(reply, nullptr);
  EXPECT_EQ(reply->getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_TRUE(reply->shadow_wrapped);
}

TEST(ShadowNode, UnsolicitedResponseIsStillWrapped) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);
  mesh.setShadowSendHook(&node);

  uint8_t secret[PUB_KEY_SIZE];
  memset(secret, 0x66, sizeof(secret));
  Identity dest;
  memset(dest.pub_key, 0x88, sizeof(dest.pub_key));
  uint8_t data[4] = { 0x40, 0x41, 0x42, 0x43 };
  Packet* inner = mesh.createDatagram(PAYLOAD_TYPE_RESPONSE, dest, secret, data, sizeof(data));
  ASSERT_NE(inner, nullptr);
  uint8_t path[1] = { 0 };
  mesh.sendDirect(inner, path, 0);

  Packet* out = mgr.getNextOutbound(100000);
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(out->getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_TRUE(out->shadow_wrapped);
}

TEST(ShadowNode, ReplyToPlainTxtMsgIsPlain) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);

  SimpleMeshTables rx_tables;
  ReplyTestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  setTestPubKey(rx, 0xA0);
  rx.reply_dest = sender.self_id;
  rx.reply_type = PAYLOAD_TYPE_TXT_MSG;
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(true);
  rx_node.setUnwrapAll(false);
  rx.setShadowSendHook(&rx_node);
  rx.setShadowRecvHook(&rx_node);

  uint8_t secret[PUB_KEY_SIZE];
  memset(secret, 0x5A, sizeof(secret));
  uint8_t data[4] = { 0x50, 0x51, 0x52, 0x53 };
  Packet* req = sender.createDatagram(PAYLOAD_TYPE_TXT_MSG, rx.self_id, secret, data, sizeof(data));
  ASSERT_NE(req, nullptr);
  uint8_t path[1] = { 0 };
  sender.sendDirect(req, path, 0);

  Packet* out = mgr.getNextOutbound(100000);
  ASSERT_NE(out, nullptr);
  EXPECT_EQ(out->getPayloadType(), PAYLOAD_TYPE_TXT_MSG);

  Packet p;
  copyRaw(out, &p);
  rx.recv(&p);
  EXPECT_EQ(rx.replies, 1);

  Packet* reply = mgr.getNextOutbound(100000);
  ASSERT_NE(reply, nullptr);
  EXPECT_EQ(reply->getPayloadType(), PAYLOAD_TYPE_TXT_MSG);
  EXPECT_FALSE(reply->shadow_wrapped);
}

TEST(ShadowNode, LocalOnlyShadowRequestReplyIsWrapped) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh sender(radio, clock, rng, rtc, mgr, tables);

  SimpleMeshTables rx_tables;
  ReplyTestMesh rx(radio, clock, rng, rtc, mgr, rx_tables);
  setTestPubKey(rx, 0xA0);
  rx.reply_dest = sender.self_id;
  ShadowNode rx_node(rx.self_id, rng);
  rx_node.setEnabled(true);
  rx_node.setUnwrapAll(true);
  rx.setShadowSendHook(&rx_node);
  rx.setShadowRecvHook(&rx_node);

  uint8_t secret[PUB_KEY_SIZE];
  memset(secret, 0x5A, sizeof(secret));
  uint8_t data[4] = { 0x60, 0x61, 0x62, 0x63 };
  Packet* req = sender.createDatagram(PAYLOAD_TYPE_REQ, rx.self_id, secret, data, sizeof(data));
  ASSERT_NE(req, nullptr);
  uint8_t path[1] = { 0 };
  sender.sendDirect(req, path, 0);

  Packet* out = mgr.getNextOutbound(100000);
  ASSERT_NE(out, nullptr);
  Packet p;
  copyRaw(out, &p);
  p.local_only = true;          // reassembled shadow payload is delivered locally
  p.shadow_unwrapped = true;

  rx.recv(&p);
  EXPECT_EQ(rx.replies, 1);

  Packet* reply = mgr.getNextOutbound(100000);
  ASSERT_NE(reply, nullptr);
  EXPECT_EQ(reply->getPayloadType(), PAYLOAD_TYPE_GRP_TXT);
  EXPECT_TRUE(reply->shadow_wrapped);
}

TEST(ShadowNode, StatusAndCliSeparateTxFromRx) {
  TestRadio radio; TestClock clock; TestRng rng; TestRtc rtc; TestPacketManager mgr; SimpleMeshTables tables;
  TestMesh mesh(radio, clock, rng, rtc, mgr, tables);
  ShadowNode node(mesh.self_id, rng);
  node.setEnabled(true);

  char reply[160];
  ASSERT_TRUE(node.handleCommand("shd.enabled off", reply, sizeof(reply)));
  EXPECT_FALSE(node.enabled());
  EXPECT_TRUE(node.rxEnabled());

  node.formatStatus(reply, sizeof(reply));
  EXPECT_NE(strstr(reply, "enabled=0 rx=1"), nullptr);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

#include <gtest/gtest.h>
#include <helpers/ShadowAuth.h>
#include <helpers/ShadowNode.h>
#include <helpers/SimpleMeshTables.h>
#include <helpers/TransportKeyStore.h>

#include <string.h>

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
        p->recv_filtered = false; p->shadow_flags = 0;
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

} // namespace

TEST(ShadowConstants, SizesMatchPlan) {
  EXPECT_EQ(SHADOW_COMMON_SIZE, 6);
  EXPECT_EQ(SHADOW_EMBEDDED_OVERHEAD, 71);
  EXPECT_EQ(SHADOW_SIG_PACKET_SIZE, 90);
  EXPECT_EQ(SHADOW_MSG_OVERHEAD, 11);
  EXPECT_EQ(SHADOW_FRAG_OVERHEAD, 77);
  EXPECT_EQ(SHADOW_MAX_INNER_EMBEDDED, 113);
  EXPECT_EQ(SHADOW_MAX_INNER_MSG, 173);
  EXPECT_EQ(SHADOW_MAX_FRAG_PAYLOAD, 107);
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
    memset(x, (uint8_t)(i + 1), sizeof(x));
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
                                      const TransportKey& key, uint8_t app_len) {
  uint8_t app[MAX_ADVERT_DATA_SIZE];
  memset(app, 0x6B, app_len);
  mesh::Packet* adv = mesh.createAdvert(mesh.self_id, app, app_len);
  if (adv == nullptr) return nullptr;
  adv->path_len = 0;

  uint16_t codes[2];
  codes[0] = key.calcTransportCode(adv);
  codes[1] = 0;
  node.setTransportKey(key.key);
  mesh.sendFlood(adv, codes, 0, 1);
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
    if (i < 8) {
      EXPECT_FALSE(auth.filter(mesh, &p));
    } else {
      EXPECT_TRUE(auth.filter(mesh, &p));   // ninth advert exceeds 8/min
    }
  }
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

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

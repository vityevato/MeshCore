// Native-only deterministic Ed25519 stand-in.
//
// The native test environment links the real Identity.h (because it is pulled
// in through Mesh.h) but not the real Crypto library. These definitions keep
// shadow-layer unit tests linkable and let them exercise sign/verify paths,
// including wrong-key and wrong-message failures.

#include <Identity.h>
#include <string.h>

namespace mesh {

static void mockSign(const uint8_t* pub, const uint8_t* msg, int len, uint8_t* sig) {
  uint32_t s = 2166136261u;
  for (int i = 0; i < PUB_KEY_SIZE; i++) {
    s = (s ^ pub[i]) * 16777619u;
  }
  for (int i = 0; i < len; i++) {
    s = (s ^ msg[i]) * 16777619u;
  }
  for (int i = 0; i < SIGNATURE_SIZE; i++) {
    s = s * 1664525u + 1013904223u;
    sig[i] = (uint8_t)(s >> 24);
  }
}

Identity::Identity() {
  memset(pub_key, 0, sizeof(pub_key));
}

Identity::Identity(const char* pub_hex) {
  memset(pub_key, 0, sizeof(pub_key));
  (void)pub_hex;
}

bool Identity::verify(const uint8_t* sig, const uint8_t* message, int msg_len) const {
  uint8_t expected[SIGNATURE_SIZE];
  mockSign(pub_key, message, msg_len, expected);
  return memcmp(sig, expected, SIGNATURE_SIZE) == 0;
}

bool Identity::readFrom(Stream&) { return false; }
bool Identity::writeTo(Stream&) const { return false; }
void Identity::printTo(Stream&) const { }

LocalIdentity::LocalIdentity() : Identity() {
  memset(prv_key, 0, sizeof(prv_key));
}

LocalIdentity::LocalIdentity(const char*, const char*) : Identity() {
  memset(prv_key, 0, sizeof(prv_key));
}

LocalIdentity::LocalIdentity(RNG* rng) : Identity() {
  memset(prv_key, 0, sizeof(prv_key));
  rng->random(pub_key, PUB_KEY_SIZE);
}

void LocalIdentity::sign(uint8_t* sig, const uint8_t* message, int msg_len) const {
  mockSign(pub_key, message, msg_len, sig);
}

void LocalIdentity::calcSharedSecret(uint8_t* secret, const uint8_t*) const {
  memset(secret, 0x11, PUB_KEY_SIZE);
}

bool LocalIdentity::validatePrivateKey(const uint8_t*) { return true; }

bool LocalIdentity::readFrom(Stream&) { return false; }
bool LocalIdentity::writeTo(Stream&) const { return false; }
void LocalIdentity::printTo(Stream&) const { }
size_t LocalIdentity::writeTo(uint8_t*, size_t) { return 0; }
void LocalIdentity::readFrom(const uint8_t*, size_t) { }

}

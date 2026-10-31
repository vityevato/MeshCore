#pragma once

#include <cstdint>
#include <cmath>
#include "Stream.h"

// Minimal filesystem type for headers that only need the FILESYSTEM typedef
// (e.g. IdentityStore.h pulled in by TransportKeyStore.h in native tests).
#ifndef FILESYSTEM
class MockFileSystem {
public:
  bool mkdir(const char*) { return true; }
};
#define FILESYSTEM MockFileSystem
#endif

inline uint32_t g_mock_millis = 0;

using std::isnan;

inline uint32_t millis() {
  return g_mock_millis;
}

inline void delay(uint32_t ms) {
  g_mock_millis += ms;
}

#pragma once

#include <cstdint>
#include <cmath>
#include <cstdio>
#include "Stream.h"

// Minimal filesystem type for headers that only need the FILESYSTEM typedef
// (e.g. IdentityStore.h pulled in by TransportKeyStore.h in native tests).
#ifndef FILESYSTEM
class MockFile {
public:
  operator bool() const { return false; }
  int read(uint8_t*, size_t) { return 0; }
  int write(const uint8_t*, size_t) { return 0; }
  void close() {}
};
using File = MockFile;

class MockFileSystem {
public:
  bool mkdir(const char*) { return true; }
  bool exists(const char*) { return false; }
  File open(const char*, const char* mode = nullptr, bool = false) {
    (void)mode;
    return File();
  }
  bool remove(const char*) { return false; }
};
#define FILESYSTEM MockFileSystem
#endif

inline uint32_t g_mock_millis = 0;

inline char* ltoa(long value, char* dest, int base) {
  if (base == 10) snprintf(dest, 32, "%ld", value);
  else if (base == 16) snprintf(dest, 32, "%lx", (unsigned long)value);
  else snprintf(dest, 32, "%ld", value);
  return dest;
}

using std::isnan;

inline uint32_t millis() {
  return g_mock_millis;
}

inline void delay(uint32_t ms) {
  g_mock_millis += ms;
}

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <math.h>

#define MAX_HASH_SIZE        8
#define PUB_KEY_SIZE        32
#define PRV_KEY_SIZE        64
#define SEED_SIZE           32
#define SIGNATURE_SIZE      64
#define MAX_ADVERT_DATA_SIZE  32
#define CIPHER_KEY_SIZE     16
#define CIPHER_BLOCK_SIZE   16

// V1
#define CIPHER_MAC_SIZE      2
#define PATH_HASH_SIZE       1

#define MAX_PACKET_PAYLOAD  184
#define MAX_GROUP_DATA_LENGTH  (MAX_PACKET_PAYLOAD - CIPHER_BLOCK_SIZE - 3)
#define MAX_PATH_SIZE        64
#define MAX_TRANS_UNIT      255

// ---------------------------------------------------------------------------
// Shadow transit auth (shd.*)
//
// A per-node signed envelope carried inside an ordinary GRP_TXT v1 packet.
// Old repeaters forward it as a normal group packet; old nodes ignore it.
// ---------------------------------------------------------------------------

#define SHADOW_CH_SIZE             1
#define SHADOW_MAGIC_SIZE          2
#define SHADOW_TAG_SIZE            2
#define SHADOW_FLAGS_SIZE          1
#define SHADOW_COMMON_SIZE         (SHADOW_CH_SIZE + SHADOW_MAGIC_SIZE + SHADOW_TAG_SIZE + SHADOW_FLAGS_SIZE)

#define SHADOW_SIG_ID_SIZE         4
#define SHADOW_MSG_HASH_SIZE      16
#define SHADOW_DIGEST_SIZE        32   // full SHA-256 used for Ed25519 signing

#define SHADOW_VERSION             0
#define SHADOW_FLAG_MODE_MASK      0x03
#define SHADOW_FLAG_VERSION_SHIFT  4
#define SHADOW_FLAG_VERSION_MASK   0x0F

#define SHADOW_MODE_EMBEDDED       0
#define SHADOW_MODE_SIGNATURE      1
#define SHADOW_MODE_MESSAGE        2
#define SHADOW_MODE_FRAGMENT       3
#define SHADOW_MODE_AUTO           0xFF

// v1 fixed network marker. Both bytes are visible to old nodes as a normal
// group channel hash + group MAC. Change only with a protocol revision.
#define SHADOW_CHANNEL_HASH        0x53
#define SHADOW_MAGIC               0x5CC5

#define SHADOW_EMBEDDED_OVERHEAD   (SHADOW_COMMON_SIZE + 1 + SIGNATURE_SIZE)          // 71
#define SHADOW_SIG_PACKET_SIZE     (SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE + SHADOW_MSG_HASH_SIZE + SIGNATURE_SIZE) // 90
#define SHADOW_MSG_OVERHEAD        (SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE + 1)      // 11
#define SHADOW_FRAG_OVERHEAD       (SHADOW_COMMON_SIZE + SHADOW_SIG_ID_SIZE + 1 + 1 + 1 + SIGNATURE_SIZE) // 77

#define SHADOW_MAX_INNER_EMBEDDED  (MAX_PACKET_PAYLOAD - SHADOW_EMBEDDED_OVERHEAD)    // 113
#define SHADOW_MAX_INNER_MSG       (MAX_PACKET_PAYLOAD - SHADOW_MSG_OVERHEAD)         // 173
#define SHADOW_MAX_FRAG_PAYLOAD    (MAX_PACKET_PAYLOAD - SHADOW_FRAG_OVERHEAD)        // 107

// Compile-time memory profile. Define SHADOW_LOW_MEMORY for 64-128 KB MCUs.
#ifdef SHADOW_LOW_MEMORY
  #ifndef SHADOW_PENDING_MAX
    #define SHADOW_PENDING_MAX       8
  #endif
  #ifndef SHADOW_VERIFIED_CACHE_SIZE
    #define SHADOW_VERIFIED_CACHE_SIZE 64
  #endif
  #ifndef SHADOW_SIG_CACHE_SIZE
    #define SHADOW_SIG_CACHE_SIZE    8
  #endif
  #ifndef SHADOW_FRAG_MAX
    #define SHADOW_FRAG_MAX          2
  #endif
#else
  #ifndef SHADOW_PENDING_MAX
    #define SHADOW_PENDING_MAX       20
  #endif
  #ifndef SHADOW_VERIFIED_CACHE_SIZE
    #define SHADOW_VERIFIED_CACHE_SIZE 160
  #endif
  #ifndef SHADOW_SIG_CACHE_SIZE
    #define SHADOW_SIG_CACHE_SIZE    16
  #endif
  #ifndef SHADOW_FRAG_MAX
    #define SHADOW_FRAG_MAX          4
  #endif
#endif

#ifdef SHADOW_LOW_MEMORY
  #ifndef SHADOW_MAX_ALLOW
    #define SHADOW_MAX_ALLOW         16
  #endif
#else
  #ifndef SHADOW_MAX_ALLOW
    #define SHADOW_MAX_ALLOW         32
  #endif
#endif
#ifndef SHADOW_TTL_SAMPLES
  #define SHADOW_TTL_SAMPLES         32
#endif

#define SHADOW_HOLD_MIN_MS          45000UL
#define SHADOW_HOLD_MAX_MS          180000UL
#define SHADOW_HOLD_DEFAULT_MS      60000UL
#define SHADOW_MARGIN_MS            2000UL
#define SHADOW_SIG_TTL_MIN_MS       75000UL
#define SHADOW_SIG_TTL_DEFAULT_MS   90000UL
#define SHADOW_SIG_TTL_MAX_MS       240000UL
#define SHADOW_FRAG_TTL_MIN_MS      45000UL
#define SHADOW_FRAG_TTL_DEFAULT_MS  60000UL
#define SHADOW_FRAG_TTL_MAX_MS      180000UL

#define SHADOW_SIG_MSG_DELAY_MS     300UL
#define SHADOW_FRAG_GAP_MS          250UL

#if MESH_DEBUG && ARDUINO
  #include <Arduino.h>
  #define MESH_DEBUG_PRINT(F, ...) Serial.printf("DEBUG: " F, ##__VA_ARGS__)
  #define MESH_DEBUG_PRINTLN(F, ...) Serial.printf("DEBUG: " F "\n", ##__VA_ARGS__)
#else
  #define MESH_DEBUG_PRINT(...) {}
  #define MESH_DEBUG_PRINTLN(...) {}
#endif

#if BRIDGE_DEBUG && ARDUINO
#define BRIDGE_DEBUG_PRINTLN(F, ...) Serial.printf("%s BRIDGE: " F, getLogDateTime(), ##__VA_ARGS__)
#else
#define BRIDGE_DEBUG_PRINTLN(...) {}
#endif

namespace mesh {

#define  BD_STARTUP_NORMAL     0  // getStartupReason() codes
#define  BD_STARTUP_RX_PACKET  1

class MainBoard {
public:
  virtual uint16_t getBattMilliVolts() = 0;
  virtual float getMCUTemperature() { return NAN; }
  virtual bool setAdcMultiplier(float multiplier) { return false; };
  virtual float getAdcMultiplier() const { return 0.0f; }
  virtual const char* getManufacturerName() const = 0;
  virtual void onBeforeTransmit() { }
  virtual void onAfterTransmit() { }
  virtual void reboot() = 0;
  virtual void powerOff() { /* no op */ }
  // Called by example setup() functions to signal that boot is complete.
  // Boards may override to stop a boot-indicator LED sequence or similar.
  // Default no-op: boards that don't care need not implement anything.
  virtual void onBootComplete() { /* no op */ }
  virtual uint32_t getIRQGpio() { return -1; } // not supported. Returns DIO1 (SX1262) and DIO0 (SX127x)
  virtual void sleep(uint32_t secs)  { /* no op */ }
  virtual uint32_t getGpio() { return 0; }
  virtual void setGpio(uint32_t values) {}
  virtual uint8_t getStartupReason() const = 0;
  virtual bool getBootloaderVersion(char* version, size_t max_len) { return false; }
  virtual bool startOTAUpdate(const char* id, char reply[]) { return false; }   // not supported

  // Power management interface (boards with power management override these)
  virtual bool isPwrMgtInitialised() const { return false; }
  virtual bool isExternalPowered() { return false; }
  // True while a board can identify an active battery-charging source.
  virtual bool isChargerActive() { return false; }

  // Optional, source-specific power detection. Boards that can distinguish a USB
  // supply from a solar charger override these; defaults keep every other board
  // unaffected (the generic CLI prints "n/a" when a capability is absent).
  virtual bool hasUsbPowerDetect() const { return false; }
  virtual bool isUsbPowered() { return false; }
  virtual bool hasSolarChargerDetect() const { return false; }
  virtual bool isSolarChargerActive() { return false; }
  virtual uint16_t getBootVoltage() { return 0; }
  virtual bool getWakeLpcompSupported() const { return false; }
  virtual uint32_t getResetReason() const { return 0; }
  virtual const char* getResetReasonString(uint32_t reason) { return "Not available"; }
  virtual uint8_t getShutdownReason() const { return 0; }
  virtual const char* getShutdownReasonString(uint8_t reason) { return "Not available"; }

  virtual bool handleCommand(const char* command, uint32_t sender_timestamp, char* reply) { return false; }

  // Called from the example main loops. Lets a board feed its watchdog and
  // run periodic housekeeping. Default no-op.
  virtual void loop() { /* no op */ }
};

/**
 * An abstraction of the device's Realtime Clock.
*/
class RTCClock {
  uint32_t last_unique;
protected:
  RTCClock() { last_unique = 0; }

public:
  /**
   * \returns  the current time. in UNIX epoch seconds.
  */
  virtual uint32_t getCurrentTime() = 0;

  /**
   * \param time  current time in UNIX epoch seconds.
  */
  virtual void setCurrentTime(uint32_t time) = 0;

  /**
   * override in classes that need to periodically update internal state
   */
  virtual void tick() { /* no op */}

  uint32_t getCurrentTimeUnique() {
    uint32_t t = getCurrentTime();
    if (t <= last_unique) {
      return ++last_unique;
    }
    return last_unique = t;
  }
};

}

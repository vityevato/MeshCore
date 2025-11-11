# MQTT Bridge TLS Support - Changelog

## Added Features

### TLS/SSL Support
- Added conditional compilation for `WiFiClientSecure` when `WITH_MQTT_TLS` is defined
- Automatic port selection: 8883 for TLS, 1883 for plain MQTT
- Support for multiple TLS modes:
  - Insecure mode (skip certificate verification)
  - Server verification with CA certificate

### Configuration Macros

#### Required for TLS
- `WITH_MQTT_TLS` - Enable TLS/SSL encryption

#### Optional TLS Settings
- `WITH_MQTT_CA_CERT` - CA certificate for server verification (PEM format)
- `WITH_MQTT_TLS_INSECURE` - Skip certificate verification (not recommended for production)

### Implementation Details

#### Header File Changes (`MQTTBridge.h`)
1. Added `#include <WiFiClientSecure.h>` when `WITH_MQTT_TLS` is defined
2. Conditional `WiFiClient` vs `WiFiClientSecure` member variable
3. Added `configureTLS()` private method
4. Updated documentation with TLS configuration options
5. Automatic port selection based on TLS flag

#### Implementation File Changes (`MQTTBridge.cpp`)
1. Added `configureTLS()` method implementation:
   - Configures insecure mode if `WITH_MQTT_TLS_INSECURE` is set
   - Sets CA certificate if `WITH_MQTT_CA_CERT` is provided
   - Falls back to insecure mode if no CA certificate is provided
2. Calls `configureTLS()` in `begin()` before connecting to broker
3. Serial debug output for TLS configuration status

### Documentation
- Created `mqtt_tls_example.md` - Comprehensive TLS configuration guide
- Created `mqtt_bridge_quick_start.md` - Quick start guide with examples

## Usage Examples

### Basic TLS (Insecure Mode)
```ini
-D WITH_MQTT_TLS=1
-D WITH_MQTT_TLS_INSECURE=1
```

### TLS with Server Verification
```ini
-D WITH_MQTT_TLS=1
'-D WITH_MQTT_CA_CERT=R"EOF(
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
)EOF"'
```


## Backward Compatibility
- All existing MQTT bridge configurations continue to work without changes
- TLS is opt-in via `WITH_MQTT_TLS` flag
- Default port remains 1883 when TLS is not enabled

## Security Considerations
1. **Never use insecure mode in production** - Only for testing
2. **Always verify server certificates** - Use CA certificate
3. **Protect private keys** - Never commit to version control
4. **Use strong authentication** - Combine TLS with username/password
5. **Monitor certificate expiration** - Plan for rotation

## Testing
Tested with:
- Mosquitto broker (local and remote)
- Public test brokers (test.mosquitto.org)
- HiveMQ Cloud (TLS with CA verification)

## Known Limitations
1. TLS requires significant memory (ESP32 recommended)
2. Certificate chain length affects memory usage
3. Some ESP32 variants may need increased stack size

## Runtime Configuration (v1.8.1+)
- ✅ Support for certificate storage in SPIFFS/LittleFS
- ✅ Runtime certificate loading via CLI
- CA certificate can be uploaded to `/mqtt_ca.crt`
- CLI commands: `get mqtt.cert.status`, `set mqtt.cert.clear`
- Runtime certificate takes precedence over compile-time define

## Future Enhancements
- [ ] Certificate expiration monitoring
- [ ] Automatic certificate rotation
- [ ] Support for PSK (Pre-Shared Key) TLS

## References
- ESP32 WiFiClientSecure: https://github.com/espressif/arduino-esp32/tree/master/libraries/WiFiClientSecure
- MQTT Security: https://www.hivemq.com/blog/mqtt-security-fundamentals/
- OpenSSL Commands: https://www.openssl.org/docs/

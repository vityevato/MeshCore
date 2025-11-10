# MQTT Bridge TLS Configuration

This document describes how to configure TLS/SSL encryption for the MQTT bridge in MeshCore.

## CA Certificate Configuration Methods

Two methods are available for configuring CA certificate:

1. **Runtime Configuration (Recommended)** — Store CA certificate in file system, configure at runtime
2. **Compile-Time Configuration** — Embed CA certificate in firmware during compilation

Runtime configuration is recommended because:
- No firmware recompilation needed to update certificate
- Easier certificate management and rotation
- Smaller firmware size
- Same firmware can be used with different brokers

**Note:** Only server verification (CA certificate) is supported. Mutual TLS (client certificates) is not implemented.

## Method 1: Runtime Configuration

### Step 1: Upload CA Certificate File

Upload CA certificate file to the device file system:
- `/mqtt_ca.crt` — CA certificate for server verification

#### Upload Methods

**Option A: Serial CLI Upload (Recommended)**

Upload certificate directly via Serial without reflashing filesystem.

1. Use the provided Python script:
   ```bash
   python3 upload_cert.py /dev/cu.usbserial-0001 mqtt_ca.crt
   ```

2. Or manually via Serial Monitor:
   ```bash
   set mqtt.cert.upload BEGIN
   set mqtt.cert.upload -----BEGIN CERTIFICATE-----
   set mqtt.cert.upload MIIDVzCCAj+gAwIBAgIUFwoUWiqP2bA0sYAQl1Y+K2y+k3YwDQYJKoZIhvcNAQEL
   # ... (paste each line)
   set mqtt.cert.upload -----END CERTIFICATE-----
   set mqtt.cert.upload END
   ```


**Memory usage:** CA certificate is loaded into a static buffer (3KB) allocated as part of the MQTTBridge object. Memory overhead: ~3KB when WITH_MQTT_TLS is enabled, regardless of whether runtime or compile-time certificate is used.

### Step 2: Enable TLS via CLI

```bash
set mqtt.tls on
set mqtt.tls_insecure off  # Enable certificate verification
reboot
```

### Step 3: Verify Configuration

```bash
get mqtt.cert.status
# Output: CA: YES
```

### Managing Certificate

**Check status:**
```bash
get mqtt.cert.status
```

**Remove certificate:**
```bash
set mqtt.cert.clear
```

**Note:** Runtime certificate takes precedence over compile-time define.

---

## Method 2: Compile-Time Configuration

### Basic TLS Configuration

To enable TLS encryption for MQTT connections, add the following to your `platformio.ini`:

```ini
[env:your_device_mqtt_tls]
extends = esp32_base
build_flags =
  ${esp32_base.build_flags}
  -D WITH_MQTT_BRIDGE=1
  -D WITH_MQTT_TLS=1
```

**Note:** All MQTT and WiFi parameters must be configured via CLI commands:
```bash
set mqtt.broker mqtt.example.com
set mqtt.port 8883
set mqtt.topic meshcore/bridge
set wifi.ssid YourWiFiSSID
set wifi.password YourWiFiPassword
reboot
```

## TLS Modes

### 1. Insecure Mode (Skip Certificate Verification)

**WARNING: Not recommended for production use!**

This mode skips certificate verification and is vulnerable to man-in-the-middle attacks.

```ini
build_flags =
  ${esp32_base.build_flags}
  -D WITH_MQTT_TLS=1
  -D WITH_MQTT_TLS_INSECURE=1
```

### 2. Server Verification (Recommended)

Verify the broker's certificate using a CA certificate:

```ini
build_flags =
  ${esp32_base.build_flags}
  -D WITH_MQTT_TLS=1
  '-D WITH_MQTT_CA_CERT=R"EOF(
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
...
-----END CERTIFICATE-----
)EOF"'
```

**Note:** Mutual TLS (client certificate authentication) is not supported.

## Certificate Formats

Certificates should be in PEM format. You can convert other formats using OpenSSL:

```bash
# Convert DER to PEM
openssl x509 -inform der -in certificate.cer -out certificate.pem

# Extract CA certificate from server
openssl s_client -showcerts -connect mqtt.example.com:8883 < /dev/null 2>/dev/null | \
  openssl x509 -outform PEM > ca.pem
```

## Testing

### Test with Mosquitto

1. Generate test certificates:
```bash
# Generate CA
openssl req -new -x509 -days 365 -extensions v3_ca -keyout ca.key -out ca.crt

# Generate server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365
```

2. Configure Mosquitto (`mosquitto.conf`):
```
listener 8883
cafile /path/to/ca.crt
certfile /path/to/server.crt
keyfile /path/to/server.key
require_certificate false
```

3. Start Mosquitto:
```bash
mosquitto -c mosquitto.conf
```

### Test with Public Brokers

Some public MQTT brokers support TLS:

- **test.mosquitto.org:8883** (port 8883 with TLS)
- **mqtt.eclipseprojects.io:8883** (port 8883 with TLS)

Example configuration for test.mosquitto.org:

```ini
build_flags =
  ${esp32_base.build_flags}
  -D WITH_MQTT_BRIDGE=1
  -D WITH_MQTT_TLS=1
  -D WITH_MQTT_TLS_INSECURE=1  # For testing only!
```

Configure via CLI:
```bash
set mqtt.broker test.mosquitto.org
set mqtt.port 8883
set wifi.ssid YourWiFi
set wifi.password YourPassword
reboot
```

## Troubleshooting

### Connection Fails with TLS

1. **Check certificate validity:**
   - Ensure the certificate is not expired
   - Verify the hostname matches the certificate CN/SAN

2. **Enable debug output:**
   ```ini
   build_flags =
     ${esp32_base.build_flags}
     -D CORE_DEBUG_LEVEL=5  # ESP32 verbose logging
   ```

3. **Test without TLS first:**
   - Verify basic MQTT connectivity works
   - Then add TLS step by step

## References

- [ESP32 WiFiClientSecure Documentation](https://github.com/espressif/arduino-esp32/tree/master/libraries/WiFiClientSecure)
- [PubSubClient Library](https://github.com/knolleary/pubsubclient)
- [MQTT Security Fundamentals](https://www.hivemq.com/blog/mqtt-security-fundamentals/)
- [OpenSSL Certificate Commands](https://www.openssl.org/docs/man1.1.1/man1/openssl-x509.html)

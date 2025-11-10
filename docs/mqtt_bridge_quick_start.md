# MQTT Bridge Quick Start

## Overview

MQTT Bridge allows MeshCore devices to communicate over the internet via MQTT broker. All configuration is done at **runtime via CLI commands** - no need to recompile firmware for different brokers or WiFi networks.

## Firmware Configuration

Add to your `platformio.ini`:

```ini
[env:my_device_mqtt]
extends = esp32_base
build_flags =
  ${esp32_base.build_flags}
  -D WITH_MQTT_BRIDGE=1      # Enable MQTT Bridge
  -D WITH_MQTT_TLS=1         # Enable TLS support (optional)
build_src_filter = 
  ${esp32_base.build_src_filter}
  +<helpers/bridges/MQTTBridge.cpp>
lib_deps =
  ${esp32_base.lib_deps}
  knolleary/PubSubClient @ ^2.8
```

## Runtime Configuration via CLI

Connect via USB Serial and configure:

### Basic Setup (No TLS)

```bash
# WiFi credentials
set wifi.ssid YourWiFiSSID
set wifi.password YourWiFiPassword

# MQTT broker
set mqtt.broker mqtt.example.com
set mqtt.port 1883
set mqtt.topic meshcore/bridge

# Enable bridge
set bridge.enabled on

# Reboot to apply
reboot
```

### With TLS (Insecure Mode - Testing Only)

```bash
# WiFi
set wifi.ssid YourWiFiSSID
set wifi.password YourWiFiPassword

# MQTT with TLS
set mqtt.broker mqtt.example.com
set mqtt.port 8883
set mqtt.topic meshcore/bridge
set mqtt.tls on
set mqtt.tls_insecure on  # Skip certificate verification

# Enable bridge
set bridge.enabled on
reboot
```

### With Authentication

```bash
# Add username/password
set mqtt.user device001
set mqtt.password SecurePass123

# Rest of configuration...
set mqtt.broker mqtt.example.com
set mqtt.port 8883
set mqtt.topic meshcore/zone1
set bridge.enabled on
reboot
```

### Optional: Custom Client ID

```bash
set mqtt.client_id my-unique-device-id
```

By default, client ID is auto-generated from MAC address: `meshcore-ABC123`

## Default Values

Default values are set in firmware (can be customized in `MyMesh.cpp` constructor):

```cpp
// MQTT Bridge defaults
_prefs.bridge_mqtt_broker = "mqtt-private.example.com"
_prefs.bridge_mqtt_port = 8883 (if TLS) or 1883 (no TLS)
_prefs.bridge_mqtt_topic = "meshcore/bridge"
_prefs.bridge_mqtt_tls = 1 (if WITH_MQTT_TLS defined)
_prefs.bridge_mqtt_tls_insecure = 1

// WiFi defaults
_prefs.bridge_wifi_ssid = "PublicWiFi"
```

## Complete Example

```ini
[env:heltec_v3_mqtt_bridge]
extends = Heltec_lora32_v3
build_flags =
  ${Heltec_lora32_v3.build_flags}
  -D DISPLAY_CLASS=SSD1306Display
  -D ADVERT_NAME='"MQTT Bridge"'
  -D WITH_MQTT_BRIDGE=1
  -D WITH_MQTT_TLS=1
  -D BRIDGE_DEBUG=1
build_src_filter = 
  ${Heltec_lora32_v3.build_src_filter}
  +<helpers/bridges/MQTTBridge.cpp>
  +<helpers/ui/SSD1306Display.cpp>
  +<../examples/simple_repeater>
lib_deps =
  ${Heltec_lora32_v3.lib_deps}
  ${esp32_ota.lib_deps}
  knolleary/PubSubClient @ ^2.8
```

## Testing

1. Build and flash:
   ```bash
   pio run -e my_device_mqtt -t upload
   ```

2. Monitor serial output:
   ```bash
   pio device monitor -e my_device_mqtt
   ```

3. Configure via CLI (see examples above)

4. You should see:
   ```
   Connecting to WiFi...
   WiFi connected, IP: 192.168.1.100
   MQTT TLS: Insecure mode enabled (certificate verification disabled)
   Attempting MQTT connection to mqtt.example.com:8883 as meshcore-ABC123...
   MQTT connected!
   Subscribed to topic: meshcore/bridge
   ```

## Viewing Current Configuration

```bash
get wifi.ssid
get wifi.password
get mqtt.broker
get mqtt.port
get mqtt.topic
get mqtt.user
get mqtt.tls
get mqtt.tls_insecure
get bridge.enabled
```

## Troubleshooting

### WiFi not connecting
```
BRIDGE: WiFi not configured!
BRIDGE: WiFi disconnected, attempting reconnection
BRIDGE: WiFi reconnection failed!
```
**Solution:** Check WiFi credentials:
```bash
get wifi.ssid
get wifi.password
set wifi.ssid CorrectSSID
set wifi.password CorrectPassword
reboot
```

### MQTT connection failed
```
MQTT connection failed, rc=-2
```
**Error codes:**
- `-2` — Network connection failed (check broker address/port)
- `-4` — Connection timeout (broker unreachable)
- `-5` — Authentication failed (check username/password)

**Solution:**
```bash
get mqtt.broker
get mqtt.port
get mqtt.user
# Fix incorrect values
set mqtt.broker correct-broker.com
reboot
```

### TLS handshake failed
Only if using TLS with certificate verification. For testing, use:
```bash
set mqtt.tls_insecure on
reboot
```

### Bridge not starting
```bash
get bridge.enabled
# If "off":
set bridge.enabled on
reboot
```

## Public MQTT Brokers for Testing

- **test.mosquitto.org** — port 1883 (no TLS), 8883 (TLS)
- **broker.hivemq.com** — port 1883
- **broker.emqx.io** — port 1883

**Example:**
```bash
set mqtt.broker test.mosquitto.org
set mqtt.port 1883
set mqtt.topic meshcore/test
set mqtt.tls off
reboot
```

⚠️ **Warning:** Public brokers have no authentication and no privacy. Use only for testing!

## Advanced: TLS with CA Certificate

### Method 1: Runtime Configuration (Recommended)

CA certificate can now be stored in the file system and configured at runtime without recompiling firmware.

1. Upload CA certificate file to the device file system:
   - `/mqtt_ca.crt` — CA certificate for server verification

2. Configure TLS via CLI:
```bash
set mqtt.tls on
set mqtt.tls_insecure off  # Enable certificate verification
reboot
```

3. Check certificate status:
```bash
get mqtt.cert.status
# Output: CA: YES
```

4. To remove certificate:
```bash
set mqtt.cert.clear
```

**Uploading certificate:**
- Manually: `set mqtt.cert.upload` (see CLI commands)
- Automated: `python3 bin/mqtt_bridge/upload_cert.py <port> <cert_file>`

**Note:** Runtime certificates take precedence over compile-time defines.

### Method 2: Compile-Time Configuration

For devices without file system access, you can compile CA certificate into firmware:

```ini
build_flags =
  ${esp32_base.build_flags}
  -D WITH_MQTT_BRIDGE=1
  -D WITH_MQTT_TLS=1
  '-D WITH_MQTT_CA_CERT=R"EOF(
-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
...your CA certificate here...
-----END CERTIFICATE-----
)EOF"'
```

Then configure via CLI:
```bash
set mqtt.tls on
set mqtt.tls_insecure off  # Enable certificate verification
reboot
```

For detailed TLS configuration, see [mqtt_tls_example.md](mqtt_tls_example.md)

## See Also

- [MQTT CLI Commands Reference](mqtt_cli_commands.md) — full list of MQTT commands
- [MQTT TLS Example](mqtt_tls_example.md) — detailed TLS configuration

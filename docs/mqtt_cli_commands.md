# MQTT Bridge CLI Commands Reference

CLI commands for configuring MQTT Bridge in MeshCore.

## Connection

To access the CLI, use:
- **USB Serial** — via terminal (115200 baud)
- **Web configurator** — https://config.meshcore.dev
- **Flasher console** — https://flasher.meshcore.co.uk

---

## MQTT Bridge

*(Available only with `WITH_MQTT_BRIDGE`)*

### Show All Settings

#### `show mqtt`
Display MQTT bridge settings and current connection status (compact format).

**Example:**
```
show mqtt
```

**Output:**
```
MQTT: mqtt.example.com:8883
Topic: meshcore/bridge
TLS: on, CA: YES
WiFi: MyNetwork
WiFi: OK (192.168.1.100)
MQTT: OK
```

**Note:** 
- Connection status shows real-time WiFi and MQTT broker connectivity
- Use individual `get` commands to view passwords and other detailed settings
- **CA status:**
  - `YES` — Certificate verification **enabled** (from file system or compile-time)
  - `NO` — Insecure mode (no certificate verification)
- **WiFi status:** `OK` (connected), `DISC` (disconnected), `NO_SSID`, `FAILED`, `LOST`
- **MQTT status:** `OK` (connected), `DISC` (disconnected)

### MQTT Parameters

#### `get mqtt.broker` / `set mqtt.broker <hostname>`
**⚠️ Requires reboot!** MQTT broker address.

**Example:**
```
set mqtt.broker mqtt.example.com
```

#### `get mqtt.port` / `set mqtt.port <port>`
**⚠️ Requires reboot!** MQTT port (1-65535, typically 1883 or 8883 for TLS).

**Example:**
```
set mqtt.port 8883
```

#### `get mqtt.topic` / `set mqtt.topic <topic>`
**⚠️ Requires reboot!** MQTT topic for publish/subscribe.

**Important:** Topic must NOT contain MQTT wildcards (`#` or `+`). The bridge uses the same topic for both publishing and subscribing, so wildcards are not allowed.

**Example:**
```
set mqtt.topic meshcore/bridge
```

**Invalid examples:**
```
set mqtt.topic meshcore/#        # ERROR: wildcard not allowed
set mqtt.topic meshcore/+/bridge # ERROR: wildcard not allowed
```

#### `get mqtt.user` / `set mqtt.user <username>`
**⚠️ Requires reboot!** MQTT username (optional).

#### `get mqtt.password` / `set mqtt.password <password>`
**⚠️ Requires reboot!** MQTT password (optional).

#### `get mqtt.client_id` / `set mqtt.client_id <client_id>`
**⚠️ Requires reboot!** MQTT Client ID (optional, auto-generated if empty).

#### `get mqtt.tls` / `set mqtt.tls <on|off>`
**⚠️ Requires reboot!** Use TLS/SSL encryption.

**Example:**
```
set mqtt.tls on
```

#### `get mqtt.tls_insecure` / `set mqtt.tls_insecure <on|off>`
**⚠️ Requires reboot!** Skip certificate verification (not recommended for production).

**Example:**
```
set mqtt.tls_insecure on
```

#### `get mqtt.cert.status`
Check status of CA certificate file in file system.

**Example output:**
```
CA: YES
```

Shows presence of `/mqtt_ca.crt` (CA certificate for server verification).

#### `set mqtt.cert.upload <line>`
Upload CA certificate line by line via Serial.

**Usage:**
```bash
set mqtt.cert.upload BEGIN
set mqtt.cert.upload -----BEGIN CERTIFICATE-----
set mqtt.cert.upload MIIDVzCCAj+gAwIBAgIUFwoUWiqP2bA0sYAQl1Y+K2y+k3YwDQYJKoZIhvcNAQEL
# ... paste each line of certificate ...
set mqtt.cert.upload -----END CERTIFICATE-----
set mqtt.cert.upload END
```

**Automated upload:**
```bash
python3 upload_cert.py /dev/cu.usbserial-0001 mqtt_ca.crt
```

#### `set mqtt.cert.clear`
Delete CA certificate file from file system.

**Example:**
```
set mqtt.cert.clear
```

**Note:** Certificate upload:
- **Manually** — `set mqtt.cert.upload` (see usage above)
- **Automated** — `python3 upload_cert.py <port> <cert_file>`

See [MQTT TLS Example](mqtt_tls_example.md) for detailed upload instructions.

Runtime certificates take precedence over compile-time defines.

### WiFi Parameters

#### `get wifi.ssid` / `set wifi.ssid <ssid>`
**⚠️ Requires reboot!** WiFi network SSID.

**Example:**
```
set wifi.ssid MyNetwork
```

#### `get wifi.password` / `set wifi.password <password>`
**⚠️ Requires reboot!** WiFi network password.

**Example:**
```
set wifi.password MyPassword123
```

### Complete MQTT Bridge Configuration Example

```bash
# WiFi
set wifi.ssid MyNetwork
set wifi.password MyPassword123

# MQTT
set mqtt.broker mqtt.example.com
set mqtt.port 8883
set mqtt.topic meshcore/my-bridge
set mqtt.user myuser
set mqtt.password mypass
set mqtt.tls on
set mqtt.tls_insecure off

# Enable bridge
set bridge.enabled on

# Reboot to apply
reboot
```

---

## Notes

- **⚠️ Requires reboot** — most MQTT and WiFi parameter changes require reboot to apply
- String parameters can be specified with or without quotes
- Commands are case-sensitive

---

## Additional Resources

- [MQTT Bridge Quick Start](mqtt_bridge_quick_start.md)
- [MQTT TLS Configuration](mqtt_tls_example.md)
- **Web configurator:** https://config.meshcore.dev
- **Discord:** https://discord.gg/BMwCtwHj5V

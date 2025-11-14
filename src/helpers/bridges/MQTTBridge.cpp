#include "MQTTBridge.h"
#include <time.h>
#include <esp_sntp.h>

#ifdef WITH_MQTT_BRIDGE

// Include compile-time CA certificate if defined
#ifdef WITH_MQTT_CA_CERT
#include "mqtt_ca_cert.h"
#endif

#ifdef ESP_PLATFORM
#include <SPIFFS.h>
#define FS_IMPL SPIFFS
#elif defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
#include <Adafruit_LittleFS.h>
#ifdef NRF52_PLATFORM
#include <InternalFileSystem.h>
#define FS_IMPL InternalFS
#elif defined(STM32_PLATFORM)
#include <stm32/InternalFileSystem.h>
#define FS_IMPL InternalFS
#endif
#endif

MQTTBridge *MQTTBridge::_instance = nullptr;

// Public methods

MQTTBridge::MQTTBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc, mesh::LocalIdentity *self_id)
    : BridgeBase(prefs, mgr, rtc), _mqtt_client(_wifi_client), _self_id(self_id) {
  _instance = this;
  _mqtt_client.setCallback(mqttCallback);
}

void MQTTBridge::begin() {
  // Generate client ID if not set in prefs (WiFi must be initialized first)
  if (_prefs->bridge_mqtt_client_id[0] == 0) {
    generateClientId();
  }
  
  // Build publish and subscribe topics
  const char *base_topic = _prefs->bridge_mqtt_topic;
  const char *client_id = _prefs->bridge_mqtt_client_id[0] != 0 
    ? _prefs->bridge_mqtt_client_id 
    : _client_id_buf;
  
  // Publish topic: <base_topic>/<client_id>
  snprintf(_publish_topic, sizeof(_publish_topic), "%s/%s", base_topic, client_id);
  
  // Subscribe topic: <base_topic>/+
  snprintf(_subscribe_topic, sizeof(_subscribe_topic), "%s/+", base_topic);

  // Get broker and port from prefs (now they are loaded)
  const char *broker = _prefs->bridge_mqtt_broker;
  uint16_t port = _prefs->bridge_mqtt_port > 0 
    ? _prefs->bridge_mqtt_port 
    : (_prefs->bridge_mqtt_tls ? 8883 : 1883);
  
  // Save hostname for SNI in TLS
  strncpy(_broker_hostname, broker, sizeof(_broker_hostname) - 1);
  _broker_hostname[sizeof(_broker_hostname) - 1] = '\0';
  
  BRIDGE_DEBUG_PRINTLN("MQTTBridge: broker='%s', port=%d, hostname='%s'\n", 
                       broker, port, _broker_hostname);

#ifdef WITH_MQTT_TLS
  // Set hostname for SNI (Server Name Indication) in TLS
  _wifi_client.setHostname(_broker_hostname, port);
#endif

  // Configure MQTT server
  _mqtt_client.setServer(broker, port);

  // Connect to WiFi if not already connected
  if (WiFi.status() != WL_CONNECTED) {
    // Get WiFi credentials from prefs
    const char *ssid = _prefs->bridge_wifi_ssid;
    const char *password = _prefs->bridge_wifi_password;

    if (ssid[0] == 0) {
      BRIDGE_DEBUG_PRINTLN("WiFi not configured!\n");
      return;
    }

    WiFi.begin(ssid, password);
    BRIDGE_DEBUG_PRINTLN("Connecting to WiFi...\n");

    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 30000) {
      delay(100);
      yield(); // Feed watchdog
    }

    if (WiFi.status() == WL_CONNECTED) {
      BRIDGE_DEBUG_PRINTLN("WiFi connected, IP: %s\n", WiFi.localIP().toString().c_str());
      syncTimeNTP();
    } else {
      BRIDGE_DEBUG_PRINTLN("WiFi connection failed!\n");
      return;
    }
  }

  // Configure TLS settings before connecting if enabled
  if (_prefs->bridge_mqtt_tls) {
#ifdef WITH_MQTT_TLS
    configureTLS();
#else
    BRIDGE_DEBUG_PRINTLN("MQTT TLS requested but not compiled in!\n");
#endif
  }

  // Reset reconnect timer to allow immediate first connection attempt
  _last_reconnect_attempt = millis() - RECONNECT_INTERVAL;

  // Initial connection attempt
  reconnect();
  _initialized = true;
}

void MQTTBridge::end() {
  if (_mqtt_client.connected()) {
    _mqtt_client.disconnect();
  }
  WiFi.disconnect();
  _initialized = false;
}

void MQTTBridge::loop() {
  // Check free heap and log warning if low (rate limited)
  uint32_t free_heap = ESP.getFreeHeap();
  unsigned long now = millis();
  if (free_heap < 10000 && (now - _last_heap_warning > HEAP_WARNING_INTERVAL)) {
    BRIDGE_DEBUG_PRINTLN("WARNING: Low memory! Free heap: %d bytes\n", free_heap);
    _last_heap_warning = now;
  }

  // Check and restore WiFi connection first
  if (WiFi.status() != WL_CONNECTED) {
    reconnectWiFi();
    return; // No point trying MQTT without WiFi
  }

  // Check and restore MQTT connection
  if (!_mqtt_client.connected()) {
    reconnect();
  }

  if (_mqtt_client.connected()) {
    _mqtt_client.loop();
  }
  
  yield(); // Feed watchdog after processing
}

void MQTTBridge::sendPacket(mesh::Packet *packet) {
  // Guard against uninitialized state
  if (_initialized == false) {
    return;
  }

  // First validate the packet pointer
  if (!packet) {
    BRIDGE_DEBUG_PRINTLN("TX invalid packet pointer\n");
    return;
  }

  // Don't send zero-hop packets (intended only for direct neighbors)
  // MQTT bridge connects remote zones via internet, so zero-hop packets
  // (which are meant for physical neighbors only) should not be forwarded
  if (packet->isRouteDirect() && packet->path_len == 0) {
    return;
  }
  
  // Don't send DIRECT packets where we are NOT in the path (not a relay for this packet)
  // This prevents forwarding packets between nodes in the same local zone
  // Only forward DIRECT packets that actually go through us as intermediate hop
  if (packet->isRouteDirect() && packet->path_len > 0) {
    // Check if our hash is in the path - if not, we're not relaying this packet
    bool we_are_in_path = false;
    uint8_t our_hash[PATH_HASH_SIZE];
    _self_id->copyHashTo(our_hash);
    
    for (uint16_t i = 0; i < packet->path_len; i += PATH_HASH_SIZE) {
      if (memcmp(&packet->path[i], our_hash, PATH_HASH_SIZE) == 0) {
        we_are_in_path = true;
        break;
      }
    }
    // If we're not in the path, don't forward to MQTT
    if (!we_are_in_path) {
      return;
    }
  }

  if (!_mqtt_client.connected()) {
    return;
  }

  // Check if we've already seen this packet (prevent loops)
  if (_seen_packets.hasSeen(packet)) {
    return;
  }

  // Add magic header
  _tx_buffer[0] = (BRIDGE_PACKET_MAGIC >> 8) & 0xFF;
  _tx_buffer[1] = BRIDGE_PACKET_MAGIC & 0xFF;

  // Reserve space for checksum (will be calculated later)
  // Position [2-3] reserved for checksum

  // Add timestamp (current time in seconds)
  uint32_t now = _rtc->getCurrentTime();
  _tx_buffer[4] = (now >> 24) & 0xFF;
  _tx_buffer[5] = (now >> 16) & 0xFF;
  _tx_buffer[6] = (now >> 8) & 0xFF;
  _tx_buffer[7] = now & 0xFF;

  // Write mesh packet to buffer (after magic, checksum, and timestamp)
  size_t payload_size = packet->writeTo(_tx_buffer + BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE + BRIDGE_TIMESTAMP_SIZE);

  if (payload_size == 0 || payload_size > (MAX_MQTT_PAYLOAD - BRIDGE_MAGIC_SIZE - BRIDGE_CHECKSUM_SIZE - BRIDGE_TIMESTAMP_SIZE)) {
    BRIDGE_DEBUG_PRINTLN("TX failed to write packet or packet too large, len=%d\n", payload_size);
    return;
  }

  // Calculate checksum over: [Timestamp 4 bytes] [Mesh Packet]
  // Now it's contiguous memory starting from position [4]
  uint16_t checksum = fletcher16(_tx_buffer + BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE, BRIDGE_TIMESTAMP_SIZE + payload_size);
  
  // Write checksum to reserved position
  _tx_buffer[2] = (checksum >> 8) & 0xFF;
  _tx_buffer[3] = checksum & 0xFF;

  size_t total_size = BRIDGE_MAGIC_SIZE + BRIDGE_TIMESTAMP_SIZE + BRIDGE_CHECKSUM_SIZE + payload_size;

  // Publish to our specific topic: <base_topic>/<repeater_id>
  if (_mqtt_client.publish(_publish_topic, _tx_buffer, total_size)) {
    BRIDGE_DEBUG_PRINTLN("TX to %s, len=%d type=%d timestamp=%u checksum=0x%04X\n", 
                         _publish_topic, payload_size, packet->getPayloadType(), now, checksum);
  } else {
    BRIDGE_DEBUG_PRINTLN("TX publish failed\n");
  }
}

void MQTTBridge::onPacketReceived(mesh::Packet *packet) {
  // Delegate to base class for duplicate check and queueing (consistent with RS232Bridge)
  handleReceivedPacket(packet);
}

// Private methods

void MQTTBridge::generateClientId() {
  // Use first 6 bytes of public key as unique identifier
  const uint8_t *pub_key = _self_id->pub_key;
  snprintf(_client_id_buf, sizeof(_client_id_buf), "%02x%02x%02x%02x%02x%02x", 
           pub_key[0], pub_key[1], pub_key[2], pub_key[3], pub_key[4], pub_key[5]);
}

bool MQTTBridge::reconnectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  unsigned long now = millis();
  if (now - _last_wifi_reconnect_attempt < WIFI_RECONNECT_INTERVAL) {
    return false;
  }

  _last_wifi_reconnect_attempt = now;

  // Get WiFi credentials from prefs
  const char *ssid = _prefs->bridge_wifi_ssid;
  const char *password = _prefs->bridge_wifi_password;

  if (ssid[0] == 0) {
    BRIDGE_DEBUG_PRINTLN("WiFi not configured!\n");
    return false;
  }

  BRIDGE_DEBUG_PRINTLN("WiFi disconnected, attempting reconnection\n");
  WiFi.disconnect();
  WiFi.begin(ssid, password);

  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 3000) {
    delay(100);
    yield(); // Feed watchdog
  }

  if (WiFi.status() == WL_CONNECTED) {
    BRIDGE_DEBUG_PRINTLN("WiFi reconnected, IP: %s\n", WiFi.localIP().toString().c_str());
    syncTimeNTP();
    return true;
  } else {
    BRIDGE_DEBUG_PRINTLN("WiFi reconnection failed!\n");
    return false;
  }
}

void MQTTBridge::syncTimeNTP() {
  BRIDGE_DEBUG_PRINTLN("Syncing time via NTP...\n");
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  
  // Wait for time sync (max 5 seconds)
  int retry = 0;
  while (sntp_get_sync_status() != SNTP_SYNC_STATUS_COMPLETED && ++retry < 10) {
    delay(500);
    yield(); // Feed watchdog during NTP sync
  }
  
  if (retry < 10) {
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);
    BRIDGE_DEBUG_PRINTLN("Time synced: %d-%02d-%02d %02d:%02d:%02d\n",
                         timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                         timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
    // Update RTC with NTP time
    _rtc->setCurrentTime((uint32_t)now);
  } else {
    BRIDGE_DEBUG_PRINTLN("Failed to sync time via NTP!\n");
  }
}

bool MQTTBridge::reconnect() {
  if (_mqtt_client.connected()) {
    return true;
  }

  unsigned long now = millis();
  if (now - _last_reconnect_attempt < RECONNECT_INTERVAL) {
    return false;
  }

  _last_reconnect_attempt = now;

  // Get parameters from prefs
  const char *broker = _prefs->bridge_mqtt_broker;
  uint16_t port =
      _prefs->bridge_mqtt_port > 0 ? _prefs->bridge_mqtt_port : (_prefs->bridge_mqtt_tls ? 8883 : 1883);
  const char *topic = _prefs->bridge_mqtt_topic;
  const char *client_id =
      _prefs->bridge_mqtt_client_id[0] != 0 ? _prefs->bridge_mqtt_client_id : _client_id_buf;
  const char *user = _prefs->bridge_mqtt_user[0] != 0 ? _prefs->bridge_mqtt_user : nullptr;
  const char *password = _prefs->bridge_mqtt_password[0] != 0 ? _prefs->bridge_mqtt_password : nullptr;

  BRIDGE_DEBUG_PRINTLN("Attempting MQTT connection to %s:%d as %s...\n", broker, port, client_id);

  bool connected;
  if (user && password) {
    connected = _mqtt_client.connect(client_id, user, password);
  } else {
    connected = _mqtt_client.connect(client_id);
  }

  if (connected) {
    BRIDGE_DEBUG_PRINTLN("MQTT connected! Free heap: %d bytes\n", ESP.getFreeHeap());

    // Subscribe to wildcard topic to receive from all other bridges: <base_topic>/+
    if (_mqtt_client.subscribe(_subscribe_topic)) {
      BRIDGE_DEBUG_PRINTLN("Subscribed to topic: %s\n", _subscribe_topic);
      BRIDGE_DEBUG_PRINTLN("Publishing to topic: %s\n", _publish_topic);
    } else {
      BRIDGE_DEBUG_PRINTLN("Failed to subscribe!\n");
    }

    return true;
  } else {
    int state = _mqtt_client.state();
    BRIDGE_DEBUG_PRINTLN("MQTT connection failed, rc=%d, free heap: %d bytes\n", state, ESP.getFreeHeap());
    
    // Disconnect on persistent errors to free resources
    if (state == -2 || state == -4) { // MQTT_CONNECT_FAILED or MQTT_CONNECTION_LOST
      _mqtt_client.disconnect();
    }
    return false;
  }
}

void MQTTBridge::mqttCallback(char *topic, uint8_t *payload, unsigned int length) {
  if (_instance) {
    _instance->onMqttMessage(topic, payload, length);
  }
}

void MQTTBridge::onMqttMessage(char *topic, uint8_t *payload, unsigned int length) {
  // Ignore packets from our own publish topic
  if (strcmp(topic, _publish_topic) == 0) {
    return; // This is our own packet, ignore it
  }
  
  // Validate minimum packet size
  if (length < BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE + BRIDGE_TIMESTAMP_SIZE) {
    BRIDGE_DEBUG_PRINTLN("RX packet too short, len=%d\n", length);
    return;
  }

  // Validate magic header
  uint16_t magic = (payload[0] << 8) | payload[1];
  if (magic != BRIDGE_PACKET_MAGIC) {
    BRIDGE_DEBUG_PRINTLN("RX invalid magic 0x%04X\n", magic);
    return;
  }

  BRIDGE_DEBUG_PRINTLN("RX from topic: %s, len=%d\n", topic, length);

  // Extract checksum
  uint16_t received_checksum = (payload[2] << 8) | payload[3];

  // Extract timestamp
  uint32_t packet_timestamp = ((uint32_t)payload[4] << 24) | 
                              ((uint32_t)payload[5] << 16) | 
                              ((uint32_t)payload[6] << 8) | 
                              (uint32_t)payload[7];
  
  BRIDGE_DEBUG_PRINTLN("RX timestamp=%u, now=%u\n", packet_timestamp, _rtc->getCurrentTime());

  // Check if packet is too old
  uint32_t now = _rtc->getCurrentTime();
  if (now > packet_timestamp) {
    uint32_t age_seconds = now - packet_timestamp;
    if (age_seconds > (MQTT_PACKET_TIMEOUT / 1000)) {
      BRIDGE_DEBUG_PRINTLN("RX packet too old, age=%d seconds, discarding\n", age_seconds);
      return;
    }
  }

  // Calculate payload size
  size_t payload_size = length - BRIDGE_MAGIC_SIZE - BRIDGE_CHECKSUM_SIZE - BRIDGE_TIMESTAMP_SIZE;
  uint8_t *mesh_payload = payload + BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE + BRIDGE_TIMESTAMP_SIZE;

  // Validate checksum (over timestamp + mesh packet)
  // Now it's contiguous memory starting from position [4]
  uint16_t calculated_checksum = fletcher16(payload + BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE, BRIDGE_TIMESTAMP_SIZE + payload_size);
  
  if (calculated_checksum != received_checksum) {
    BRIDGE_DEBUG_PRINTLN("RX checksum mismatch, rcv=0x%04X calc=0x%04X\n", received_checksum, calculated_checksum);
    return;
  }

  // Allocate mesh packet
  mesh::Packet *packet = _mgr->allocNew();
  if (!packet) {
    BRIDGE_DEBUG_PRINTLN("RX failed to allocate packet\n");
    return;
  }

  // Read mesh packet from buffer
  if (!packet->readFrom(mesh_payload, payload_size)) {
    BRIDGE_DEBUG_PRINTLN("RX failed to parse packet\n");
    _mgr->free(packet);
    return;
  }

  BRIDGE_DEBUG_PRINTLN("RX, len=%d type=%d\n", payload_size, packet->getPayloadType());

  onPacketReceived(packet);
}

#ifdef WITH_MQTT_TLS
bool MQTTBridge::loadCertFromFile(const char* filename, char* buffer, size_t max_size) {
  if (!FS_IMPL.exists(filename)) {
    return false;
  }

  auto file = FS_IMPL.open(filename, "r");
  if (!file) {
    BRIDGE_DEBUG_PRINTLN("Failed to open certificate file: %s\n", filename);
    return false;
  }

  size_t file_size = file.size();
  if (file_size == 0 || file_size >= max_size) {
    BRIDGE_DEBUG_PRINTLN("Certificate file size invalid: %s (%d bytes)\n", filename, file_size);
    file.close();
    return false;
  }

  size_t bytes_read = file.readBytes(buffer, file_size);
  buffer[bytes_read] = '\0'; // Null-terminate
  file.close();

  if (bytes_read != file_size) {
    BRIDGE_DEBUG_PRINTLN("Failed to read certificate file: %s\n", filename);
    return false;
  }

  BRIDGE_DEBUG_PRINTLN("Loaded certificate from %s (%d bytes)\n", filename, bytes_read);
  return true;
}

void MQTTBridge::configureTLS() {
  // CRITICAL: Set hostname for SNI (Server Name Indication) BEFORE any cert configuration
  // This is required for modern MQTT brokers that use SNI for TLS routing
  // Must be called before setInsecure() or setCACert()
  BRIDGE_DEBUG_PRINTLN("MQTT TLS: Setting hostname for SNI: %s\n", _broker_hostname);
  
  // Check if insecure mode is enabled in prefs or compile-time define
  bool insecure = _prefs->bridge_mqtt_tls_insecure;
#ifdef WITH_MQTT_TLS_INSECURE
  insecure = true;
#endif

  if (insecure) {
    // Skip certificate verification (not recommended for production)
    _wifi_client.setInsecure();
    BRIDGE_DEBUG_PRINTLN("MQTT TLS: Insecure mode enabled (certificate verification disabled)\n");
    return;
  }

  // Try to load CA certificate from file system (takes precedence over compile-time define)
  if (loadCertFromFile("/mqtt_ca.crt", _ca_cert_buffer, CERT_BUFFER_SIZE)) {
    _wifi_client.setCACert(_ca_cert_buffer);
    BRIDGE_DEBUG_PRINTLN("MQTT TLS: CA certificate loaded from file system\n");
  }
#ifdef WITH_MQTT_CA_CERT
  else {
    _wifi_client.setCACert(WITH_MQTT_CA_CERT);
    BRIDGE_DEBUG_PRINTLN("MQTT TLS: CA certificate configured from compile-time define\n");
  }
#else
  else {
    // No CA cert provided - use insecure mode
    _wifi_client.setInsecure();
    BRIDGE_DEBUG_PRINTLN("MQTT TLS: No CA certificate provided, using insecure mode\n");
  }
#endif
}
#endif

void MQTTBridge::getConnectionStatus(char *status_buf) {
  char *dp = status_buf;

  // WiFi status (compact format)
#ifdef ESP_PLATFORM
  wl_status_t wifi_status = WiFi.status();

  if (wifi_status == WL_CONNECTED) {
    dp += sprintf(dp, "WiFi: OK (%s)\n", WiFi.localIP().toString().c_str());
  }
  else {
    const char *status_str = "ERR";
    switch (wifi_status) {
    case WL_NO_SSID_AVAIL:
      status_str = "NO_SSID";
      break;
    case WL_CONNECT_FAILED:
      status_str = "FAILED";
      break;
    case WL_CONNECTION_LOST:
      status_str = "LOST";
      break;
    case WL_DISCONNECTED:
      status_str = "DISC";
      break;
    }
    dp += sprintf(dp, "WiFi: %s\n", status_str);
  }
#else
  dp += sprintf(dp, "WiFi: N/A\n");
#endif

  // MQTT broker connection status
  bool mqtt_connected = _mqtt_client.connected();
  dp += sprintf(dp, "MQTT: %s", mqtt_connected ? "OK" : "DISC");
}

#endif // WITH_MQTT_BRIDGE

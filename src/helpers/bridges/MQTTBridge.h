#pragma once

#include "helpers/bridges/BridgeBase.h"

#ifdef WITH_MQTT_BRIDGE

// PubSubClient has a default MQTT_MAX_PACKET_SIZE of 256 bytes which may be insufficient
// for full-size mesh packets (up to 260 bytes with bridge overhead). Set to 512 for safety
// and future protocol versions. Must be defined before including the library.
#ifndef MQTT_MAX_PACKET_SIZE
#define MQTT_MAX_PACKET_SIZE 512
#endif

#include <PubSubClient.h>
#include <WiFi.h>

#ifdef WITH_MQTT_TLS
#include <WiFiClientSecure.h>

/**
 * Wrapper for WiFiClientSecure that ensures SNI (Server Name Indication) is used
 * PubSubClient calls connect(IPAddress, port) which doesn't set SNI hostname
 * This wrapper intercepts and redirects to connect(hostname, port)
 */
class WiFiClientSecureWithSNI : public WiFiClientSecure {
private:
  char _hostname[128];
  uint16_t _port;
  
public:
  void setHostname(const char* hostname, uint16_t port) {
    strncpy(_hostname, hostname, sizeof(_hostname) - 1);
    _hostname[sizeof(_hostname) - 1] = '\0';
    _port = port;
  }
  
  // Override connect(IPAddress, port) to use hostname instead
  int connect(IPAddress ip, uint16_t port) override {
    if (_hostname[0] != '\0') {
      // Use hostname for SNI
      return WiFiClientSecure::connect(_hostname, _port);
    }
    // Fallback to IP if hostname not set
    return WiFiClientSecure::connect(ip, port);
  }
};
#endif

/**
 * @brief Bridge implementation using MQTT protocol for packet transport
 *
 * This bridge enables mesh packet transport over MQTT broker, allowing
 * nodes to communicate across the internet or local network infrastructure.
 *
 * Features:
 * - Publish/Subscribe communication through MQTT broker
 * - Network isolation using topic namespaces
 * - Duplicate packet detection using SimpleMeshTables tracking
 * - Automatic reconnection on connection loss
 * - Optional authentication (username/password)
 * - Optional TLS/SSL support (define WITH_MQTT_TLS)
 *
 * Packet Structure:
 * [2 bytes] Magic Header (0xC03E) - Used to identify MQTTBridge packets
 * [2 bytes] Fletcher-16 checksum
 * [n bytes] Mesh Packet Payload
 *
 * Configuration:
 * - Define WITH_MQTT_BRIDGE to enable this bridge
 * - All MQTT parameters (broker, port, topic, credentials) must be configured via CLI
 * - WiFi credentials must be configured via CLI
 * - See docs/cli_commands.md for available commands
 *
 * TLS Configuration:
 * - Define WITH_MQTT_TLS to enable TLS/SSL encryption
 * - Define WITH_MQTT_CA_CERT with CA certificate (optional, insecure mode if not set)
 * - Define WITH_MQTT_TLS_INSECURE to skip certificate verification (not recommended)
 *
 * Runtime TLS Configuration (via CLI):
 * - CA certificate can be stored in file system:
 *   - /mqtt_ca.crt - CA certificate for server verification
 * - Use CLI commands to manage certificate (see docs/cli_commands.md)
 * - Runtime certificate takes precedence over compile-time define
 *
 * Note: MQTT_MAX_PACKET_SIZE is automatically set to 512 bytes to support full-size
 * mesh packets (up to 260 bytes) with safety margin for future protocol versions.
 */
class MQTTBridge : public BridgeBase {
private:
#ifdef WITH_MQTT_TLS
  WiFiClientSecureWithSNI _wifi_client;
  
  // Static buffer for CA certificate (WiFiClientSecure stores pointer, not copy)
  static const size_t CERT_BUFFER_SIZE = 3072;
  char _ca_cert_buffer[CERT_BUFFER_SIZE];
#else
  WiFiClient _wifi_client;
#endif
  PubSubClient _mqtt_client;

  // Auto-generated client ID buffer (if not set in prefs or compile-time)
  char _client_id_buf[32] = {0};
  
  // Hostname for SNI (Server Name Indication) in TLS
  char _broker_hostname[128] = {0};

  /** Buffer for building MQTT messages */
  static const size_t MAX_MQTT_PAYLOAD = BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE + (MAX_TRANS_UNIT + 1);

  uint8_t _tx_buffer[MAX_MQTT_PAYLOAD];

  unsigned long _last_reconnect_attempt = 0;
  static const unsigned long RECONNECT_INTERVAL = 30000; // 30 seconds

  unsigned long _last_wifi_reconnect_attempt = 0;
  static const unsigned long WIFI_RECONNECT_INTERVAL = 30000; // 30 seconds

  /**
   * MQTT callback for received messages
   * Called by PubSubClient when a message arrives
   */
  static void mqttCallback(char *topic, uint8_t *payload, unsigned int length);
  static MQTTBridge *_instance;

  /**
   * Handle received MQTT message
   */
  void onMqttMessage(char *topic, uint8_t *payload, unsigned int length);

  /**
   * Attempt to connect/reconnect to MQTT broker
   */
  bool reconnect();

  /**
   * Generate unique client ID based on MAC address
   */
  void generateClientId();

  /**
   * Attempt to reconnect to WiFi
   */
  bool reconnectWiFi();

#ifdef WITH_MQTT_TLS
  /**
   * Configure TLS settings for secure connection
   */
  void configureTLS();

  /**
   * Load certificate from file system
   * @param filename Path to certificate file
   * @param buffer Buffer to store certificate content
   * @param max_size Maximum buffer size
   * @return true if loaded successfully
   */
  bool loadCertFromFile(const char* filename, char* buffer, size_t max_size);
#endif

public:
  /**
   * Constructs an MQTTBridge instance
   */
  MQTTBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc);

  /**
   * Initializes the MQTT bridge
   * - Connects to WiFi (if not already connected)
   * - Generates client ID if needed
   * - Connects to MQTT broker
   * - Subscribes to bridge topic
   */
  void begin() override;

  /**
   * Stops the MQTT bridge
   * - Disconnects from MQTT broker
   * - Disconnects from WiFi
   */
  void end() override;

  /**
   * Main loop handler
   * - Maintains MQTT connection
   * - Processes incoming messages
   * - Handles reconnection
   */
  void loop() override;

  /**
   * Sends a packet via MQTT bridge
   */
  void sendPacket(mesh::Packet *packet) override;

  /**
   * Called when a valid packet has been received from MQTT
   */
  void onPacketReceived(mesh::Packet *packet) override;
};

#endif // WITH_MQTT_BRIDGE

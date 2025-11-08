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

#ifndef WITH_MQTT_BROKER
#error WITH_MQTT_BROKER must be defined (e.g. "mqtt.example.com")
#endif

#ifndef WITH_MQTT_PORT
#define WITH_MQTT_PORT 1883
#endif

#ifndef WITH_MQTT_TOPIC
#define WITH_MQTT_TOPIC "meshcore/bridge"
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
 * - Optional TLS/SSL support
 *
 * Packet Structure:
 * [2 bytes] Magic Header (0xC03E) - Used to identify MQTTBridge packets
 * [2 bytes] Fletcher-16 checksum
 * [n bytes] Mesh Packet Payload
 *
 * Configuration:
 * - Define WITH_MQTT_BRIDGE to enable this bridge
 * - Define WITH_MQTT_BROKER with broker hostname/IP
 * - Define WITH_MQTT_PORT (optional, default 1883)
 * - Define WITH_MQTT_TOPIC (optional, default "meshcore/bridge")
 * - Define WITH_MQTT_USER (optional)
 * - Define WITH_MQTT_PASSWORD (optional)
 * - Define WITH_MQTT_CLIENT_ID (optional, auto-generated if not set)
 * - Define WITH_WIFI_SSID and WITH_WIFI_PASSWORD for WiFi connection
 *
 * Note: MQTT_MAX_PACKET_SIZE is automatically set to 512 bytes to support full-size
 * mesh packets (up to 260 bytes) with safety margin for future protocol versions.
 */
class MQTTBridge : public BridgeBase
{
private:
  WiFiClient _wifi_client;
  PubSubClient _mqtt_client;

  const char *_broker = WITH_MQTT_BROKER;
  uint16_t _port = WITH_MQTT_PORT;
  const char *_topic = WITH_MQTT_TOPIC;

#ifdef WITH_MQTT_USER
  const char *_user = WITH_MQTT_USER;
#else
  const char *_user = nullptr;
#endif

#ifdef WITH_MQTT_PASSWORD
  const char *_password = WITH_MQTT_PASSWORD;
#else
  const char *_password = nullptr;
#endif

#ifdef WITH_MQTT_CLIENT_ID
  const char *_client_id = WITH_MQTT_CLIENT_ID;
#else
  char _client_id[32]; // auto-generated
#endif

  /** Buffer for building MQTT messages */
  static const size_t MAX_MQTT_PAYLOAD =
      BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE + (MAX_TRANS_UNIT + 1);

  uint8_t _tx_buffer[MAX_MQTT_PAYLOAD];

  unsigned long _last_reconnect_attempt = 0;
  static const unsigned long RECONNECT_INTERVAL = 5000; // 5 seconds

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
   * Called when a packet needs to be transmitted via MQTT
   */
  void onPacketTransmitted(mesh::Packet *packet);

  /**
   * Called when a valid packet has been received from MQTT
   */
  void onPacketReceived(mesh::Packet *packet);
};

#endif // WITH_MQTT_BRIDGE

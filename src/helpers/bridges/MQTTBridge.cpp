#include "MQTTBridge.h"

#ifdef WITH_MQTT_BRIDGE

MQTTBridge *MQTTBridge::_instance = nullptr;

MQTTBridge::MQTTBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc)
    : BridgeBase(prefs, mgr, rtc), _mqtt_client(_wifi_client)
{
  _instance = this;
  _mqtt_client.setServer(_broker, _port);
  _mqtt_client.setCallback(mqttCallback);

#ifndef WITH_MQTT_CLIENT_ID
  generateClientId();
#endif
}

void MQTTBridge::generateClientId()
{
  uint8_t mac[6];
  WiFi.macAddress(mac);
  snprintf(_client_id, sizeof(_client_id), "meshcore-%02X%02X%02X",
           mac[3], mac[4], mac[5]);
}

void MQTTBridge::begin()
{
  // Connect to WiFi if not already connected
  if (WiFi.status() != WL_CONNECTED)
  {
#ifdef WITH_WIFI_SSID
    WiFi.begin(WITH_WIFI_SSID, WITH_WIFI_PASSWORD);
    Serial.print("Connecting to WiFi");

    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 30000)
    {
      delay(500);
      Serial.print(".");
    }
    Serial.println();

    if (WiFi.status() == WL_CONNECTED)
    {
      Serial.print("WiFi connected, IP: ");
      Serial.println(WiFi.localIP());
    }
    else
    {
      Serial.println("WiFi connection failed!");
      return;
    }
#else
    Serial.println("WiFi not configured!");
    return;
#endif
  }

  // Initial connection attempt
  reconnect();
  _initialized = true;
}

void MQTTBridge::end()
{
  if (_mqtt_client.connected())
  {
    _mqtt_client.disconnect();
  }
  WiFi.disconnect();
  _initialized = false;
}

bool MQTTBridge::reconnect()
{
  if (_mqtt_client.connected())
  {
    return true;
  }

  unsigned long now = millis();
  if (now - _last_reconnect_attempt < RECONNECT_INTERVAL)
  {
    return false;
  }

  _last_reconnect_attempt = now;

  Serial.print("Attempting MQTT connection to ");
  Serial.print(_broker);
  Serial.print(":");
  Serial.print(_port);
  Serial.print(" as ");
  Serial.print(_client_id);
  Serial.print("...");

  bool connected;
  if (_user && _password)
  {
    connected = _mqtt_client.connect(_client_id, _user, _password);
  }
  else
  {
    connected = _mqtt_client.connect(_client_id);
  }

  if (connected)
  {
    Serial.println(" connected!");

    // Subscribe to bridge topic
    if (_mqtt_client.subscribe(_topic))
    {
      Serial.print("Subscribed to topic: ");
      Serial.println(_topic);
    }
    else
    {
      Serial.println("Failed to subscribe!");
    }

    return true;
  }
  else
  {
    Serial.print(" failed, rc=");
    Serial.println(_mqtt_client.state());
    return false;
  }
}

void MQTTBridge::loop()
{
  if (!_mqtt_client.connected())
  {
    reconnect();
  }

  if (_mqtt_client.connected())
  {
    _mqtt_client.loop();
  }
}

void MQTTBridge::mqttCallback(char *topic, uint8_t *payload, unsigned int length)
{
  if (_instance)
  {
    _instance->onMqttMessage(topic, payload, length);
  }
}

void MQTTBridge::onMqttMessage(char *topic, uint8_t *payload, unsigned int length)
{
  // Validate minimum packet size
  if (length < BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE)
  {
    Serial.println("MQTT: Packet too short");
    return;
  }

  // Validate magic header
  uint16_t magic = (payload[0] << 8) | payload[1];
  if (magic != BRIDGE_PACKET_MAGIC)
  {
    Serial.println("MQTT: Invalid magic header");
    return;
  }

  // Extract checksum
  uint16_t received_checksum = (payload[2] << 8) | payload[3];

  // Calculate payload size
  size_t payload_size = length - BRIDGE_MAGIC_SIZE - BRIDGE_CHECKSUM_SIZE;
  uint8_t *mesh_payload = payload + BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE;

  // Validate checksum
  if (!validateChecksum(mesh_payload, payload_size, received_checksum))
  {
    Serial.println("MQTT: Checksum validation failed");
    return;
  }

  // Allocate mesh packet
  mesh::Packet *packet = _mgr->allocNew();
  if (!packet)
  {
    Serial.println("MQTT: Failed to allocate packet");
    return;
  }

  // Read mesh packet from buffer
  if (!packet->readFrom(mesh_payload, payload_size))
  {
    Serial.println("MQTT: Failed to read packet");
    _mgr->free(packet);
    return;
  }

  Serial.print(getLogDateTime());
  Serial.printf(": MQTT RX, len=%d, type=%d\n", payload_size, packet->getPayloadType());

  // Forward to mesh network
  handleReceivedPacket(packet);
}

void MQTTBridge::onPacketTransmitted(mesh::Packet *packet)
{
  if (!_mqtt_client.connected())
  {
    return;
  }

  // Check if we've already seen this packet (prevent loops)
  if (_seen_packets.hasSeen(packet))
  {
    return;
  }

  // Write mesh packet to buffer
  size_t payload_size = packet->writeTo(_tx_buffer + BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE);

  if (payload_size == 0 || payload_size > (MAX_MQTT_PAYLOAD - BRIDGE_MAGIC_SIZE - BRIDGE_CHECKSUM_SIZE))
  {
    Serial.println("MQTT: Failed to write packet or packet too large");
    return;
  }

  // Add magic header
  _tx_buffer[0] = (BRIDGE_PACKET_MAGIC >> 8) & 0xFF;
  _tx_buffer[1] = BRIDGE_PACKET_MAGIC & 0xFF;

  // Calculate and add checksum
  uint16_t checksum = fletcher16(_tx_buffer + BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE, payload_size);
  _tx_buffer[2] = (checksum >> 8) & 0xFF;
  _tx_buffer[3] = checksum & 0xFF;

  size_t total_size = BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE + payload_size;

  // Publish to MQTT
  if (_mqtt_client.publish(_topic, _tx_buffer, total_size))
  {
    Serial.print(getLogDateTime());
    Serial.printf(": MQTT TX, len=%d, type=%d\n", payload_size, packet->getPayloadType());
  }
  else
  {
    Serial.println("MQTT: Publish failed");
  }
}

void MQTTBridge::sendPacket(mesh::Packet *packet)
{
  // Forward to onPacketTransmitted for actual MQTT publishing
  onPacketTransmitted(packet);
}

void MQTTBridge::onPacketReceived(mesh::Packet *packet)
{
  // This is called by handleReceivedPacket() after duplicate check
  // Packet is already queued for mesh processing
}

#endif // WITH_MQTT_BRIDGE

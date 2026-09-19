## 1) PUBLISH - Topic Name
**Message:** PUBLISH
**Target Field's path:** Topic Name
**Threat Model:**
- **Attack Assumption:**
In the target IoT deployment, a cloud-hosted MQTT broker manages device communication for IoT sensors and industrial actuators over the MQTT protocol (OASIS MQTT v3.1.1).
We assume: (i) the MQTT broker requires TLS and username/password authentication for connecting clients; (ii) however, all devices of the same product model share identical hardcoded MQTT credentials embedded in the device firmware — a well-documented vulnerability pattern affecting numerous commercial IoT products; (iii) the attacker has obtained these shared credentials by purchasing one device of the same model and extracting the firmware; (iv) the MQTT broker authenticates connecting clients at the product-model level ("this is a legitimate device of model X") but does not enforce per-device topic-level ACLs — any authenticated client can publish to or subscribe to any topic, including topics belonging to other devices of the same model; and (v) the attacker has identified a sensitive actuator control topic on the broker (e.g., `factory/plc/cmd`) through firmware analysis, which reveals the topic naming convention used by all devices of this model.
- **Attacker Capability:**
The attacker is restricted to only establish one authenticated MQTT session with the broker using the shared credentials and send at most one PUBLISH packet.

**Attack Procedure:**
The attacker first extracts the hardcoded MQTT credentials from a device of the same model via firmware analysis. The attacker then establishes an authenticated MQTT session by sending a CONNECT packet with the shared credentials (Username Flag and Password Flag set to 1), a unique Client Identifier, and standard parameters, receiving a CONNACK with return code 0 (Connection Accepted). The attacker then crafts an Attack Message PUBLISH, ensuring that the fixed header contains a valid packet type (PUBLISH) and the variable header contains a well-formed Topic Name. Specifically, the attacker sets the Topic Name to `factory/plc/cmd` (the target PLC controller's command topic, discovered through firmware analysis of the topic naming convention) and the payload to `{"action":"emergency_stop"}` (a valid command format recognized by the PLC controller, also obtained from firmware analysis). The QoS level is set to 0 (at most once delivery) and the Retain flag is set to 0. The attacker then sends the crafted PUBLISH packet to the broker.

After the broker receives the PUBLISH, per MQTT v3.1.1 Section 3.3.1, it matches the Topic Name against all active subscriptions. The broker accepts the message because the attacker is authenticated with valid credentials; it does not verify whether this specific device connection is authorized to publish to this particular topic. All clients subscribed to `factory/plc/cmd` (including the legitimate PLC controller) receive a copy of the attacker's message. The PLC controller parses the payload as a valid command and executes the emergency stop, halting the production line. The PoC is successful if the PLC controller receives and executes the attacker's crafted command, causing an unauthorized production shutdown.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "mqtt_fixed_header": {
    "packet_type": "PUBLISH",
    "dup": 0,
    "qos": 0,
    "retain": 0
  },
  "mqtt_variable_header": {
    "topic_name": "factory/plc/cmd"
  },
  "mqtt_payload": "{\"action\":\"emergency_stop\"}"
}

**Classification:**
ATTACK


## 2) SUBSCRIBE - Topic Filter
**Message:** SUBSCRIBE
**Target Field's path:** Topic Filter
**Threat Model:**
- **Attack Assumption:**
In the target IoT deployment, a cloud-hosted MQTT broker manages device communication for IoT sensors and industrial actuators over the MQTT protocol (OASIS MQTT v3.1.1).
We assume: (i) the MQTT broker requires TLS and username/password authentication for connecting clients; (ii) however, all devices of the same product model share identical hardcoded MQTT credentials embedded in the device firmware — a well-documented vulnerability pattern affecting numerous commercial IoT products; (iii) the attacker has obtained these shared credentials by purchasing one device of the same model and extracting the firmware; (iv) the MQTT broker authenticates connecting clients at the product-model level ("this is a legitimate device of model X") but does not enforce per-device topic-level ACLs — any authenticated client can subscribe to any topic, including topics belonging to other devices of the same model; and (v) the broker manages multiple devices of the same model, each publishing sensitive operational data (e.g., sensor readings, device status, control command acknowledgments) to device-specific topic hierarchies.
- **Attacker Capability:**
The attacker is restricted to only establish one authenticated MQTT session with the broker using the shared credentials and send at most one SUBSCRIBE packet.

**Attack Procedure:**
The attacker first extracts the hardcoded MQTT credentials from a device of the same model via firmware analysis. The attacker then establishes an authenticated MQTT session by sending a CONNECT packet with the shared credentials (Username Flag and Password Flag set to 1), a unique Client Identifier, and standard parameters, receiving a CONNACK with return code 0 (Connection Accepted). The attacker then crafts an Attack Message SUBSCRIBE, ensuring that the fixed header has the reserved flag bits set correctly (0x82) and the variable header contains a valid Packet Identifier. Specifically, the attacker sets the Topic Filter in the payload to `#` (the multi-level wildcard character defined in MQTT v3.1.1 Section 4.7.1.2), which matches "any topic at any level of the topic hierarchy." The Requested QoS is set to 0. The attacker then sends the crafted SUBSCRIBE packet to the broker.

After the broker processes the SUBSCRIBE, per MQTT v3.1.1 Section 3.8.4, it returns a SUBACK confirming the subscription. The broker accepts the wildcard subscription because the attacker is authenticated with valid credentials; it does not restrict which topics this device connection may observe. From this point, the broker delivers a copy of every message published by any device on the broker to the attacker's client. This includes sensitive operational data from all other devices of the same model: sensor readings, control command acknowledgments, device credentials or tokens exchanged over MQTT topics, and internal system status messages. The PoC is successful if the attacker receives messages from topics belonging to other devices, demonstrating unauthorized cross-device eavesdropping.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "mqtt_fixed_header": {
    "packet_type": "SUBSCRIBE",
    "reserved_flags": 2
  },
  "mqtt_variable_header": {
    "packet_identifier": 1
  },
  "mqtt_payload": {
    "topic_filters": [
      {
        "topic_filter": "#",
        "requested_qos": 0
      }
    ]
  }
}

**Classification:**
ATTACK


## 3) CONNECT - Will Topic
**Message:** CONNECT
**Target Field's path:** Will Topic
**Threat Model:**
- **Attack Assumption:**
In the target IoT deployment, a cloud-hosted MQTT broker manages device communication for IoT sensors and industrial actuators over the MQTT protocol (OASIS MQTT v3.1.1).
We assume: (i) the MQTT broker requires TLS and username/password authentication for connecting clients; (ii) however, all devices of the same product model share identical hardcoded MQTT credentials embedded in the device firmware — a well-documented vulnerability pattern affecting numerous commercial IoT products; (iii) the attacker has obtained these shared credentials by purchasing one device of the same model and extracting the firmware; (iv) the MQTT broker authenticates connecting clients at the product-model level ("this is a legitimate device of model X") but does not enforce per-device topic-level ACLs — any authenticated client can set Last Will and Testament (LWT) messages targeting any topic, including topics belonging to other devices of the same model; and (v) the attacker has identified a sensitive actuator control topic on the broker (e.g., `building/hvac/setpoint`) through firmware analysis of the topic naming convention.
- **Attacker Capability:**
The attacker is restricted to only send one authenticated MQTT CONNECT packet to the broker using the shared credentials and then terminate the TCP connection.

**Attack Procedure:**
The attacker first extracts the hardcoded MQTT credentials from a device of the same model via firmware analysis. The attacker crafts an Attack Message CONNECT, ensuring that the variable header contains a valid Protocol Name ("MQTT"), Protocol Level (4), and well-formed Connect Flags. Specifically, the attacker sets the Username Flag and Password Flag to 1 to provide the shared credentials, the Will Flag to 1 (enabling the Last Will and Testament feature defined in MQTT v3.1.1 Section 3.1.2.5), the Will QoS to 1 (at least once delivery), and the Will Retain to 1 (the broker stores the Will Message as the retained message on the Will Topic). In the payload, the attacker provides the shared username and password, sets the Will Topic to `building/hvac/setpoint` (the HVAC system's temperature control topic belonging to another device) and the Will Message to `{"temp_c":55,"mode":"heat"}` (an extreme temperature setpoint). The Clean Session flag is set to 1 and Keep Alive to 0. The attacker then sends the crafted CONNECT to the broker, receives a CONNACK with return code 0 (Connection Accepted) — the broker accepts the connection because the credentials are valid — and immediately terminates the TCP connection ungracefully (e.g., by sending a TCP RST without sending a DISCONNECT packet).

After the broker detects the ungraceful disconnection, per MQTT v3.1.1 Section 3.1.2.5, it MUST publish the Will Message to the Will Topic "as if a normal PUBLISH message had been received." The broker does not verify whether the disconnected client was authorized to publish to the Will Topic, only that it was authenticated at connection time. Because Will Retain is set to 1, the broker stores this message as the retained message for `building/hvac/setpoint`. All current subscribers to this topic (including the legitimate HVAC controller) immediately receive the malicious setpoint command. Any future subscriber to this topic also receives the retained message upon subscribing. The HVAC system sets the building temperature to 55°C, creating unsafe environmental conditions. The PoC is successful if the HVAC controller receives the retained malicious setpoint and adjusts the temperature accordingly.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "mqtt_fixed_header": {
    "packet_type": "CONNECT",
    "flags": 0
  },
  "mqtt_variable_header": {
    "protocol_name": "MQTT",
    "protocol_level": 4,
    "connect_flags": {
      "username_flag": 1,
      "password_flag": 1,
      "will_retain": 1,
      "will_qos": 1,
      "will_flag": 1,
      "clean_session": 1
    },
    "keep_alive": 0
  },
  "mqtt_payload": {
    "client_identifier": "attacker-will-01",
    "will_topic": "building/hvac/setpoint",
    "will_message": "{\"temp_c\":55,\"mode\":\"heat\"}",
    "username": "device-user",
    "password": "FirmwareExtracted!2024"
  }
}

**Classification:**
ATTACK


## 4) CONNECT - Client Identifier
**Message:** CONNECT
**Target Field's path:** Client Identifier
**Threat Model:**
- **Attack Assumption:**
In the target IoT deployment, a cloud-hosted MQTT broker manages device communication for IoT sensors and industrial actuators over the MQTT protocol (OASIS MQTT v3.1.1).
We assume: (i) the MQTT broker requires TLS and username/password authentication for connecting clients; (ii) however, all devices of the same product model share identical hardcoded MQTT credentials embedded in the device firmware — a well-documented vulnerability pattern affecting numerous commercial IoT products; (iii) the attacker has obtained these shared credentials by purchasing one device of the same model and extracting the firmware; (iv) the MQTT broker authenticates connecting clients at the product-model level ("this is a legitimate device of model X") but does not enforce unique Client Identifier policies or rate-limit connection attempts with duplicate Client Identifiers; (v) the attacker has identified the Client Identifier of a legitimate connected device (e.g., `sensor-temperature-01`) through firmware analysis of the predictable Client Identifier generation scheme (e.g., based on MAC address or serial number prefix) or through subscribing to a status topic that reveals connected device identifiers; and (vi) the MQTT broker follows the MQTT v3.1.1 specification for handling duplicate Client Identifiers.
- **Attacker Capability:**
The attacker is restricted to only send one authenticated MQTT CONNECT packet to the broker using the shared credentials and observe the broker's subsequent behavior.

**Attack Procedure:**
The attacker first extracts the hardcoded MQTT credentials and the Client Identifier generation scheme from a device of the same model via firmware analysis. The attacker crafts an Attack Message CONNECT, ensuring that the variable header contains a valid Protocol Name ("MQTT"), Protocol Level (4), and well-formed Connect Flags. Specifically, the attacker sets the Username Flag and Password Flag to 1 and provides the shared credentials in the payload. Crucially, the attacker sets the Client Identifier in the payload to `sensor-temperature-01` — the same Client Identifier used by a legitimate, currently connected temperature sensor, derived from the predictable naming scheme discovered in firmware. The Clean Session flag is set to 0, so the broker will deliver any stored messages and preserve existing subscriptions associated with this Client Identifier. The attacker then sends the crafted CONNECT packet to the broker.

The broker accepts the connection because the credentials are valid (they are shared across all devices of this model). Per MQTT v3.1.1 Section 3.1.4, "If the ClientId represents a Client already connected to the Server then the Server MUST disconnect the existing Client [MQTT-3.1.4-2]." When the broker receives the attacker's CONNECT with the duplicate Client Identifier, it forcefully disconnects the legitimate `sensor-temperature-01` device and accepts the attacker's connection. The legitimate device loses its connection, all its active subscriptions, and can no longer publish sensor data or receive control commands. Because Clean Session is 0, the attacker inherits the device's persistent session state including stored subscriptions, receiving messages originally intended for the legitimate sensor. The PoC is successful if the legitimate device is disconnected from the broker and the attacker's connection is accepted in its place.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "mqtt_fixed_header": {
    "packet_type": "CONNECT",
    "flags": 0
  },
  "mqtt_variable_header": {
    "protocol_name": "MQTT",
    "protocol_level": 4,
    "connect_flags": {
      "username_flag": 1,
      "password_flag": 1,
      "will_retain": 0,
      "will_qos": 0,
      "will_flag": 0,
      "clean_session": 0
    },
    "keep_alive": 60
  },
  "mqtt_payload": {
    "client_identifier": "sensor-temperature-01",
    "username": "device-user",
    "password": "FirmwareExtracted!2024"
  }
}

**Classification:**
ATTACK


## 5) CONNECT - Keep Alive
**Message:** CONNECT
**Target Field's path:** Keep Alive
**Threat Model:**
- **Attack Assumption:**
In the target IoT deployment, a cloud-hosted MQTT broker manages device communication for IoT sensors and industrial actuators over the MQTT protocol (OASIS MQTT v3.1.1).
We assume: (i) the MQTT broker requires TLS and username/password authentication for connecting clients; (ii) however, all devices of the same product model share identical hardcoded MQTT credentials embedded in the device firmware — a well-documented vulnerability pattern affecting numerous commercial IoT products; (iii) the attacker has obtained these shared credentials by purchasing one device of the same model and extracting the firmware; (iv) the MQTT broker authenticates connecting clients at the product-model level ("this is a legitimate device of model X") but does not enforce per-device topic-level ACLs; and (v) the broker manages multiple devices of the same model, each serving different end-user customers.
- **Attacker Capability:**
The attacker is restricted to only establish one authenticated MQTT session with the broker using the shared credentials and send at most one additional control packet.
**Security Analysis:**
Keep Alive is a 16-bit value in the CONNECT variable header defined in MQTT v3.1.1 Section 3.1.2.10, specifying the maximum time interval in seconds between control packets sent by the client. If the broker does not receive any MQTT control packet from the client within 1.5 times the Keep Alive period, it closes the network connection as if the client had disconnected. Manipulating the Keep Alive value in a crafted CONNECT packet has no meaningful security impact on other devices or the broker's core messaging functionality: setting it to 0 disables the keep-alive mechanism for the attacker's own connection, meaning the broker will never close the attacker's session due to inactivity — this only affects the attacker's own session lifetime and has no effect on any other connected device; setting it to a very small value (e.g., 1 second) causes the broker to aggressively time out the attacker's own connection if the attacker does not send frequent PINGREQ packets, affecting only the attacker; setting it to the maximum value (65535 seconds, approximately 18.2 hours) merely extends the attacker's own session timeout window. In all cases, Keep Alive does not influence the broker's message routing decisions for other devices, does not affect topic-level access control or authentication policies, does not alter the delivery of messages between other publishers and subscribers, and does not expose any data belonging to other devices. The Keep Alive field is a per-connection session management parameter that only governs liveness detection for the connection it belongs to. Even with shared credentials granting the attacker a valid authenticated session, the Keep Alive value cannot be leveraged to affect any device other than the attacker's own connection.

**Classification:**
SAFE


## 6) PUBLISH - QoS Level
**Message:** PUBLISH
**Target Field's path:** QoS Level
**Threat Model:**
- **Attack Assumption:**
In the target IoT deployment, a cloud-hosted MQTT broker manages device communication for IoT sensors and industrial actuators over the MQTT protocol (OASIS MQTT v3.1.1).
We assume: (i) the MQTT broker requires TLS and username/password authentication for connecting clients; (ii) however, all devices of the same product model share identical hardcoded MQTT credentials embedded in the device firmware — a well-documented vulnerability pattern affecting numerous commercial IoT products; (iii) the attacker has obtained these shared credentials by purchasing one device of the same model and extracting the firmware; (iv) the MQTT broker authenticates connecting clients at the product-model level ("this is a legitimate device of model X") but does not enforce per-device topic-level ACLs; and (v) the broker manages multiple devices of the same model, each serving different end-user customers.
- **Attacker Capability:**
The attacker is restricted to only establish one authenticated MQTT session with the broker using the shared credentials and send at most one PUBLISH packet.
**Security Analysis:**
QoS Level is a 2-bit field in the PUBLISH fixed header defined in MQTT v3.1.1 Section 3.3.1.2, controlling the delivery assurance of the published message. QoS 0 (at most once) provides fire-and-forget delivery with no broker acknowledgment; QoS 1 (at least once) requires the broker to acknowledge receipt with a PUBACK packet; QoS 2 (exactly once) uses a four-step handshake (PUBLISH, PUBREC, PUBREL, PUBCOMP) to guarantee the message is delivered exactly once. Manipulating the QoS Level in a crafted PUBLISH packet has no meaningful security impact on other devices or the broker's state: changing QoS from 0 to 2 only increases the reliability with which the attacker's own message is delivered to the broker, but does not alter which subscribers receive the message, does not bypass topic ACLs or authentication requirements, and does not modify the message content or topic routing behavior. The set of subscribers who receive a message published to a given topic is identical regardless of the QoS level used by the publisher — a message published to topic X with QoS 0 reaches exactly the same set of subscribers as the same message published with QoS 2. Per MQTT v3.1.1 Section 3.8.4, each subscriber's actual delivery QoS is the minimum of the publisher's QoS and the subscriber's requested QoS, but this only affects delivery guarantees (whether duplicates or losses are possible), not access control or message routing. The QoS field carries no subscriber data, credentials, or session state, and cannot be leveraged for unauthorized cross-device access or denial of service to other devices. Even with shared credentials granting the attacker a valid authenticated session, the QoS Level value cannot be used to influence the broker's behavior toward any device other than the attacker's own message delivery.

**Classification:**
SAFE

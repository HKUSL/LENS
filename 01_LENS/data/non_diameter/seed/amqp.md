## 1) OPEN - max-frame-size
**Message:** OPEN
**Target Performative-Field's path:** max-frame-size
**Threat Model:**
- **Attack Assumption:**
In an enterprise message-oriented middleware deployment, an AMQP 1.0 broker (e.g., Apache Qpid Broker-J, Apache ActiveMQ Artemis) handles message routing for multiple tenants and microservices over the AMQP 1.0 protocol (OASIS Standard, October 2012).
We assume: (i) the victim AMQP broker's listening port (TCP 5672) is reachable from the attacker's network due to misconfiguration or insufficient network segmentation — a common finding in cloud-native microservice deployments where message brokers are exposed to internal service meshes; (ii) the AMQP broker does not enforce TLS (AMQPS on port 5671) and accepts plaintext AMQP connections; (iii) the AMQP broker does not require SASL authentication for incoming connections (e.g., Apache Qpid Broker-J configured with ANONYMOUS authentication provider, or ActiveMQ Artemis with anonymous access enabled); (iv) the AMQP broker processes attacker-crafted AMQP frames according to the OASIS AMQP 1.0 Transport specification (Part 2, Section 2.7.1); and (v) the broker does not enforce a minimum value for the negotiated max-frame-size beyond the protocol-mandated MIN-MAX-FRAME-SIZE of 512 bytes.
- **Attacker Capability:**
The attacker can establish one or more AMQP 1.0 connections to the broker and send crafted AMQP performative frames.

**Attack Procedure:**
The attacker establishes a TCP connection to the broker on port 5672 and completes the AMQP protocol header exchange (sending the 8-byte header `AMQP\x00\x01\x00\x00`). The attacker then sends an OPEN performative frame with the max-frame-size field set to an extremely large value (e.g., 4294967295, the maximum uint32 value). Per the OASIS AMQP 1.0 specification Part 2, Section 2.7.1, the max-frame-size field in the OPEN performative "specifies the maximum frame size that the sending peer is able to accept on this connection." The specification states that "if this field is not set it means that the peer does not impose any specific limit" and that the negotiated maximum frame size is the minimum of the two peers' values.

However, the attack exploits the fact that many broker implementations allocate receive buffers based on the peer's advertised max-frame-size. The attacker proceeds as follows:

1. The attacker sends the AMQP protocol header and receives the broker's protocol header response.
2. The attacker sends an OPEN performative with `max-frame-size=4294967295` (0xFFFFFFFF) and `channel-max=65535`.
3. The broker, upon receiving this OPEN, may allocate memory buffers proportional to the advertised max-frame-size for the incoming connection's frame parsing. This is documented in CVE-2017-15701 (Apache Qpid Broker-J 6.1.0-6.1.4), where the broker failed to properly enforce maximum frame size limits.
4. The attacker opens multiple such connections in rapid succession (e.g., 100 connections), each advertising max-frame-size=4294967295.
5. Each connection causes the broker to allocate large memory buffers, rapidly exhausting the broker's heap memory.
6. The broker becomes unresponsive to legitimate client connections, or the JVM throws OutOfMemoryError and the broker process terminates.

The PoC is successful if the broker becomes unresponsive to legitimate AMQP clients or terminates due to memory exhaustion, causing a denial of service for all tenants sharing the broker.

**Attack Message:**
The following is the attack AMQP frame sequence represented in a fixed JSON structure. This frame sequence can be used to verify the PoC in a real environment.

{
  "amqp_header": {
    "protocol": "AMQP",
    "protocol_id": 0,
    "major": 1,
    "minor": 0,
    "revision": 0
  },
  "frames": [
    {
      "type": "AMQP",
      "channel": 0,
      "performative": "open",
      "fields": {
        "container-id": "attacker-client-001",
        "hostname": "broker.example.com",
        "max-frame-size": 4294967295,
        "channel-max": 65535,
        "idle-time-out": 0
      }
    }
  ]
}

**Classification:**
ATTACK


## 2) OPEN - properties
**Message:** OPEN
**Target Performative-Field's path:** properties
**Threat Model:**
- **Attack Assumption:**
In an enterprise message-oriented middleware deployment, an AMQP 1.0 broker (e.g., Apache Qpid Broker-J, Apache ActiveMQ Artemis) handles message routing for multiple tenants and microservices over the AMQP 1.0 protocol (OASIS Standard).
We assume: (i) the victim AMQP broker's listening port (TCP 5672) is reachable from the attacker's network; (ii) the AMQP broker does not enforce TLS and accepts plaintext AMQP connections; (iii) the AMQP broker does not require SASL authentication or uses a permissive authentication provider; (iv) the attacker can set the properties field in the OPEN performative to arbitrary key-value pairs; and (v) all other connection parameters (max-frame-size, channel-max, idle-time-out) remain at standard values.
- **Attacker Capability:**
The attacker can establish one AMQP 1.0 connection to the broker and send crafted AMQP performative frames.
**Security Analysis:**
The properties field in the OPEN performative (OASIS AMQP 1.0 Part 2, Section 2.7.1) is defined as a map of "the properties of the connection being opened." The specification states that "the properties map contains a set of fields intended to indicate information about the connection and its container." These are informational key-value pairs used for capability advertisement and metadata exchange between peers. Per the specification, the properties field is an opaque map that implementations MAY use to communicate implementation-specific information. Manipulating the properties field has no meaningful security impact on the broker or other connections: setting arbitrary key-value pairs only affects the metadata associated with the attacker's own connection; the broker does not make routing, authorization, or resource allocation decisions based on connection properties; other clients' connections, sessions, and links are completely unaffected by the properties of the attacker's connection; the properties field does not influence authentication outcomes, access control decisions, or message delivery semantics. The properties field is a per-connection metadata container that only affects how the broker logs or displays information about that specific connection.

**Classification:**
SAFE


## 3) OPEN - container-id
**Message:** OPEN
**Target Performative-Field's path:** container-id
**Threat Model:**
- **Attack Assumption:**
In an enterprise message-oriented middleware deployment, an AMQP 1.0 broker (e.g., Apache Qpid Broker-J, Apache ActiveMQ Artemis) handles message routing for multiple tenants and microservices over the AMQP 1.0 protocol (OASIS Standard).
We assume: (i) the victim AMQP broker's listening port (TCP 5672) is reachable from the attacker's network; (ii) the AMQP broker does not enforce TLS and accepts plaintext AMQP connections; (iii) the AMQP broker does not require SASL authentication or uses a permissive authentication provider; (iv) the attacker can set the container-id field in the OPEN performative to any arbitrary string; and (v) all other connection parameters remain at standard values.
- **Attacker Capability:**
The attacker can establish one AMQP 1.0 connection to the broker and send crafted AMQP performative frames.
**Security Analysis:**
The container-id field in the OPEN performative (OASIS AMQP 1.0 Part 2, Section 2.7.1) is defined as "the id of the source container" and is a mandatory string field. Per the specification, "each container has a globally unique container-id, which is used to identify the container amongst its peers." The container-id is used for identification and logging purposes. Manipulating the container-id value has no meaningful security impact on the broker or other connections: setting it to another client's container-id does not grant the attacker access to that client's sessions, links, or messages — the AMQP 1.0 specification does not define any mechanism by which a container-id value confers authorization or session ownership; the broker maintains separate connection state for each TCP connection regardless of the container-id value; link recovery (Section 2.6.13) uses the link name and terminus state, not the container-id alone, to resume deliveries; setting the container-id to an extremely long string is bounded by the broker's frame size limit and does not cause resource exhaustion beyond the single connection's frame buffer. The container-id field is a per-connection identifier that only affects how the broker logs and identifies the connection, with no impact on authorization, routing, or other clients' state.

**Classification:**
SAFE

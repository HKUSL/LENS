## 1) SLE-BIND-INVOCATION - invoker-credentials.the-protected
**Message:** SLE-BIND-INVOCATION
**Target Parameter's path:** invoker-credentials.the-protected
**Threat Model:**
- **Attack Assumption:**
In a satellite ground station network, SLE (Space Link Extension) services provide cross-support telemetry and telecommand relay between ground stations and mission control centers, as specified by CCSDS 913.1-B-2 (Internet Protocol for Transfer Services). The SLE Provider runs at the ground station and the SLE User runs at the mission control center, communicating over a TCP/IP network.
We assume: (i) the attacker has gained access to the network segment carrying SLE traffic between the SLE User and SLE Provider — this can occur via compromise of a network switch, a misconfigured VPN, or insider access at a shared ground station facility; (ii) the attacker can passively capture SLE PDUs on the wire and actively inject crafted PDUs; (iii) the SLE Provider uses ISP1 authentication as defined in CCSDS 913.1-B-2 Section 3.1, where the invoker-credentials contain a message digest computed via SHA-256 over the DER encoding of (time, random-number, user-name, password) per the HashInput ASN.1 type in Figure 3-1; (iv) the Provider's acceptable-delay parameter (the maximum time allowed between generation and verification of credentials, per Section 3.1.2.2.1) is configured to 120 seconds or more, a common setting for cross-agency interoperability to accommodate network latency and clock drift between agencies (NASA, ESA, JAXA); and (v) the specification only mandates a time-difference check for credential verification (Section 3.1.2.2.1: "The time in the credentials shall be checked against the current time. If the time difference is larger than acceptable, authentication shall fail.") — there is no requirement to track or reject previously seen random-number values, and open-source SLE implementations such as pySLE do not implement nonce replay detection.
- **Attacker Capability:**
The attacker can capture SLE PDUs from the network and inject crafted PDUs into the TCP stream between the SLE User and SLE Provider.

**Attack Procedure:**
The attacker captures a valid SLE-BIND-INVOCATION PDU from the network. This PDU contains the ISP1Credentials structure (Figure 3-2 of CCSDS 913.1-B-2): {time (8-byte CCSDS CDS time code), randomNumber (integer 0..2147483647), theProtected (SHA-256 message digest, 32 bytes)}. The attacker then replays this exact PDU from their own TCP connection to the SLE Provider, within the acceptable-delay window.

Per CCSDS 913.1-B-2 Section 3.1.2.2, the Provider validates ISP1 credentials by: (a) checking that |current_time - credential_time| ≤ acceptable-delay (Section 3.1.2.2.1); (b) re-computing the hash from (credential_time, credential_random_number, peer_user_name, peer_password) using the HashInput type (Figure 3-1) and SHA-256, then comparing with theProtected field (Sections 3.1.2.2.2 to 3.1.2.2.4). Since the entire credential structure is replayed verbatim, condition (b) is automatically satisfied. Condition (a) is satisfied as long as the replay occurs within the acceptable-delay window. The specification does not require the Provider to maintain a history of previously received (time, randomNumber) pairs for duplicate detection.

1. The attacker monitors the network and captures a complete SLE-BIND-INVOCATION PDU (BER-encoded ASN.1) from a legitimate SLE User session.
2. The attacker establishes a new TCP connection to the SLE Provider's responder-port and sends a valid TML context message (containing 'ISP1' protocol identifier, version 1, heartbeat-interval, and dead-factor per Section 2.5.3).
3. Within the acceptable-delay window (≤ 120 seconds from the original credential's time field), the attacker transmits the captured BIND PDU on the new TCP connection.
4. The SLE Provider processes the replayed BIND: it extracts the ISP1Credentials, verifies the SHA-256 hash against the configured shared password, and checks the time window. Both checks pass.
5. The Provider returns SLE-BIND-RETURN with result=positive, establishing an authenticated SLE session for the attacker.
6. The attacker now has full access to the bound SLE service (e.g., RAF for telemetry download, or CLTU for telecommand uplink), authenticated under the legitimate User's identity.

The PoC is successful if the attacker receives an SLE-BIND-RETURN with bind-result = 0 (positive result), demonstrating that the replayed credentials were accepted and an unauthorized SLE service session has been established.

**Attack Message:**
The following is the replayed SLE-BIND-INVOCATION PDU represented in a JSON structure. This structure maps directly to the ASN.1 BER-encoded PDU defined in CCSDS 913.1-B-2.

{
  "sle_pdu_type": "SLE-BIND-INVOCATION",
  "invoker_credentials": {
    "type": "used",
    "isp1_credentials": {
      "time": "2026-03-15T14:30:00.000Z",
      "random_number": 1847293650,
      "the_protected": "a3f2b7c9e1d04589bc7e1f2a3d5c6b8e92a1d3f4e8c7216b5a9304d1f2e6c8b7"
    }
  },
  "initiator_identifier": "MISSION-CONTROL-1",
  "responder_port_identifier": "SLE-Provider-Port-55529",
  "service_type": "rtnAllFrames",
  "version_number": 5,
  "service_instance_identifier": "sagr=GSC-SVALBARD.spack=SAT-ALPHA.rsl-fg=1.raf=onlc1"
}

**Classification:**
ATTACK


## 2) CLTU-TRANSFER-DATA-INVOCATION - cltu-data
**Message:** CLTU-TRANSFER-DATA-INVOCATION
**Target Parameter's path:** cltu-data
**Threat Model:**
- **Attack Assumption:**
In a satellite ground station network, the SLE Forward CLTU service (CCSDS 912.1-B-5) provides telecommand uplink capability: the SLE User at mission control sends CLTU (Command Link Transmission Unit) data to the SLE Provider at the ground station, which then radiates it to the spacecraft via the uplink antenna.
We assume: (i) the attacker has gained access to the network segment carrying SLE traffic between the SLE User and SLE Provider; (ii) a legitimate CLTU service session has been established (BIND completed with valid ISP1 credentials) between the authorized User and the Provider, with authentication-level set to 'bind' — per CCSDS 913.1-B-2 Section 2.3, when authentication-level is 'bind', only the BIND invocation and return are authenticated, and all subsequent PDUs including CLTU-TRANSFER-DATA are transmitted without credentials; (iii) the attacker can perform TCP session hijacking to inject segments into the existing connection — achievable on same-segment networks via ARP spoofing; (iv) the attacker can derive the expected-cltu-identification value by observing prior CLTU-TRANSFER-DATA exchanges or querying it from status reports; and (v) the FCLTU specification itself acknowledges this threat: per CCSDS 912.1-B-5 Section 2.8.3, "an attacker could 'hijack' an established FCLTU service instance and overwrite the commands in the PDUs to subvert or destroy the operation of the spacecraft."
- **Attacker Capability:**
The attacker can inject crafted SLE PDUs into the TCP connection between the SLE User and SLE Provider after the session has been established.

**Attack Procedure:**
After a legitimate CLTU-BIND is established with auth-level 'bind', the attacker injects a crafted CLTU-TRANSFER-DATA-INVOCATION PDU into the TCP stream. Because auth-level is 'bind', CLTU-TRANSFER-DATA invocations do not carry credentials (invoker-credentials is set to 'unused'). The PDU's cltu-data field contains a malicious CLTU wrapping unauthorized telecommand (TC) frames.

Per CCSDS 912.1-B-5 Section 2.8.2.3, the FCLTU service uses the monotonically increasing cltu-identification as a data integrity mechanism to "constrain the ability of a third party to inject additional command data." However, Section 2.8.3 explicitly acknowledges the residual risk: the specification "does not specify mechanisms that would prevent an attacker from intercepting the PDUs and replacing the contents of the data parameter." The prevention of such replacement attacks depends on unspecified mechanisms outside the SLE layer.

1. The attacker monitors the TCP stream and observes prior CLTU-TRANSFER-DATA exchanges to determine the expected-cltu-identification value (the next expected sequence number).
2. The attacker constructs a CLTU containing a malicious TC frame following CCSDS TC Space Data Link Protocol (CCSDS 232.0-B-4) format with the target spacecraft's Spacecraft ID (SCID) and Virtual Channel ID (VCID).
3. The attacker wraps the TC frame in a CLTU structure with proper start sequence (0xEB90), BCH codeblocks, and tail sequence (0xC5C5C5C5C5C5C579) as defined in CCSDS 231.0-B-4.
4. The attacker constructs a CLTU-TRANSFER-DATA-INVOCATION PDU with: invoker-credentials set to 'unused' (matching the auth-level 'bind' configuration), cltu-identification set to the expected sequence number, and cltu-data containing the malicious CLTU.
5. The attacker injects this BER-encoded PDU into the TCP stream using TCP session hijacking, ahead of the legitimate User's next CLTU-TRANSFER-DATA.
6. The SLE Provider accepts the PDU, validates the cltu-identification against the expected value (which matches), queues the CLTU, and radiates it to the spacecraft per Section 3.6.
7. The consequences, as stated by the FCLTU specification Section 2.8.4: "The consequences of not applying security to the FCLTU service are possible degradation and loss of ability to command the spacecraft, and even loss of the spacecraft itself."

The PoC is successful if the SLE Provider returns a CLTU-TRANSFER-DATA-RETURN with result = cltuRadiated, confirming that the malicious telecommand has been transmitted to the spacecraft.

**Attack Message:**
The following is the injected CLTU-TRANSFER-DATA-INVOCATION PDU represented in a JSON structure.

{
  "sle_pdu_type": "CLTU-TRANSFER-DATA-INVOCATION",
  "invoker_credentials": {
    "type": "unused",
    "isp1_credentials": null
  },
  "invoke_id": 42,
  "cltu_identification": 1001,
  "earliest_radiation_time": {
    "type": "known",
    "time": "2026-03-15T14:35:00.000Z"
  },
  "latest_radiation_time": {
    "type": "undefined"
  },
  "delay_time": 0,
  "radiation_notification": "produceNotification",
  "cltu_data": "EB90_01A2_03_TC_FRAME_SCID0x1AB_VCID0_CMDPAYLOAD_BCH_C5C5C5C5C5C5C579"
}

**Classification:**
ATTACK


## 3) SLE-PEER-ABORT-INVOCATION - peer-abort-diagnostic
**Message:** SLE-PEER-ABORT-INVOCATION
**Target Parameter's path:** peer-abort-diagnostic
**Threat Model:**
- **Attack Assumption:**
In a satellite ground station network, SLE sessions carry mission-critical telemetry and telecommand data. The SLE PEER-ABORT operation (CCSDS 913.1-B-2 Section 2.5.5) allows either peer to immediately terminate an active SLE association without requiring confirmation from the other side.
We assume: (i) the attacker has gained access to the network segment carrying SLE traffic between the SLE User and SLE Provider; (ii) an active SLE session exists between a legitimate SLE User and SLE Provider, carrying time-critical data (e.g., during a spacecraft orbital maneuver, launch phase, or emergency commanding window); (iii) the attacker can inject TCP segments into the existing SLE TCP connection — achievable through TCP session hijacking or ARP spoofing on a shared LAN segment at the ground station; (iv) the SLE PEER-ABORT is explicitly excluded from authentication at all authentication levels — per CCSDS 913.1-B-2 Section 2.3, even when authentication-level is 'all', "all invocations and returns, except the invocation of PEER-ABORT, shall be authenticated"; and (v) the PEER-ABORT is implemented as a single byte of TCP urgent data (Section 2.5.5 and 3.3.6.1.3.1), not as a BER-encoded ASN.1 PDU, making it trivially simple to construct and inject. The FCLTU specification (CCSDS 912.1-B-5 Section 3.12) also acknowledges this threat: "CLTU-PEER-ABORT does not carry an invoker-credentials parameter. It is conceivable that an intruder might use the CLTU-PEER-ABORT operation for a denial-of-service attack."
- **Attacker Capability:**
The attacker can inject TCP segments, specifically TCP urgent data, into an existing TCP connection between the SLE User and SLE Provider.

**Attack Procedure:**
The attacker injects a single byte of TCP urgent data containing a PEER-ABORT diagnostic code into the TCP stream of an active SLE session. Per CCSDS 913.1-B-2 Section 3.3.6.1.3.1, the PEER-ABORT diagnostic is transmitted "as one byte of urgent data using TCP-URGENT-DATA-request." Per Section 3.3.6.1.3.2, "When the TML is notified by TCP-URGENT-DATA-indication that urgent data are pending," it reads the diagnostic byte and immediately issues TML-PEER-ABORT-indication, causing the association to terminate. No ISP1 credential verification is performed for PEER-ABORT at any authentication level.

1. The attacker identifies an active SLE TCP connection between User and Provider by monitoring network traffic for SLE's characteristic BER-encoded ASN.1 PDU patterns on known service ports.
2. The attacker performs TCP session hijacking by predicting or observing TCP sequence numbers on the target connection (achievable on same-segment networks or via compromised switches providing port mirroring).
3. The attacker injects a single TCP segment with the URGENT flag set, containing one byte with a PEER-ABORT diagnostic code. Codes 0-127 are reserved for SLE transfer service diagnostics (Section 2.5.6); the attacker uses code 127 ('other reason') — a generic code that provides no indication of an attack, making the disruption appear as a transient error.
4. The receiving TML processes the urgent data per Section 3.3.6.1.3.2: it reads and discards all buffered data, extracts the diagnostic byte, closes the TCP connection, and issues TML-PEER-ABORT-indication to the higher layers.
5. The higher layers immediately transition the association to the UNBOUND state, tearing down the SLE service.
6. Impact depends on the disrupted service: (a) if the session carried CLTU forward data: pending telecommands in the radiation buffer may be discarded, and the spacecraft misses critical commanding during the outage; (b) if the session carried RAF return data: real-time telemetry delivery stops, and frames received by the ground station during the outage window are lost if the Provider does not buffer them; (c) during time-critical operations such as orbit maneuvers, the re-establishment delay may cause the loss of a one-time commanding opportunity.
7. The legitimate User must perform a complete re-BIND and re-START sequence to restore service.

The PoC is successful if an active SLE session is terminated by the injected PEER-ABORT, causing measurable loss of telemetry frames or telecommand capability during the disruption window, as confirmed by gaps in the User's received frame sequence count or the Provider's CLTU radiation log.

**Attack Message:**
The following is the injected SLE-PEER-ABORT byte transmitted as TCP urgent data.

{
  "sle_pdu_type": "SLE-PEER-ABORT-INVOCATION",
  "peer_abort_diagnostic": 127
}

**Classification:**
ATTACK


## 4) SLE-BIND-INVOCATION - service-instance-identifier
**Message:** SLE-BIND-INVOCATION
**Target Parameter's path:** service-instance-identifier
**Threat Model:**
- **Attack Assumption:**
In a satellite ground station network supporting multiple space missions, SLE services are identified by hierarchical service-instance-identifiers. A single ground station may host SLE services for multiple missions from different agencies.
We assume: (i) the attacker has legitimate SLE User credentials for Mission-A at a multi-mission ground station; (ii) the attacker manipulates the service-instance-identifier field in SLE-BIND-INVOCATION to target a different mission's service instance (e.g., changing spack=MISSION-A to spack=MISSION-B); and (iii) all other BIND parameters including valid ISP1 credentials are provided.
- **Attacker Capability:**
The attacker has valid SLE User credentials for one mission and can issue SLE-BIND-INVOCATION PDUs targeting arbitrary service-instance-identifiers.
**Security Analysis:**
The service-instance-identifier field in SLE-BIND-INVOCATION identifies the specific SLE service instance being requested. The SLE transfer service specifications define mandatory access control requirements: per CCSDS 911.1-B-5 Section 2.8.2.5, the RAF service "defines access control requirements and defines initiator-identifier and responder-identifier parameters of the service operation invocations and returns that are used to perform SLE transfer service access control." Per Section 3.2.2.11.1(a), if the initiator-identifier is not recognized by the responder as authorized for the requested service instance, the Provider returns bind-result = 'negative result' with diagnostic = 'access denied' ("the value of the initiator-identifier parameter is not recognized by the responder, e.g., the value does not identify the authorized initiator for this service instance"). The same access control mechanism is defined in CCSDS 912.1-B-5 Section 4.1.6 for FCLTU services. Furthermore, the ISP1 credential hash (HashInput per 913.1-B-2 Figure 3-1) includes the userName (initiator-identifier) and password, and different service instances can be configured with different passwords. Therefore, even if the naming convention for service-instance-identifiers is predictable, the Provider's access control check will reject the BIND for unauthorized initiator-identifier values. Manipulating the service-instance-identifier alone, without valid credentials and authorization for that specific service instance, does not grant access.

**Classification:**
SAFE


## 5) RAF-START-INVOCATION - requested-frame-quality
**Message:** RAF-START-INVOCATION
**Target Parameter's path:** requested-frame-quality
**Threat Model:**
- **Attack Assumption:**
In a satellite ground station network, the SLE Return All Frames (RAF) service (CCSDS 911.1-B-5) delivers telemetry frames from the ground station's receiver to the mission control center. The requested-frame-quality parameter in RAF-START-INVOCATION specifies a frame quality filter for delivery.
We assume: (i) the attacker has an established RAF-BIND session; (ii) the attacker manipulates the requested-frame-quality field to request 'all frames' (value 2) when only 'good frames only' (value 0) was intended; and (iii) the attacker expects to receive erred frames containing data from other missions' virtual channels.
- **Attacker Capability:**
The attacker has an established RAF-BIND session and can issue RAF-START-INVOCATION PDUs with arbitrary requested-frame-quality values.
**Security Analysis:**
The requested-frame-quality parameter in RAF-START-INVOCATION (CCSDS 911.1-B-5 Section 3.4.2.7) specifies which frames are to be delivered based on quality: 'good frames only', 'erred frames only', or 'all frames'. However, the RAF service defines a service management parameter called permitted-frame-quality-set (Section 3.10 / Table 3-11), which specifies "the set of frame quality criteria that the RAF service user can choose from to select which frames the RAF service provider shall deliver." This parameter is configured by service management and enforced by the Provider — the user can only select frame quality values that are within the permitted set. If the service management configuration only allows 'good frames only', a request for 'all frames' will be rejected. Furthermore, the RAF service delivers frames from a single physical channel as configured by service management (Section 2.4): it does not deliver frames from other missions' physical channels or frequency bands. Frame filtering is determined by the service instance's configured physical channel, not by the frame quality parameter. Erred frames on the configured channel are simply frames that failed error-correction decoding — they do not contain data from other missions. The requested-frame-quality parameter does not bypass access control, does not alter which physical channel is being monitored, and does not provide access to other missions' telemetry.

**Classification:**
SAFE


## 6) SLE-BIND-INVOCATION - version-number
**Message:** SLE-BIND-INVOCATION
**Target Parameter's path:** version-number
**Threat Model:**
- **Attack Assumption:**
In a satellite ground station network, SLE services use the version-number field in SLE-BIND-INVOCATION to negotiate the protocol version between User and Provider, as specified in CCSDS 913.1-B-2.
We assume: (i) the attacker has SLE User credentials and can issue SLE-BIND-INVOCATION PDUs; (ii) the attacker manipulates the version-number field to request unsupported or non-standard protocol versions; and (iii) all other protocol parameters (credentials, service-instance-identifier, service-type) are valid.
- **Attacker Capability:**
The attacker can issue SLE-BIND-INVOCATION PDUs with arbitrary version-number values.
**Security Analysis:**
The version-number field in SLE-BIND-INVOCATION specifies the highest SLE service version that the initiator supports. Per the SLE transfer service specifications (e.g., CCSDS 911.1-B-5 Section 3.2 for RAF, CCSDS 912.1-B-5 Section 3.2 for FCLTU), the responder compares this with its own supported version range. If the requested version is within the supported range, the responder returns SLE-BIND-RETURN with the agreed version. If the requested version is outside the supported range, the responder returns bind-result = 'version not supported' and the association is not established. Manipulating the version-number value has no meaningful security impact: setting it to a lower-than-current version may result in using an older but still valid protocol version with reduced features, which does not compromise confidentiality or integrity of telemetry/telecommand data; setting it to a higher-than-supported version causes the Provider to reject the BIND entirely. The version-number field does not influence ISP1 authentication mechanisms, does not bypass credential verification, does not alter the service instance's access control configuration, and does not affect the underlying TCP transport security. It is a purely functional negotiation parameter.

**Classification:**
SAFE


## 7) CLTU-TRANSFER-DATA-INVOCATION - cltu-identification
**Message:** CLTU-TRANSFER-DATA-INVOCATION
**Target Parameter's path:** cltu-identification
**Threat Model:**
- **Attack Assumption:**
In a satellite ground station network, the cltu-identification field in CLTU-TRANSFER-DATA-INVOCATION (CCSDS 912.1-B-5) serves as a monotonically increasing sequence number for CLTU tracking and data integrity.
We assume: (i) the attacker has an established CLTU-BIND session; (ii) the attacker manipulates the cltu-identification field to use out-of-sequence, duplicate, or very large values; and (iii) the cltu-data content itself contains a valid, authorized telecommand.
- **Attacker Capability:**
The attacker can issue CLTU-TRANSFER-DATA-INVOCATION PDUs with arbitrary cltu-identification values within an established session.
**Security Analysis:**
The cltu-identification parameter in CLTU-TRANSFER-DATA-INVOCATION (CCSDS 912.1-B-5 Section 3.6.2.5) is a monotonically increasing sequence number with mandatory Provider-side enforcement. Per Section 3.6.2.5.1, the parameter "shall contain a monotonically increasing sequence number" starting from the first-cltu-identification value set by CLTU-START. Per Section 2.8.2.3, "Failure of a CLTU to be accompanied by the expected sequence number causes that CLTU to be rejected (see 3.6.2.13.1 d))." The Provider maintains the expected-cltu-identification as a state parameter (Table 3-3) and validates each incoming CLTU against it. If the value does not match, the CLTU-TRANSFER-DATA operation returns a negative result. This strict enforcement means manipulating cltu-identification to out-of-sequence or duplicate values will cause the Provider to reject the transfer. The cltu-identification field serves as a data integrity mechanism that "constrains the ability of a third party to inject additional command data into an active FCLTU service instance" (Section 2.8.2.3). It does not alter telecommand content, does not bypass radiation authorization, and does not affect spacecraft command processing.

**Classification:**
SAFE


## 8) RAF-SCHEDULE-STATUS-REPORT-INVOCATION - reporting-cycle
**Message:** RAF-SCHEDULE-STATUS-REPORT-INVOCATION
**Target Parameter's path:** reporting-cycle
**Threat Model:**
- **Attack Assumption:**
In a satellite ground station network, the RAF-SCHEDULE-STATUS-REPORT operation (CCSDS 911.1-B-5) allows the SLE User to request periodic status reports from the Provider. The reporting-cycle parameter specifies the interval (in seconds) between consecutive status reports.
We assume: (i) the attacker has an established RAF-BIND session; (ii) the attacker manipulates the reporting-cycle field to request very frequent (e.g., 1-second) or very infrequent (e.g., 999999-second) status reports; and (iii) all other session parameters are within normal ranges.
- **Attacker Capability:**
The attacker can issue RAF-SCHEDULE-STATUS-REPORT-INVOCATION PDUs with arbitrary reporting-cycle values within an established session.
**Security Analysis:**
The reporting-cycle parameter in RAF-SCHEDULE-STATUS-REPORT-INVOCATION (CCSDS 911.1-B-5 Section 3.8) specifies the periodicity of status reports delivered by the Provider. The RAF service defines a service management parameter minimum-reporting-cycle (Table 3-11: "The minimum setting (in seconds) of reporting-cycle for status reports that the RAF service user may request"). The Provider enforces this minimum bound — if the requested cycle is below the configured minimum, the Provider returns a negative result. Manipulating the reporting-cycle value has no meaningful security impact: setting it to a very small value is bounded by the Provider's minimum-reporting-cycle configuration; setting it to a very large value simply means the User receives infrequent status updates, which is an operational inconvenience but not a security issue; setting it to 0 is interpreted as a request to stop periodic reporting. The reporting-cycle field does not influence telemetry frame delivery, does not alter frame content or quality, does not affect session authentication, does not bypass access control, and does not impact the spacecraft or ground station RF equipment. Status reports contain only aggregate statistics (delivered frame counts, lock status, production status) and do not expose sensitive telemetry content.

**Classification:**
SAFE

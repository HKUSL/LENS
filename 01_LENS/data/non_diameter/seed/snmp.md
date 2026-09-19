## 1) SetRequest - Variable-Binding-Value
**Message:** SetRequest (SR)
**Target Binding's path:** Variable-Binding-Value
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, an SNMP-managed network device (router/switch/firewall) runs an SNMP agent that accepts SNMPv2c management operations over UDP port 161 as defined in RFC 3416 (Protocol Operations for SNMPv2) and RFC 1157 (SNMPv1).
We assume: (i) the victim device's SNMP agent port (UDP 161) is reachable from the attacker's network segment due to insufficient access control lists or flat network architecture; (ii) the SNMP agent uses SNMPv2c with community-based authentication and the read-write community string is a well-known default value (e.g., "private") that has not been changed by the administrator; (iii) the SNMP agent processes all syntactically valid SetRequest-PDUs received on UDP 161 and modifies MIB objects accordingly per RFC 3416 Section 4.2.5; (iv) the target device implements the standard IF-MIB (RFC 2863) and the OID ifAdminStatus (1.3.6.1.2.1.2.2.1.7) is writable; and (v) the attacker has obtained the target device's IP address and knows that interface index 1 (ifIndex=1) corresponds to the device's primary uplink interface.
- **Attacker Capability:**
The attacker is restricted to only send one SNMP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message SetRequest-PDU, constructing a valid SNMPv2c message with version field set to 1 (SNMPv2c), the community string set to "private" (the default read-write community), and a request-id for correlating the response. The PDU contains a single variable binding with OID 1.3.6.1.2.1.2.2.1.7.1 (ifAdminStatus for interface 1) and value INTEGER 2 (down). The attacker sends this SNMP message to the victim device on UDP port 161.

After the SNMP agent processes the SetRequest, it sets ifAdminStatus.1 to down(2), which administratively disables the primary uplink interface. This causes immediate loss of network connectivity for all traffic traversing that interface, effectively isolating the device and all downstream networks. The agent responds with a GetResponse-PDU containing error-status noError(0) and the same variable binding, confirming the write succeeded. The PoC is successful if the target device's primary uplink interface transitions to administratively down state and network connectivity through that interface is lost.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "snmp_message": {
    "version": 1,
    "community": "private",
    "pdu_type": "SetRequest-PDU"
  },
  "pdu": {
    "request_id": 12345,
    "error_status": 0,
    "error_index": 0,
    "variable_bindings": [
      {
        "oid": "1.3.6.1.2.1.2.2.1.7.1",
        "type": "INTEGER",
        "value": 2
      }
    ]
  }
}

**Classification:**
ATTACK


## 2) SetRequest - Extend-Command
**Message:** SetRequest (SR)
**Target Binding's path:** Extend-Command
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, a Linux server runs the Net-SNMP agent (snmpd) with SNMPv2c support on UDP port 161. The agent is compiled with the NET-SNMP-EXTEND-MIB module enabled (the default build configuration for Net-SNMP packages on most Linux distributions).
We assume: (i) the victim server's SNMP agent port (UDP 161) is reachable from the attacker's network segment due to insufficient firewall rules or flat network architecture; (ii) the SNMP agent uses SNMPv2c with a default read-write community string "private" that has not been changed by the administrator (ref: CVE-2026-28775, CVSS 10.0, which documents real-world exploitation of default SNMP RW community strings for RCE); (iii) the NET-SNMP-EXTEND-MIB (OID subtree 1.3.6.1.4.1.8072.1.3) is loaded and accessible, allowing the creation of arbitrary command entries via SetRequest-PDU per the nsExtendObjects table definition; (iv) the snmpd process runs with sufficient OS privileges to execute the injected command (e.g., running as root or as a user with access to sensitive system commands); and (v) the attacker has obtained the target server's IP address.
- **Attacker Capability:**
The attacker is restricted to only send one SNMP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message SetRequest-PDU, constructing a valid SNMPv2c message with the community string "private". The PDU contains three variable bindings that together create a new command entry in the nsExtendObjects table: (1) nsExtendStatus."cmd1" (OID 1.3.6.1.4.1.8072.1.3.2.2.1.21.4.99.109.100.49) set to INTEGER 4 (createAndGo), which creates and activates the row; (2) nsExtendCommand."cmd1" (OID 1.3.6.1.4.1.8072.1.3.2.2.1.2.4.99.109.100.49) set to the path of the command to execute (e.g., "/bin/id"); (3) nsExtendArgs."cmd1" (OID 1.3.6.1.4.1.8072.1.3.2.2.1.3.4.99.109.100.49) set to an empty string (no arguments needed for this PoC). The attacker sends this message to the victim server on UDP port 161.

After the SNMP agent processes the SetRequest, a new extend entry named "cmd1" is created in the agent's runtime configuration. When the nsExtendObjects subtree is subsequently read (via GetRequest or GetNextRequest on 1.3.6.1.4.1.8072.1.3.2.3), the agent executes "/bin/id" and returns the output (e.g., "uid=0(root) gid=0(root) groups=0(root)") in the nsExtendOutput1Line OID. This demonstrates arbitrary command execution on the target server with the privileges of the snmpd process. The agent responds to the initial SetRequest with a GetResponse-PDU containing error-status noError(0). The PoC is successful if the attacker can subsequently read the command output via SNMP, confirming remote code execution.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "snmp_message": {
    "version": 1,
    "community": "private",
    "pdu_type": "SetRequest-PDU"
  },
  "pdu": {
    "request_id": 12346,
    "error_status": 0,
    "error_index": 0,
    "variable_bindings": [
      {
        "oid": "1.3.6.1.4.1.8072.1.3.2.2.1.21.4.99.109.100.49",
        "type": "INTEGER",
        "value": 4
      },
      {
        "oid": "1.3.6.1.4.1.8072.1.3.2.2.1.2.4.99.109.100.49",
        "type": "OCTET STRING",
        "value": "/bin/id"
      },
      {
        "oid": "1.3.6.1.4.1.8072.1.3.2.2.1.3.4.99.109.100.49",
        "type": "OCTET STRING",
        "value": ""
      }
    ]
  }
}

**Classification:**
ATTACK


## 3) GetBulkRequest - Max-Repetitions
**Message:** GetBulkRequest (GBR)
**Target Binding's path:** Max-Repetitions
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, an SNMP-managed device (router/switch) runs an SNMP agent that supports SNMPv2c GetBulkRequest operations on UDP port 161 as defined in RFC 3416 Section 4.2.3.
We assume: (i) the victim device's SNMP agent port (UDP 161) is reachable from the attacker's network segment; (ii) the SNMP agent uses SNMPv2c with a known read-only community string (e.g., "public"); (iii) the SNMP agent processes all syntactically valid GetBulkRequest-PDUs and generates responses per RFC 3416 Section 4.2.3; (iv) the device has limited CPU and memory resources typical of embedded network equipment; and (v) the attacker has obtained the target device's IP address.
- **Attacker Capability:**
The attacker is restricted to only send one SNMP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message GetBulkRequest-PDU, constructing a valid SNMPv2c message with the community string "public". The PDU sets non-repeaters to 0 and max-repetitions to 2147483647 (the maximum 32-bit signed integer value). The variable bindings contain a single OID 1.3.6.1.2.1.1 (system subtree) as the starting point for the bulk walk.

After the SNMP agent processes the GetBulkRequest, it attempts to retrieve up to 2147483647 successive OID-value pairs starting from the system subtree. This forces the agent to perform an exhaustive MIB walk, consuming all available CPU cycles and memory to build an extremely large response PDU. The device's control plane becomes unresponsive during this operation, causing management session timeouts, routing protocol adjacency drops, and potential forwarding plane degradation. The agent may crash, restart, or become permanently unresponsive depending on the implementation. The PoC is successful if the target device experiences observable resource exhaustion (elevated CPU, dropped management sessions, or service restart) after receiving the single GetBulkRequest.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "snmp_message": {
    "version": 1,
    "community": "public",
    "pdu_type": "GetBulkRequest-PDU"
  },
  "pdu": {
    "request_id": 12347,
    "non_repeaters": 0,
    "max_repetitions": 2147483647,
    "variable_bindings": [
      {
        "oid": "1.3.6.1.2.1.1",
        "type": "NULL",
        "value": null
      }
    ]
  }
}

**Classification:**
ATTACK


## 4) SetRequest - IP-Forwarding
**Message:** SetRequest (SR)
**Target Binding's path:** IP-Forwarding
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, an SNMP-managed router or Layer-3 switch runs an SNMP agent on UDP port 161 as defined in RFC 3416. The device performs IP forwarding (routing) for traffic between network segments.
We assume: (i) the victim device's SNMP agent port (UDP 161) is reachable from the attacker's network segment; (ii) the SNMP agent uses SNMPv2c with a default read-write community string "private" (ref: CVE-2024-43388, CVSS 8.8, which documents SNMP-based unauthorized device reconfiguration on industrial network equipment); (iii) the SNMP agent implements the standard IP-MIB (RFC 4293) and the OID ipForwarding (1.3.6.1.2.1.4.1) is writable; (iv) the device is actively forwarding traffic between multiple network segments (e.g., between 10.0.1.0/24 and 10.0.2.0/24) and other devices depend on it as their default gateway; and (v) the attacker has obtained the target device's IP address.
- **Attacker Capability:**
The attacker is restricted to only send one SNMP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message SetRequest-PDU, constructing a valid SNMPv2c message with the community string "private". The PDU contains a single variable binding with OID 1.3.6.1.2.1.4.1.0 (ipForwarding.0) and value INTEGER 2 (notForwarding). This instructs the device to stop acting as an IP router and cease forwarding packets between interfaces. The attacker sends this SNMP message to the victim device on UDP port 161.

After the SNMP agent processes the SetRequest, it sets ipForwarding to notForwarding(2), which disables the device's IP packet forwarding function. All inter-segment traffic that traverses this device is immediately dropped — hosts using this device as their default gateway lose connectivity to all remote subnets, including access to critical services such as DNS, email, and database servers. Unlike shutting down a single interface (which only affects one link), disabling IP forwarding silently drops traffic on all interfaces while the device itself remains reachable for local-segment management, making the attack harder to diagnose. The agent responds with a GetResponse-PDU containing error-status noError(0). The PoC is successful if hosts on connected subnets lose inter-segment connectivity and packet captures on the device show forwarded packets being dropped.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "snmp_message": {
    "version": 1,
    "community": "private",
    "pdu_type": "SetRequest-PDU"
  },
  "pdu": {
    "request_id": 12348,
    "error_status": 0,
    "error_index": 0,
    "variable_bindings": [
      {
        "oid": "1.3.6.1.2.1.4.1.0",
        "type": "INTEGER",
        "value": 2
      }
    ]
  }
}

**Classification:**
ATTACK


## 5) GetRequest - Variable-Binding-OID
**Message:** GetRequest (GR)
**Target Binding's path:** Variable-Binding-OID
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, an SNMP-managed network device (router/switch) runs an SNMP agent that accepts SNMPv2c GetRequest operations on UDP port 161 as defined in RFC 3416.
We assume: (i) the victim device's SNMP agent port (UDP 161) is reachable from the attacker's network segment; (ii) the SNMP agent uses SNMPv2c with a known read-only community string "public"; (iii) the SNMP agent processes all syntactically valid GetRequest-PDUs per RFC 3416 Section 4.2.1; and (iv) the attacker has obtained the target device's IP address.
- **Attacker Capability:**
The attacker is restricted to only send one SNMP request message and passively receive a corresponding response.
**Security Analysis:**
GetRequest-PDU (RFC 3416 Section 4.2.1) is a read-only operation that retrieves the value of one or more MIB objects specified by OID. Manipulating the Variable-Binding-OID field in a GetRequest only determines which MIB object's value is returned in the response. If the OID exists and is accessible under the community string's view, the agent returns the value; if the OID does not exist, the agent returns a noSuchObject or noSuchInstance error in the variable binding per RFC 3416 Section 4.2.1. In neither case does a GetRequest modify any MIB object, device configuration, or operational state. GetRequest is a pure retrieval operation — it cannot change interface states, routing tables, access control lists, or any other device parameter. While reading MIB values may disclose network topology, device configuration details, or performance statistics (information disclosure), a single GetRequest with a manipulated OID does not constitute an active attack that causes harm to the network device or its managed services.

**Classification:**
SAFE


## 6) GetNextRequest - Variable-Binding-OID
**Message:** GetNextRequest (GNR)
**Target Binding's path:** Variable-Binding-OID
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, an SNMP-managed network device (router/switch) runs an SNMP agent that accepts SNMPv2c GetNextRequest operations on UDP port 161 as defined in RFC 3416.
We assume: (i) the victim device's SNMP agent port (UDP 161) is reachable from the attacker's network segment; (ii) the SNMP agent uses SNMPv2c with a known read-only community string "public"; (iii) the SNMP agent processes all syntactically valid GetNextRequest-PDUs per RFC 3416 Section 4.2.2; and (iv) the attacker has obtained the target device's IP address.
- **Attacker Capability:**
The attacker is restricted to only send one SNMP request message and passively receive a corresponding response.
**Security Analysis:**
GetNextRequest-PDU (RFC 3416 Section 4.2.2) is a read-only operation that retrieves the value of the lexicographically next MIB object following the specified OID. Like GetRequest, manipulating the Variable-Binding-OID field only determines the starting point for the next-OID lookup. The agent returns the next available OID-value pair if one exists, or an endOfMibView marker if the walk has reached the end of the MIB tree. GetNextRequest cannot modify any MIB object, device configuration, interface state, or operational parameter. It is the fundamental building block of SNMP MIB walks and is inherently a read-only retrieval operation. While an attacker could use it to enumerate the MIB tree and discover available OIDs (information gathering), a single GetNextRequest with a manipulated OID does not constitute an active attack that causes harm to the network device or disrupts its services.

**Classification:**
SAFE

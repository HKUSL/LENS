# RADIUS Attribute Security Analysis Seed Examples

## 1) Access-Request - Proxy-State
**Message:** Access-Request
**Target Attribute's path:** Proxy-State
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, a RADIUS server (e.g., FreeRADIUS) authenticates network access for users connecting via 802.1X or VPN over the RADIUS protocol (RFC 2865).
We assume: (i) the attacker is positioned as a man-in-the-middle (MITM) on the network path between a RADIUS client (NAS) and the RADIUS server, capable of intercepting, reading, and modifying RADIUS/UDP packets in transit — this is achievable via ARP spoofing, BGP hijacking, or compromise of an intermediate network device; (ii) the RADIUS deployment uses a non-EAP authentication method (PAP, CHAP, or MS-CHAPv2) over UDP without TLS/RadSec encryption; (iii) the RADIUS client does not require the Message-Authenticator attribute in server responses; (iv) the RADIUS server echoes Proxy-State attributes in responses as mandated by RFC 2865 Section 5.33; and (v) the attacker has sufficient computational resources to compute an MD5 chosen-prefix collision within the RADIUS client's response timeout window (demonstrated to be achievable in under 5 minutes on commodity hardware, per Goldberg et al., USENIX Security 2024).
- **Attacker Capability:**
The attacker can intercept and modify RADIUS packets in transit between the NAS and the RADIUS server (man-in-the-middle position).

**Attack Procedure:**
This attack implements the Blast-RADIUS protocol vulnerability (CVE-2024-3596), disclosed by Goldberg, Haller, Heninger et al. at the 33rd USENIX Security Symposium (2024), in the paper "RADIUS/UDP Considered Harmful." The attack exploits the MD5-based Response Authenticator in RADIUS to forge Access-Accept responses.

The attacker intercepts a legitimate Access-Request packet from the NAS to the RADIUS server. The attacker extracts the 16-byte Request Authenticator from the intercepted packet. The attacker then injects one or more Proxy-State attributes (Type 33, RFC 2865 Section 5.33) into the Access-Request before forwarding it to the server. Per RFC 2865, "a RADIUS server MUST echo all Proxy-State attributes from a request in the response, in order." The injected Proxy-State attributes contain carefully computed collision padding bytes. Simultaneously, the attacker pre-computes an MD5 chosen-prefix collision between: (a) a forged Access-Accept packet containing the attacker's desired authorization attributes, and (b) the server's expected Access-Reject response (which will echo the injected Proxy-State attributes). The collision ensures both packets produce the same MD5 hash in the Response Authenticator field. When the server sends its genuine Access-Reject (echoing the injected Proxy-State), the attacker replaces it with the pre-computed forged Access-Accept and forwards it to the NAS.

The NAS validates the Response Authenticator of the forged Access-Accept using MD5(Code+ID+Length+RequestAuth+Attributes+Secret), which matches because of the chosen-prefix collision. The NAS accepts the forged response and grants the attacker network access with the authorization attributes specified in the forged Access-Accept (e.g., administrative VLAN assignment, unrestricted ACLs). The PoC is successful if the NAS accepts the forged Access-Accept and grants network access to an unauthenticated user.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "radius_header": {
    "code": 1,
    "code_name": "Access-Request",
    "identifier": 42,
    "length": 200,
    "authenticator": "0xA1B2C3D4E5F60718293A4B5C6D7E8F90"
  },
  "attributes": [
    {
      "type": 1,
      "type_name": "User-Name",
      "value": "jdoe"
    },
    {
      "type": 2,
      "type_name": "User-Password",
      "value": "<MD5-hidden using shared secret and authenticator per RFC 2865 Section 5.2>"
    },
    {
      "type": 4,
      "type_name": "NAS-IP-Address",
      "value": "10.0.0.1"
    },
    {
      "type": 5,
      "type_name": "NAS-Port",
      "value": 1
    },
    {
      "type": 33,
      "type_name": "Proxy-State",
      "value": "<collision-padding-block-1: 256 bytes of computed MD5 chosen-prefix collision data>"
    },
    {
      "type": 33,
      "type_name": "Proxy-State",
      "value": "<collision-padding-block-2: 256 bytes of computed MD5 chosen-prefix collision data>"
    }
  ]
}

**Classification:**
ATTACK


## 2) Access-Request - Calling-Station-Id
**Message:** Access-Request
**Target Attribute's path:** Calling-Station-Id
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, a RADIUS server (e.g., FreeRADIUS, Cisco ISE) authenticates network access for devices connecting via 802.1X over the RADIUS protocol (RFC 2865).
We assume: (i) the victim RADIUS server's authentication port (UDP 1812) is reachable from the attacker's network segment; (ii) the attacker has obtained the RADIUS shared secret between the NAS and the RADIUS server (e.g., through prior compromise of the NAS configuration or firmware extraction); (iii) the network deploys MAC Authentication Bypass (MAB) as a fallback mechanism for non-802.1X-capable devices, where the NAS sends the device's MAC address in the Calling-Station-Id attribute (Type 31, RFC 2865 Section 5.31) and the RADIUS server uses it to apply device-profile-specific authorization policies (e.g., VLAN assignment per Cisco ISE profiling or FreeRADIUS huntgroup rules); (iv) the RADIUS server does not enforce cryptographic binding between the Calling-Station-Id attribute and the actual connecting device's MAC address — this is inherent to the RADIUS protocol design, as noted in Cisco's MAB Deployment Guide: "MAB does not provide true authentication because the MAC address can be spoofed"; and (v) the attacker has obtained the MAC address of a trusted device class (e.g., a VoIP phone or medical IoT device) through passive network observation, DHCP snooping table access, or ARP table enumeration.
- **Attacker Capability:**
The attacker is restricted to only send one RADIUS request packet and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message Access-Request implementing a MAC Authentication Bypass (MAB) spoofing attack. MAB is a widely deployed 802.1X fallback mechanism documented in Cisco's MAB Deployment Guide and RFC 3580 (IEEE 802.1X RADIUS Usage Guidelines). The attacker sets the Calling-Station-Id attribute to the MAC address of a trusted device (e.g., "00:1A:2B:3C:4D:5E", a registered Cisco IP phone). In MAB mode, the NAS typically also sets User-Name to the MAC address and uses it as the password, but the critical authorization decision is based on the Calling-Station-Id value matching a device profile in the RADIUS server's policy engine.

Since the RADIUS protocol provides no mechanism to cryptographically verify that the Calling-Station-Id value corresponds to the actual connecting device's hardware address (the attribute is a plain text string set by the NAS based on the source MAC of the Ethernet frame, which is trivially spoofable at Layer 2), the RADIUS server applies the authorization policy associated with the spoofed device profile. The attacker receives an Access-Accept containing VLAN assignment attributes (Tunnel-Type=VLAN, Tunnel-Medium-Type=802, Tunnel-Private-Group-Id=voice-vlan per RFC 3580 Section 3.31) that place them on the privileged voice VLAN or medical device network segment with less restrictive ACLs. The PoC is successful if the attacker receives VLAN assignment or ACL attributes corresponding to the spoofed device class rather than the default guest VLAN.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "radius_header": {
    "code": 1,
    "code_name": "Access-Request",
    "identifier": 87,
    "length": 112,
    "authenticator": "0xF0E1D2C3B4A596870718293A4B5C6D7E"
  },
  "attributes": [
    {
      "type": 1,
      "type_name": "User-Name",
      "value": "001a2b3c4d5e"
    },
    {
      "type": 2,
      "type_name": "User-Password",
      "value": "<MD5-hidden: '001a2b3c4d5e' used as password in MAB mode>"
    },
    {
      "type": 31,
      "type_name": "Calling-Station-Id",
      "value": "00:1A:2B:3C:4D:5E"
    },
    {
      "type": 4,
      "type_name": "NAS-IP-Address",
      "value": "10.0.0.1"
    },
    {
      "type": 61,
      "type_name": "NAS-Port-Type",
      "value": 15,
      "value_name": "Ethernet"
    },
    {
      "type": 6,
      "type_name": "Service-Type",
      "value": 10,
      "value_name": "Call-Check"
    },
    {
      "type": 5,
      "type_name": "NAS-Port",
      "value": 3
    }
  ]
}

**Classification:**
ATTACK


## 3) Access-Request - Vendor-Specific
**Message:** Access-Request
**Target Attribute's path:** Vendor-Specific
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, a Cisco Secure Firewall Management Center (FMC) uses RADIUS for external administrator authentication, with a RADIUS server (e.g., Cisco ISE, FreeRADIUS) providing authentication and authorization via Vendor-Specific Attributes (VSA).
We assume: (i) the attacker has compromised or can impersonate the RADIUS server (e.g., through DNS spoofing, ARP poisoning, or by exploiting the Blast-RADIUS vulnerability CVE-2024-3596 to forge responses); (ii) the target system processes Cisco AV-pair Vendor-Specific Attributes (Vendor-ID 9, Vendor-Type 1) from RADIUS Access-Accept responses to determine user authorization levels and apply configuration parameters; (iii) the target system does not perform adequate input sanitization on the values received in Vendor-Specific attributes before processing them; and (iv) the RADIUS deployment does not use TLS/RadSec to protect the integrity of RADIUS responses.
- **Attacker Capability:**
The attacker can send a forged RADIUS Access-Accept response to the NAS/target system (either by controlling a rogue RADIUS server or by exploiting CVE-2024-3596 to forge responses in transit).

**Attack Procedure:**
This attack exploits CVE-2025-20265 (Cisco Secure Firewall RADIUS Injection), a critical command injection vulnerability disclosed in 2025. The attacker crafts a RADIUS Access-Accept response containing a malicious Vendor-Specific attribute (Type 26, RFC 2865 Section 5.26). The Vendor-Specific attribute uses Cisco's vendor ID (9) and contains a cisco-avpair (Vendor-Type 1) with a crafted value string. Per RFC 2865 Section 5.26, the Vendor-Specific attribute "allows vendors to support their own extended Attributes not suitable for general usage" — the RADIUS protocol places no restrictions on the content of vendor-specific sub-attributes.

The attacker sets the cisco-avpair value to a string containing OS-level command injection payloads. When the Cisco FMC processes the Access-Accept response, it extracts the cisco-avpair values to determine the authenticated user's role and apply configuration. Due to insufficient input sanitization (CVE-2025-20265), the injected commands are executed at the OS level on the FMC management appliance. The attacker achieves remote code execution on the management plane, enabling manipulation of firewall policies, disabling of security controls, and lateral movement to managed firewalls.

The PoC is successful if the attacker achieves command execution on the FMC management appliance through the injected Vendor-Specific attribute value.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "radius_header": {
    "code": 2,
    "code_name": "Access-Accept",
    "identifier": 42,
    "length": 150,
    "authenticator": "<computed Response Authenticator>"
  },
  "attributes": [
    {
      "type": 6,
      "type_name": "Service-Type",
      "value": 6,
      "value_name": "Administrative-User"
    },
    {
      "type": 26,
      "type_name": "Vendor-Specific",
      "vendor_id": 9,
      "vendor_id_name": "Cisco",
      "vendor_type": 1,
      "vendor_type_name": "cisco-avpair",
      "value": "shell:priv-lvl=15; <injected-os-command>"
    },
    {
      "type": 18,
      "type_name": "Reply-Message",
      "value": "Authentication successful"
    }
  ]
}

**Classification:**
ATTACK


## 4) Access-Request - Tunnel-Password
**Message:** Access-Request
**Target Attribute's path:** Tunnel-Password
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, a RADIUS server (e.g., FreeRADIUS 0.9.2 or earlier) authenticates network access over the RADIUS protocol (RFC 2865), with tunnel attributes defined in RFC 2868.
We assume: (i) the victim RADIUS server's authentication port (UDP 1812) is reachable from the attacker's network; (ii) the attacker does not need the RADIUS shared secret for this attack; (iii) the RADIUS server runs a version of FreeRADIUS prior to 1.0.1 that is vulnerable to CVE-2003-0967 (a buffer overflow in the rad_decode function when processing malformed Tunnel-Password attributes); and (iv) the RADIUS server processes incoming Access-Request packets before authenticating them (the vulnerable code path is reached during attribute decoding, before shared secret validation).
- **Attacker Capability:**
The attacker is restricted to only send one RADIUS request packet to the server.

**Attack Procedure:**
This attack exploits CVE-2003-0967, a buffer overflow vulnerability in FreeRADIUS 0.9.2 and earlier, documented in CERT VU#541574 and the FreeRADIUS security advisory. The vulnerability exists in the rad_decode() function that processes RADIUS attributes during packet parsing.

The attacker crafts an Access-Request containing a malformed Tunnel-Password attribute (Type 69, RFC 2868 Section 3.5). The Tunnel-Password attribute uses a tagged string format where the attribute value begins with a 1-byte tag field followed by encrypted password data. The attacker sets the attribute length field to the minimum value of 3 (1 byte type + 1 byte length + 1 byte tag), leaving zero bytes for the actual password data. When the vulnerable FreeRADIUS server's rad_decode() function processes this attribute, it computes the password data length as (attribute_length - 2 - 1) = 0. A subsequent code path that handles tag validation subtracts an additional byte, producing a length value of -1 (0xFFFFFFFF when interpreted as unsigned). This value is passed to memcpy(), which attempts to copy approximately 4 GB of memory, causing an immediate segmentation fault and server process crash.

The PoC is successful if the FreeRADIUS server process crashes (denial of service), rendering the RADIUS authentication service unavailable for all users and devices relying on it for network access.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "radius_header": {
    "code": 1,
    "code_name": "Access-Request",
    "identifier": 1,
    "length": 43,
    "authenticator": "0x00000000000000000000000000000000"
  },
  "attributes": [
    {
      "type": 1,
      "type_name": "User-Name",
      "value": "test"
    },
    {
      "type": 2,
      "type_name": "User-Password",
      "value": "<any 16-byte value>"
    },
    {
      "type": 69,
      "type_name": "Tunnel-Password",
      "length": 3,
      "tag": 0,
      "value": "<empty — zero-length password data triggers CVE-2003-0967>"
    }
  ]
}

**Classification:**
ATTACK


## 5) Access-Request - NAS-Port
**Message:** Access-Request
**Target Attribute's path:** NAS-Port
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, a RADIUS server (e.g., FreeRADIUS) authenticates network access for users connecting via 802.1X over the RADIUS protocol (RFC 2865).
We assume: (i) the victim RADIUS server's authentication port (UDP 1812) is reachable from the attacker's network; (ii) the attacker has obtained the RADIUS shared secret; (iii) the RADIUS server processes attacker-crafted Access-Request packets according to RFC 2865; and (iv) the attacker has valid credentials for a regular user account.
- **Attacker Capability:**
The attacker is restricted to only send one RADIUS request packet and passively receive a corresponding response.
**Security Analysis:**
NAS-Port (Type 5, RFC 2865 Section 5.5) is an informational attribute that indicates the physical or virtual port number on the NAS through which the user is connecting. It is a 32-bit integer value set by the NAS to identify the access port. Manipulating the NAS-Port value in a crafted Access-Request has no meaningful security impact on other users or the RADIUS server's security posture: the attribute is used primarily for accounting and session identification purposes. The RADIUS server does not make authentication or authorization decisions based on the NAS-Port value alone — it does not grant different privilege levels, VLAN assignments, or ACLs based on which port number is reported. Setting NAS-Port to an arbitrary value (e.g., 999) only affects the attacker's own session metadata in accounting records. The attribute carries no credentials, no authorization policy bindings, and no routing information that could be leveraged to affect other users' sessions or network access.

**Classification:**
SAFE


## 6) Access-Request - NAS-IP-Address
**Message:** Access-Request
**Target Attribute's path:** NAS-IP-Address
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, a RADIUS server (e.g., FreeRADIUS) authenticates network access for users connecting via 802.1X over the RADIUS protocol (RFC 2865).
We assume: (i) the victim RADIUS server's authentication port (UDP 1812) is reachable from the attacker's network; (ii) the attacker has obtained the RADIUS shared secret; (iii) the RADIUS server processes attacker-crafted Access-Request packets according to RFC 2865; and (iv) the attacker has valid credentials for a regular user account.
- **Attacker Capability:**
The attacker is restricted to only send one RADIUS request packet and passively receive a corresponding response.
**Security Analysis:**
NAS-IP-Address (Type 4, RFC 2865 Section 5.4) indicates the identifying IP address of the NAS that is requesting authentication on behalf of the user. While the RADIUS server may use NAS-IP-Address for logging and to select the appropriate shared secret (when multiple NAS devices share the same RADIUS server), manipulating this attribute in a crafted Access-Request has limited security impact in the standard deployment model. Per RFC 2865 Section 3, the shared secret is typically selected based on the source IP address of the UDP packet (the actual network-layer source), not the NAS-IP-Address attribute value. FreeRADIUS's client configuration explicitly binds shared secrets to source IP addresses. Therefore, spoofing the NAS-IP-Address attribute while sending from a different source IP will not cause the RADIUS server to use a different shared secret — the packet will either be authenticated with the correct shared secret (based on source IP) or rejected. The attribute primarily affects accounting records and session correlation. In deployments where the RADIUS server does not apply per-NAS authorization policies based on NAS-IP-Address (the common case), manipulating this value only affects the attacker's own session metadata.

**Classification:**
SAFE

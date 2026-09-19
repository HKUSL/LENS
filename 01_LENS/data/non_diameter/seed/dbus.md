## 1) METHOD_CALL - MEMBER
**Message:** METHOD_CALL
**Target Bus Field's path:** MEMBER
**Threat Model:**
- **Attack Assumption:**
On the target Ubuntu Desktop host (versions 12.04–19.04, before the June 2019 patch), the USBCreator D-Bus service (`com.ubuntu.USBCreator`) runs as root and exposes methods on the system bus following the D-Bus Specification (freedesktop.org).
We assume: (i) the victim host is an Ubuntu Desktop installation with the `usb-creator` package installed (default on Ubuntu Desktop); (ii) the attacker has local shell access as a member of the `sudo` group (standard for the first user created during Ubuntu installation); (iii) the system D-Bus bus is accessible to the attacker via `/var/run/dbus/system_bus_socket`; (iv) the D-Bus policy file for `com.ubuntu.USBCreator` allows users in the `sudo` group to call methods on this service without polkit authentication; and (v) the USBCreator service's `Image` method does not validate or sanitize the source and target file paths provided by the caller.
- **Attacker Capability:**
The attacker can send D-Bus METHOD_CALL messages to the system bus targeting the `com.ubuntu.USBCreator` service. The attacker controls the MEMBER field and all method arguments.

**Attack Procedure:**
The attacker exploits the USBCreator D-Bus service's `Image` method to perform arbitrary file operations as root without password authentication (discovered by Palo Alto Unit42, disclosed June 2019). The attack targets the MEMBER header field of a METHOD_CALL message. The `Image` method is designed to write a disk image to a USB device, but it accepts arbitrary file paths for both source and destination without validation. The attacker sends a METHOD_CALL with MEMBER set to `Image`, DESTINATION set to `com.ubuntu.USBCreator`, and PATH set to `/com/ubuntu/USBCreator`. The method's SIGNATURE is `sb` (string, boolean): the first argument is a source path (the file to copy) and the second is a boolean flag.

By setting the source argument to a sensitive file path (e.g., `/etc/shadow`) and the destination to a world-readable location (e.g., `/tmp/shadow_copy`), the attacker causes the root-privileged USBCreator service to copy the shadow file to a location the attacker can read. Alternatively, the attacker can overwrite `/etc/shadow` with a crafted file containing a known root password hash, or overwrite `/root/.ssh/authorized_keys` with the attacker's public key. Because the D-Bus policy grants access based on group membership (`sudo` group) without requiring polkit interactive authentication, no password prompt is displayed. The MEMBER value `Image` is the critical field — changing it to any other method name (e.g., `Introspect`, `KVMTest`) would not trigger this vulnerability. The PoC is successful if the attacker reads `/etc/shadow` or writes an SSH key to gain root access.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet represents the D-Bus METHOD_CALL message sent to the system bus.

{
  "dbus_header": {
    "endianness": "l",
    "message_type": "METHOD_CALL",
    "flags": 0,
    "protocol_version": 1,
    "serial": 1
  },
  "header_fields": {
    "PATH": "/com/ubuntu/USBCreator",
    "INTERFACE": "com.ubuntu.USBCreator",
    "MEMBER": "Image",
    "DESTINATION": "com.ubuntu.USBCreator",
    "SIGNATURE": "sb"
  },
  "body": {
    "arg0_source": "/etc/shadow",
    "arg1_allow_system_internal": true
  },
  "_exploit_context": {
    "reference": "Palo Alto Unit42 disclosure, June 2019: 'USBCreator D-Bus Privilege Escalation in Ubuntu Desktop'",
    "note": "MEMBER=Image triggers root-privileged file copy without password authentication; changing MEMBER to any other value prevents the attack"
  }
}

**Classification:**
ATTACK

## 2) METHOD_CALL - DESTINATION
**Message:** METHOD_CALL
**Target Bus Field's path:** DESTINATION
**Threat Model:**
- **Attack Assumption:**
On the target Linux host (running systemd version 240, e.g., Fedora 30, Debian Buster), the system D-Bus daemon mediates IPC between unprivileged user processes and privileged system services following the D-Bus Specification (freedesktop.org).
We assume: (i) the victim host runs systemd-resolved with its D-Bus interface exposed on the system bus; (ii) systemd-resolved's D-Bus connection was opened using `bus_open_system_watch_bind_with_description()` which internally calls `sd_bus_set_trusted(bus, true)`, disabling all access control checks on incoming messages (CVE-2019-15718, disclosed September 2019 on oss-security); (iii) the system D-Bus bus is accessible to unprivileged local users via `/var/run/dbus/system_bus_socket`; (iv) the attacker has local shell access as an unprivileged user; and (v) no additional mandatory access control policy (AppArmor, SELinux) restricts D-Bus method calls to `org.freedesktop.resolve1`.
- **Attacker Capability:**
The attacker can send D-Bus METHOD_CALL messages to the system bus with a controlled DESTINATION header field value.

**Attack Procedure:**
The attacker exploits missing access controls on systemd-resolved's D-Bus interface (CVE-2019-15718). The attack targets the DESTINATION header field of a METHOD_CALL message. The DESTINATION field determines which system service receives the method call. By setting DESTINATION to `org.freedesktop.resolve1`, the attacker routes the message to systemd-resolved, which — due to the `sd_bus_set_trusted(true)` misconfiguration — processes all incoming method calls without any authorization checks, regardless of the caller's UID or capabilities.

The attacker sends a METHOD_CALL with DESTINATION set to `org.freedesktop.resolve1` and MEMBER set to `SetLinkDNS`. This method accepts an interface index and an array of DNS server addresses. The attacker provides the primary network interface index (e.g., 2 for `eth0`) and an attacker-controlled DNS server address (e.g., `192.168.1.100`). Because the trusted flag bypasses all authorization, systemd-resolved accepts the configuration change from the unprivileged user. All subsequent DNS queries on the targeted interface are redirected to the attacker's DNS server, enabling DNS hijacking, phishing redirection, and man-in-the-middle attacks. The DESTINATION value is the critical field — setting DESTINATION to any other service (e.g., `org.freedesktop.NetworkManager`) would route the message to a service that does enforce access controls, and the attack would fail. The PoC is successful if DNS queries from the host are redirected to the attacker-controlled server.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet represents the D-Bus METHOD_CALL message sent to the system bus.

{
  "dbus_header": {
    "endianness": "l",
    "message_type": "METHOD_CALL",
    "flags": 0,
    "protocol_version": 1,
    "serial": 2
  },
  "header_fields": {
    "PATH": "/org/freedesktop/resolve1",
    "INTERFACE": "org.freedesktop.resolve1.Manager",
    "MEMBER": "SetLinkDNS",
    "DESTINATION": "org.freedesktop.resolve1",
    "SIGNATURE": "ia(iay)"
  },
  "body": {
    "arg0_ifindex": 2,
    "arg1_dns_servers": [
      {
        "address_family": 2,
        "address": [192, 168, 1, 100]
      }
    ]
  },
  "_exploit_context": {
    "reference": "CVE-2019-15718, oss-security disclosure September 2019",
    "note": "DESTINATION=org.freedesktop.resolve1 routes to a service with sd_bus_set_trusted(true), bypassing all access control; any other DESTINATION would enforce normal policy"
  }
}

**Classification:**
ATTACK

## 3) METHOD_CALL - INTERFACE
**Message:** METHOD_CALL
**Target Bus Field's path:** INTERFACE
**Threat Model:**
- **Attack Assumption:**
On the target Linux host, a custom privileged D-Bus service runs as root and exposes a method that processes user-supplied string arguments by passing them to a shell command (e.g., `iptables`, `ip`, or a custom script) without proper input sanitization. This pattern is documented in HackTricks ("D-Bus Enumeration & Command Injection Privilege Escalation") and demonstrated in the HackTheBox Oouch machine (Hard difficulty).
We assume: (i) the victim host runs a custom D-Bus service (e.g., `htb.oouch.Block`) on the system bus that accepts METHOD_CALL messages from authenticated local users; (ii) the service's D-Bus policy file (`/etc/dbus-1/system.d/htb.oouch.Block.conf`) allows any authenticated user to send messages to this interface; (iii) the service implements a method (e.g., `Block`) that takes a string argument (an IP address) and passes it to a shell command such as `iptables -A INPUT -s <user_input> -j DROP` using `subprocess.call()` with `shell=True` or equivalent; (iv) the attacker has local shell access as an unprivileged user; and (v) the service does not validate or sanitize the string argument before shell interpolation.
- **Attacker Capability:**
The attacker can send D-Bus METHOD_CALL messages to the system bus with a controlled INTERFACE header field and method arguments.

**Attack Procedure:**
The attacker exploits a command injection vulnerability in a privileged D-Bus service by targeting the INTERFACE header field to route the message to the vulnerable service. The INTERFACE field determines which D-Bus interface the method call is dispatched to. By setting INTERFACE to `htb.oouch.Block`, the attacker ensures the message reaches the vulnerable `Block` method handler rather than a standard interface like `org.freedesktop.DBus.Introspectable` (which would only return XML schema and be harmless).

The attacker sends a METHOD_CALL with INTERFACE set to `htb.oouch.Block`, MEMBER set to `Block`, and the body containing a crafted string argument: instead of a legitimate IP address like `10.10.14.1`, the attacker provides `10.10.14.1;id>/tmp/pwned` (or `10.10.14.1$(cat /etc/shadow > /tmp/shadow)`). The service constructs the shell command `iptables -A INPUT -s 10.10.14.1;id>/tmp/pwned -j DROP`, which the shell interprets as two commands: the iptables command and `id>/tmp/pwned`. The injected command executes as root (the service's UID). The INTERFACE value is the critical field — setting INTERFACE to `org.freedesktop.DBus.Peer` would dispatch to the standard Ping method, and setting it to `org.freedesktop.DBus.Introspectable` would return harmless XML. Only `htb.oouch.Block` routes to the vulnerable command-execution handler. The PoC is successful if the attacker achieves arbitrary command execution as root.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet represents the D-Bus METHOD_CALL message sent to the system bus.

{
  "dbus_header": {
    "endianness": "l",
    "message_type": "METHOD_CALL",
    "flags": 0,
    "protocol_version": 1,
    "serial": 3
  },
  "header_fields": {
    "PATH": "/htb/oouch/Block",
    "INTERFACE": "htb.oouch.Block",
    "MEMBER": "Block",
    "DESTINATION": "htb.oouch.Block",
    "SIGNATURE": "s"
  },
  "body": {
    "arg0_ip": "10.10.14.1;cat /etc/shadow > /tmp/shadow"
  },
  "_exploit_context": {
    "reference": "HackTricks 'D-Bus Enumeration & Command Injection Privilege Escalation'; HackTheBox Oouch (Hard)",
    "note": "INTERFACE=htb.oouch.Block routes to vulnerable command-execution handler; any other INTERFACE value dispatches to safe standard methods"
  }
}

**Classification:**
ATTACK

## 4) METHOD_CALL - PATH
**Message:** METHOD_CALL
**Target Bus Field's path:** PATH
**Threat Model:**
- **Attack Assumption:**
On the target Linux host running Deepin Desktop Environment (DDE) with dde-api-proxy versions 1.0.17 or 1.0.18, the `com.deepin.api.XEventMonitor` D-Bus service runs as root and acts as a proxy for legacy Deepin D-Bus interfaces.
We assume: (i) the victim host runs Deepin Desktop Environment with the dde-api-proxy package installed; (ii) the dde-api-proxy service is registered on the system D-Bus bus and accepts METHOD_CALL messages from authenticated local users; (iii) the dde-api-proxy service forwards method calls to backend services based on the PATH header field without verifying the caller's identity or authorization (CVE-2025-23222, CWE-940, disclosed January 2025 by SUSE Security Team); (iv) the attacker has local shell access as an unprivileged user; and (v) no additional mandatory access control policy restricts D-Bus method calls to `com.deepin.api.XEventMonitor`.
- **Attacker Capability:**
The attacker can send D-Bus METHOD_CALL messages to the system bus with a controlled PATH header field value.

**Attack Procedure:**
The attacker exploits an authentication bypass in Deepin's dde-api-proxy D-Bus service (CVE-2025-23222). The attack targets the PATH header field of a METHOD_CALL message. The dde-api-proxy service acts as a forwarding proxy: it receives D-Bus method calls on the system bus and forwards them to backend Deepin services. The proxy determines which backend service to invoke based on the PATH field in the incoming message. Critically, the proxy does not verify the caller's credentials or check whether the caller is authorized to invoke the target backend method — it trusts the PATH field as sufficient routing information.

The attacker sends a METHOD_CALL with PATH set to a privileged backend object path (e.g., `/com/deepin/daemon/Accounts/User1000`) and INTERFACE set to the corresponding backend interface. The proxy forwards this call to the privileged backend service as if it originated from a trusted component. The backend service, seeing the call arrive from the proxy (which runs as root), processes it without additional authentication. This allows the attacker to invoke privileged operations such as modifying user account settings, changing system configuration, or accessing protected resources. The PATH value is the critical field — it determines which backend object the proxy forwards to. Setting PATH to a non-privileged object (e.g., `/com/deepin/api/XEventMonitor`) would only access the event monitor's own methods, which are non-sensitive. Only PATH values pointing to privileged backend objects enable the escalation. The PoC is successful if the attacker invokes a privileged backend method through the proxy without authentication.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet represents the D-Bus METHOD_CALL message sent to the system bus.

{
  "dbus_header": {
    "endianness": "l",
    "message_type": "METHOD_CALL",
    "flags": 0,
    "protocol_version": 1,
    "serial": 4
  },
  "header_fields": {
    "PATH": "/com/deepin/daemon/Accounts/User1000",
    "INTERFACE": "com.deepin.daemon.Accounts.User",
    "MEMBER": "SetPassword",
    "DESTINATION": "com.deepin.api.XEventMonitor",
    "SIGNATURE": "s"
  },
  "body": {
    "arg0_password": "attacker_controlled_password_hash"
  },
  "_exploit_context": {
    "reference": "CVE-2025-23222, SUSE Security Team Blog, January 2025: 'dde-api-proxy: Authentication Bypass in Deepin D-Bus Proxy Service'",
    "note": "PATH=/com/deepin/daemon/Accounts/User1000 routes through the proxy to a privileged backend; the proxy forwards without verifying caller credentials (CWE-940)"
  }
}

**Classification:**
ATTACK

## 5) METHOD_CALL - SIGNATURE
**Message:** METHOD_CALL
**Target Bus Field's path:** SIGNATURE
**Threat Model:**
- **Attack Assumption:**
On the target Linux host, a privileged D-Bus service exposes sensitive configuration data as D-Bus properties on the system bus. The service's D-Bus policy file restricts access to specific methods (e.g., `SetPassword`, `Reconfigure`) but does not restrict access to the standard `org.freedesktop.DBus.Properties` interface.
We assume: (i) the victim host runs a D-Bus service (e.g., a system configuration daemon) that stores sensitive data as D-Bus properties (e.g., password hashes, API keys, internal state); (ii) the service's D-Bus policy file (`/etc/dbus-1/system.d/*.conf`) uses `<allow send_member="GetStatus"/>` and `<deny send_member="SetPassword"/>` rules to restrict specific methods, but does not include `<deny send_interface="org.freedesktop.DBus.Properties"/>` (a common misconfiguration documented by the SUSE Security Team in their KDE6 D-Bus/Polkit audit, April 2024); (iii) the system D-Bus bus is accessible to unprivileged local users; (iv) the attacker has local shell access; and (v) the attacker has enumerated the service's properties via `org.freedesktop.DBus.Introspectable.Introspect`.
- **Attacker Capability:**
The attacker can send D-Bus METHOD_CALL messages to the system bus with a controlled SIGNATURE header field and method arguments.

**Attack Procedure:**
The attacker exploits a method-level ACL bypass via the standard `org.freedesktop.DBus.Properties` interface. The attack targets the SIGNATURE header field of a METHOD_CALL message. The D-Bus Specification defines `org.freedesktop.DBus.Properties` as a standard interface that all objects should implement, providing `Get(ss)`, `GetAll(s)`, and `Set(ssv)` methods for reading and writing object properties. The SIGNATURE field declares the argument types: `ss` for `Get` (interface name + property name), `s` for `GetAll` (interface name), and `ssv` for `Set` (interface name + property name + value).

The attacker sends a METHOD_CALL with INTERFACE set to `org.freedesktop.DBus.Properties`, MEMBER set to `GetAll`, and SIGNATURE set to `s`. The body contains the target interface name (e.g., `com.example.ConfigService`). Because the D-Bus policy only restricts specific method names on the service's own interface (e.g., `<deny send_member="SetPassword" send_interface="com.example.ConfigService"/>`), the `GetAll` call on `org.freedesktop.DBus.Properties` is not covered by the deny rule and is allowed through. The service returns all properties of the specified interface, including sensitive values that the attacker should not have access to. The SIGNATURE value `s` is the critical field — it must match the `GetAll` method's expected signature exactly. Setting SIGNATURE to `ss` (the `Get` signature) would invoke a different method, and setting it to an invalid signature would cause the call to be rejected by the D-Bus type system. The PoC is successful if the attacker reads sensitive properties that are not accessible via the restricted methods.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet represents the D-Bus METHOD_CALL message sent to the system bus.

{
  "dbus_header": {
    "endianness": "l",
    "message_type": "METHOD_CALL",
    "flags": 0,
    "protocol_version": 1,
    "serial": 5
  },
  "header_fields": {
    "PATH": "/com/example/ConfigService",
    "INTERFACE": "org.freedesktop.DBus.Properties",
    "MEMBER": "GetAll",
    "DESTINATION": "com.example.ConfigService",
    "SIGNATURE": "s"
  },
  "body": {
    "arg0_interface_name": "com.example.ConfigService"
  },
  "_exploit_context": {
    "reference": "SUSE Security Team, 'KDE6 release: D-Bus and Polkit Galore', April 2024; D-Bus Specification standard interfaces section",
    "note": "SIGNATURE=s invokes GetAll on org.freedesktop.DBus.Properties, bypassing method-level ACLs that only restrict the service's own interface methods"
  }
}

**Classification:**
ATTACK

## 6) METHOD_CALL - INTERFACE
**Message:** METHOD_CALL
**Target Bus Field's path:** INTERFACE
**Threat Model:**
- **Attack Assumption:**
On the target Linux host, the system D-Bus daemon mediates IPC between unprivileged user processes and privileged system services following the D-Bus Specification.
We assume: (i) the system D-Bus bus is accessible to unprivileged local users; (ii) the attacker has local shell access; (iii) the attacker can send D-Bus METHOD_CALL messages with an arbitrary INTERFACE header field value; (iv) the attacker targets the `org.freedesktop.DBus.Introspectable` interface; and (v) no additional mandatory access control policy restricts D-Bus introspection calls.
- **Attacker Capability:**
The attacker can send D-Bus METHOD_CALL messages to the system bus with a controlled INTERFACE header field.
**Security Analysis:**
The INTERFACE header field in a METHOD_CALL specifies which D-Bus interface the method belongs to. Setting INTERFACE to `org.freedesktop.DBus.Introspectable` and calling the `Introspect` method is a standard, read-only operation defined in the D-Bus Specification (section "Standard Interfaces"). The `Introspect` method returns an XML description of the object's interfaces, methods, signals, and properties. This is explicitly designed to be publicly accessible — the D-Bus Specification states that `org.freedesktop.DBus.Introspectable` should be implemented by all objects and does not require special privileges. The returned XML contains only the API schema (method names, argument types, signal definitions) and does not expose runtime state, credentials, secrets, or configuration values. Enumerating available interfaces and methods is equivalent to reading a public API specification — it reveals the same information available in the software's documentation and source code. The dbus-daemon's default security policy (`/etc/dbus-1/system.conf`) allows introspection by default for all authenticated users. No known implementation vulnerability exists in the `Introspect` method handler in dbus-daemon, GDBus, or sd-bus that would allow memory corruption, information leakage beyond the API schema, or privilege escalation.

**Classification:**
SAFE

## 7) METHOD_RETURN - REPLY_SERIAL
**Message:** METHOD_RETURN
**Target Bus Field's path:** REPLY_SERIAL
**Threat Model:**
- **Attack Assumption:**
On the target Linux host, the system D-Bus daemon mediates IPC between processes following the D-Bus Specification.
We assume: (i) the system D-Bus bus is accessible to unprivileged local users; (ii) the attacker has local shell access; (iii) the attacker attempts to craft a METHOD_RETURN message with a spoofed REPLY_SERIAL header field to inject a fake reply into another client's pending call; (iv) the attacker can send raw D-Bus wire protocol messages; and (v) the dbus-daemon is a standard build without modifications.
- **Attacker Capability:**
The attacker can send D-Bus METHOD_RETURN messages to the system bus with a controlled REPLY_SERIAL value.
**Security Analysis:**
The REPLY_SERIAL header field in a METHOD_RETURN message indicates which METHOD_CALL (by serial number) this reply corresponds to. The attacker attempts to forge a METHOD_RETURN with a REPLY_SERIAL matching another client's pending METHOD_CALL, hoping to inject a fake response. However, this attack is prevented by the D-Bus daemon's message routing architecture. Per the D-Bus Specification, METHOD_RETURN messages must include a DESTINATION header field set to the unique bus name of the original caller. The dbus-daemon enforces that: (a) only the actual destination service (the one that received the METHOD_CALL) can send a METHOD_RETURN for that serial, because the daemon tracks pending replies and matches them by sender; (b) the SENDER header field is always overwritten by dbus-daemon with the actual unique bus name of the sending process — it cannot be spoofed; and (c) the receiving client's D-Bus library (libdbus, GDBus, sd-bus) matches incoming METHOD_RETURN messages by both REPLY_SERIAL and SENDER, rejecting replies from unexpected senders. Even if the attacker guesses the correct REPLY_SERIAL value, the reply will be rejected because the SENDER field will show the attacker's unique bus name, not the expected service's name. No known implementation vulnerability exists in dbus-daemon's reply tracking that would allow reply injection across different bus connections.

**Classification:**
SAFE

## 8) SIGNAL - SENDER
**Message:** SIGNAL
**Target Bus Field's path:** SENDER
**Threat Model:**
- **Attack Assumption:**
On the target Linux host, the system D-Bus daemon mediates IPC between processes following the D-Bus Specification.
We assume: (i) the system D-Bus bus is accessible to unprivileged local users; (ii) the attacker has local shell access; (iii) the attacker attempts to spoof the SENDER header field in a SIGNAL message to impersonate a privileged system service (e.g., `org.freedesktop.NetworkManager`); (iv) the attacker can craft raw D-Bus wire protocol messages; and (v) the dbus-daemon is a standard build.
- **Attacker Capability:**
The attacker can send D-Bus SIGNAL messages to the system bus with a controlled SENDER header field value in the wire-level message.
**Security Analysis:**
The SENDER header field identifies the unique bus name of the process that sent the message. The attacker attempts to set SENDER to a privileged service's unique bus name (e.g., `:1.5` belonging to NetworkManager) to make the signal appear to originate from that service. However, this attack is fundamentally prevented by the D-Bus daemon's architecture. Per the D-Bus Specification (section "Message Bus Messages"), the message bus daemon always overwrites the SENDER header field with the actual unique bus name of the sending connection before forwarding the message to any recipient. This is enforced in `bus_dispatch()` in dbus-daemon and is not configurable. The attacker's message will always arrive at recipients with SENDER set to the attacker's own unique bus name (e.g., `:1.42`), regardless of what value the attacker placed in the SENDER field. This is a fundamental security invariant of the D-Bus message bus — the SENDER field is trusted precisely because it is always set by the daemon, never by the sender. No known implementation vulnerability exists in dbus-daemon, dbus-broker, or any compliant D-Bus bus implementation that would allow SENDER spoofing. The field is effectively read-only from the sender's perspective.

**Classification:**
SAFE

## 9) ERROR - ERROR_NAME
**Message:** ERROR
**Target Bus Field's path:** ERROR_NAME
**Threat Model:**
- **Attack Assumption:**
On the target Linux host, the system D-Bus daemon mediates IPC between processes following the D-Bus Specification.
We assume: (i) the system D-Bus bus is accessible to unprivileged local users; (ii) the attacker has local shell access; (iii) the attacker attempts to craft an ERROR message with a malicious ERROR_NAME header field to cause unexpected behavior in a receiving client; (iv) the attacker can send raw D-Bus wire protocol messages; and (v) the target client application uses a standard D-Bus library (libdbus, GDBus, or sd-bus).
- **Attacker Capability:**
The attacker can send D-Bus ERROR messages to the system bus with a controlled ERROR_NAME value.
**Security Analysis:**
The ERROR_NAME header field in an ERROR message contains a dot-separated error identifier string (e.g., `org.freedesktop.DBus.Error.ServiceUnknown`). The attacker attempts to inject a crafted ERROR message with a malicious ERROR_NAME to confuse or crash a client application. However, this attack is prevented by the same mechanisms that protect METHOD_RETURN messages. Per the D-Bus Specification, ERROR messages are replies to METHOD_CALL messages and must include a REPLY_SERIAL and DESTINATION. The dbus-daemon tracks pending replies and only allows the actual destination service to send ERROR replies for a given METHOD_CALL. The SENDER field is overwritten by the daemon, so the client can verify the error came from the expected service. Furthermore, the ERROR_NAME field is validated by dbus-daemon to conform to the D-Bus interface naming rules (dot-separated identifiers, no special characters, maximum 255 bytes). The D-Bus Specification defines ERROR_NAME as a simple string identifier — client libraries treat it as an opaque error code for matching against known error names. Standard D-Bus libraries (libdbus `dbus_message_get_error_name()`, GDBus `g_dbus_message_get_error_name()`, sd-bus `sd_bus_message_get_error()`) return it as a plain string without interpretation, evaluation, or execution. No known implementation vulnerability exists in ERROR_NAME processing in any major D-Bus library that would allow code injection, buffer overflow, or unexpected behavior from a crafted error name string.

**Classification:**
SAFE

## 10) METHOD_CALL - FLAGS
**Message:** METHOD_CALL
**Target Bus Field's path:** FLAGS
**Threat Model:**
- **Attack Assumption:**
On the target Linux host, the system D-Bus daemon mediates IPC between processes following the D-Bus Specification.
We assume: (i) the system D-Bus bus is accessible to unprivileged local users; (ii) the attacker has local shell access; (iii) the attacker attempts to manipulate the FLAGS header field in a METHOD_CALL message, specifically setting the NO_REPLY_EXPECTED flag (0x1) and NO_AUTO_START flag (0x2); (iv) the attacker can send D-Bus METHOD_CALL messages via standard tools or raw wire protocol; and (v) the dbus-daemon is a standard build.
- **Attacker Capability:**
The attacker can send D-Bus METHOD_CALL messages to the system bus with controlled FLAGS values.
**Security Analysis:**
The FLAGS field in the D-Bus message header is a byte containing bitwise flags that modify message handling behavior. The D-Bus Specification defines two flags for METHOD_CALL: NO_REPLY_EXPECTED (0x1), which tells the recipient that no METHOD_RETURN or ERROR reply is needed, and NO_AUTO_START (0x2), which tells the bus daemon not to auto-launch the destination service if it is not already running. Manipulating these flags has no security impact. Setting NO_REPLY_EXPECTED simply means the caller does not expect a reply — the recipient service still processes the method call with full authorization checks (polkit, D-Bus policy, application-level ACLs). The flag only affects whether a reply message is generated, not whether the request is authorized or executed. Setting NO_AUTO_START prevents service activation, which is a restrictive action (it can only prevent a service from starting, not force one to start that wouldn't otherwise). Setting both flags simultaneously, or setting undefined flag bits, is handled gracefully by dbus-daemon: undefined bits are ignored per the specification's forward-compatibility rules. The FLAGS field cannot bypass authentication, authorization, or access control. No known implementation vulnerability exists in dbus-daemon's flag processing that would allow privilege escalation, denial of service, or information disclosure through FLAGS manipulation alone.

**Classification:**
SAFE

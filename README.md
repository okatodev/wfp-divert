# WFP Selective Proxy Redirector (Windows)

[Читать на русском (README_RU.md) ->](README_RU.md)

A lightweight, high-performance background utility written in C++17 designed to selectively redirect UDP/TCP traffic of specific Windows applications through a local SOCKS5 proxy. 

It is designed to solve latency and connection blocks in applications like Discord (WebRTC voice calls) and Telegram, utilizing a routing model on top of the Windows Filtering Platform (WFP).

---

## Key Features

- **Ultra-lightweight:** Written in native C++17 with zero heavy dependencies, resulting in minimal CPU and RAM usage.
- **Active Resource Management:** Includes a background session cleanup worker that terminates inactive UDP SOCKS5 tunnels and threads after 60 seconds of idle time, preventing operating system handle and memory leaks.
- **Double-check Cache Optimization:** Resolves process PIDs only once per active UDP port. Subsequent packets are routed instantly via a memory-cached session table, eliminating expensive IP Helper API socket table queries.
- **System Tray Integration:** 
  - Runs silently in the Windows system tray.
  - Hides/shows console logs on-demand from the tray context menu.
  - Disables the console close button ("X") to prevent accidental app termination when logs are visible.
  - Reloads configuration files dynamically on-the-fly.

---

## How It Works Under the Hood

```text
 [Target App (e.g. Discord)] 
       │
       ├──► TCP Traffic  ──► Windows System Proxy ──► SOCKS5 (v2rayN) ──► VPN/VPS
       │
       └──► UDP (Voice)  ──► WinDivert Driver     ──► SOCKS5 (UDP Assoc) ──► VPN/VPS
```

1. **TCP Connection:** The proxy client (like v2rayN) sets the Windows system proxy. Discord (an Electron/Chromium app) automatically detects it and routes its TCP traffic (WebSocket gateway, media, text API) directly through SOCKS5.
2. **UDP Interception:** Discord establishes its voice/video connection via WebRTC (UDP). Standard system proxies do not support UDP routing, so the kernel-level driver (`WinDivert64.sys`) intercepts outgoing UDP frames.
3. **Process Matching:** The engine inspects the outgoing port, scans active system socket tables via `GetExtendedUdpTable`, and matches the port to a Process ID (PID) and executable name (e.g., `discord.exe`).
4. **Proxy Encapsulation:** If the executable matches the blacklist, the engine drops the raw packet, encapsulates its payload in a SOCKS5 UDP Associate wrapper, and forwards it to the local proxy.
5. **Reinjection:** The background receiver thread decrypts returning packets from SOCKS5, reconstructs the IP/UDP frames with the original physical adapter interface index (`IfIdx`), and injects them back so the application receives them.

---

## Directory Structure

```text
wfp-divert/
├── CMakeLists.txt
├── config.example.json
├── include/
│   ├── config.h
│   ├── divert.h
│   ├── process_info.h
│   ├── socks5_tcp.h
│   └── socks5_udp.h
├── src/
│   ├── main.cpp
│   ├── config.cpp
│   ├── divert.cpp
│   ├── process_info.cpp
│   ├── socks5_tcp.cpp
│   └── socks5_udp.cpp
└── windivert/
    ├── windivert.h
    ├── x64/
    │   ├── WinDivert.dll
    │   ├── WinDivert.lib
    │   └── WinDivert64.sys
    └── x86/
        ├── WinDivert.dll
        ├── WinDivert.lib
        └── WinDivert32.sys
```

---

## Configuration (`config.json`)

The application reads its settings from a `config.json` file. An example file `config.example.json` is provided alongside the build:

```json
{
  "proxy_host": "127.0.0.1",
  "proxy_port": 10808,
  "intercept_tcp": false,
  "intercept_udp": true,
  "udp_session_timeout_sec": 60,
  "blacklist": [
    "discord.exe",
    "telegram.exe"
  ]
}
```

### Parameters

* **`proxy_host`** (string): The IP address of your local proxy client (usually `127.0.0.1` for v2rayN/Nekoray).
* **`proxy_port`** (integer): SOCKS5/Mixed port of your local client. Typically `10808` for v2rayN, `2080` for Nekoray, or `7890` for Clash.
* **`intercept_tcp`** (boolean): Set to `false` for the recommended hybrid setup. If `false`, rely on your proxy client's "Set system proxy" option for TCP traffic.
* **`intercept_udp`** (boolean): Set to `true` to redirect voice UDP packets through the SOCKS5 UDP Associate tunnel.
* **`udp_session_timeout_sec`** (integer): Idle time in seconds before an inactive UDP session is closed and its thread is terminated.
* **`blacklist`** (array of strings): Lowercase executable file names (with the `.exe` extension) to route through the proxy.

---

## Compilation

You must compile the project on an x64 or x86 compiler depending on your target OS (MSVC/Clang inside Visual Studio Build Tools).

1. Create a `build` directory:
   ```powershell
   mkdir build
   cd build
   ```
2. Generate build files and compile using CMake:
   ```powershell
   cmake ..
   cmake --build . --config Release
   ```
   *Note: On compilation, CMake will automatically copy `WinDivert.dll`, `WinDivert64.sys` (or 32-bit), and `config.example.json` to the output directory of your executable.*

---

## Running the Application

1. Open your proxy client (e.g., v2rayN) and set **"System Proxy"** to **"Set system proxy"** (icon in tray turns red). This will handle Discord's TCP/HTTP traffic.
2. Create `config.json` next to the executable (the program will auto-create it from `config.example.json` if it's missing on first launch).
3. Right-click the `wfp_divert.exe` and select **"Run as Administrator"** (required to load the WinDivert driver).
4. The application will start silently in the system tray. Right-click the tray icon to:
    - **Show/Hide Console Logs** (manually inspect active connections and debug logs).
    - **Edit Config** (opens `config.json` in Notepad).
    - **Reload Config** (safely restarts the interception engine on-the-fly with updated rules).
    - **Exit** (stops the engine, unloads the driver, and safely exits).
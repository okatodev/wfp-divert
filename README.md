
# WFP-Based Selective Proxy Redirector (Windows)

[Читать на русском (README_RU.md) ->](README_RU.md)

A lightweight, high-performance background utility written in C++17 designed to selectively redirect TCP and UDP traffic of specific Windows applications, hostnames, IP ranges, and GeoIP regions through a local SOCKS5 proxy.

The project is developed to resolve latency and blocking issues with voice communication in Discord (WebRTC/RTC voice calls), Telegram, and in general for any similar use cases.

---

## Key Features

- **True Transparency (No System Proxy):** The utility operates at the kernel network packet level. It is no longer required to enable the Windows system proxy in VPN clients—the program intercepts both TCP and UDP on-the-fly.
- **Double NAT (Address Reflection):** An innovative method for TCP traffic redirection. The program swaps the source and destination IP addresses, converting an outbound connection into an inbound one on a local port. This bypasses strict Windows security policies (Strong Host Model) and prevents firewall blocks without using complex loopback interfaces.
- **Bypassing Protected PPL Processes:** Resolving process IDs and names using `CreateToolhelp32Snapshot` instead of `OpenProcess`. This allows the utility to inspect and redirect traffic of protected processes (such as anti-cheat drivers or system services) to which access is closed even for the Administrator account.
- **Flexible Configuration-Driven Routing:** Supports four independent types of traffic redirection: by executable names (`apps`), by resolved domain names (`hostnames`), by specific IP ranges (`ips` using CIDR subnets), and by geographic regions (`geoip` using CIDR block files).
- **Dynamic Hostname Resolution:** Automatically resolves configured domains to their active IP addresses at startup. Intercepts and proxies only TCP traffic bound for these specific IPs, allowing other traffic to bypass the SOCKS5 tunnel natively.
- **Active Resource Management:** A background thread periodically cleans up inactive UDP sessions, closing sockets and terminating their threads after a timeout (protection against RAM and system handle leaks).

---

## How It Works Under the Hood

```text
 [Program (Discord etc)] 
       │
       ├──► TCP (Authorization/API) ──► WinDivert Driver (Double NAT) ──► SOCKS5 (v2rayN) ──► VPN/VPS
       │
       └──► UDP (Voice/WebRTC)      ──► WinDivert Driver (UDP Assoc)  ──► SOCKS5 (v2rayN) ──► VPN/VPS
```

1. **TCP Interception:** The application initiates a TCP connection. The driver (`WinDivert64.sys`) intercepts it, stores the original addresses in a NAT table keyed by the client's source port, performs IP mirroring, and routes the packet to a local TCP listener. The local listener accepts the connection, queries the NAT table for the real destination address, and translates the data via SOCKS5.
2. **UDP Interception:** WebRTC voice UDP frames are intercepted, encapsulated in a SOCKS5 header (UDP Associate), and forwarded to the proxy client.
3. **Reinjecting Responses:** A dedicated background thread receives responses from the proxy, removes the SOCKS5 wrapper, reconstructs a legitimate inbound IP/UDP (or TCP) frame specifying the original physical network adapter index (`IfIdx`), and injects it back into the network stack.

---

## Project Directory Structure

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

## Configuration Setup (`config.json`)

An example file is provided with the build under the name `config.example.json`:

```json
{
  "proxy_host": "127.0.0.1",
  "proxy_port": 10808,
  "intercept_tcp": true,
  "intercept_udp": true,
  "udp_session_timeout_sec": 60,
  "apps": [
    "discord.exe",
    "telegram.exe",
    "update.exe"
  ],
  "hostnames": [
    "example.com"
  ],
  "ips": [
    "1.1.1.1/32"
  ],
  "geoip": [
    "ru"
  ]
}
```

### Parameter Description

* **`proxy_host`** (string): The IP address of your local VPN client (usually `127.0.0.1` for v2rayN/Nekoray).
* **`proxy_port`** (number): The SOCKS5/Mixed port of your client. Typically `10808` for v2rayN or `2080` for Nekoray.
* **`intercept_tcp`** (boolean): Recommended to be set to `true`. Enables kernel-level interception of TCP connections by the driver.
* **`intercept_udp`** (boolean): Recommended to be set to `true`. Enables interception of UDP voice calls to redirect them to the proxy tunnel.
* **`udp_session_timeout_sec`** (number): Idle time in seconds, after which an inactive UDP session is closed, freeing memory.
* **`apps`** (array of strings): Process names for selective proxying in **lowercase** and strictly with the `.exe` extension.
* **`hostnames`** (array of strings): Hostnames to resolve at startup and selectively redirect.
* **`ips`** (array of strings): Specific IP addresses or CIDR subnets to selectively redirect.
* **`geoip`** (array of strings): Lowercase country codes to load corresponding subnets (e.g., `"geoip_ru.txt"`) and selectively redirect.

---

## Compilation

Building the project on Windows requires CMake and the MSVC/Clang compiler (for example, from Visual Studio Build Tools).

1. Create a `build` directory:
   ```powershell
   mkdir build
   cd build
   ```
2. Generate configuration files and compile the project:
   ```powershell
   cmake ..
   cmake --build . --config Release
   ```
   *Note: CMake will automatically copy the required `WinDivert.dll` libraries, the `WinDivert64.sys` driver (or 32-bit), and the template file `config.example.json` into the output directory next to the executable.*

---

## Running the Application

1. Run your proxy client (for example, v2rayN) and make sure its SOCKS5 port is active. **There is no need to enable System Proxy**—leave it in "Clear" (disabled) mode.
2. Create a `config.json` file in the program folder (upon the very first launch, the utility will automatically copy it from the `config.example.json` template file).
3. Run `wfp_divert.exe` **as Administrator** (required to load the WinDivert driver into the kernel).
4. The program will minimize to the tray. By right-clicking the icon near the clock, you will be able to manage the log console, edit, and instantly reload the config without restarting the utility.
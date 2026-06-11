#define NOMINMAX
#include "divert.h"
#include "process_info.h"
#include "socks5_udp.h"
#include "socks5_tcp.h"
#include "nat_table.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include "windivert.h"

#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <vector>
#include <algorithm>
#include <chrono>

static std::atomic<bool> g_running{ true };
static HANDLE            g_divert_handle = INVALID_HANDLE_VALUE;
static NatTable          g_tcp_nat;
static std::unordered_set<uint32_t> g_resolved_ips;
static std::vector<CidrBlock> g_geoip_blocks;

void StopDivertEngine() {
    g_running = false;
    if (g_divert_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(g_divert_handle);
    }
}

static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static bool IsBlacklisted(const std::string& exe_name, const Config& cfg) {
    return cfg.apps.count(ToLower(exe_name)) > 0;
}

static std::string FmtIP(uint32_t ip_net) {
    in_addr a;
    a.s_addr = ip_net;
    return inet_ntoa(a);
}

static uint32_t GetPidByUdpEndpoint(uint32_t src_ip, uint16_t src_port) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<uint8_t> buf(size);

    if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        return 0;
    }

    auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if ((row.dwLocalAddr == src_ip || row.dwLocalAddr == 0) &&
            ntohs((uint16_t)row.dwLocalPort) == ntohs(src_port)) {
            return row.dwOwningPid;
        }
    }
    return 0;
}

static uint32_t GetPidByTcpEndpoint(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<uint8_t> buf(size);

    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return 0;
    }

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if ((row.dwLocalAddr == src_ip || row.dwLocalAddr == 0) &&
            ntohs((uint16_t)row.dwLocalPort)  == ntohs(src_port) &&
            row.dwRemoteAddr == dst_ip  &&
            ntohs((uint16_t)row.dwRemotePort) == ntohs(dst_port)) {
            return row.dwOwningPid;
        }
    }
    return 0;
}

static void ParsePacket(
    void* pPacket, UINT packetLen,
    WINDIVERT_IPHDR**   ppIpHdr,
    WINDIVERT_IPV6HDR** ppIpv6Hdr,
    WINDIVERT_TCPHDR**  ppTcpHdr,
    WINDIVERT_UDPHDR**  ppUdpHdr,
    PVOID*              ppData,
    UINT*               pDataLen)
{
    UINT8                protocol = 0;
    WINDIVERT_ICMPHDR*   icmph   = nullptr;
    WINDIVERT_ICMPV6HDR* icmp6h  = nullptr;
    PVOID                pNext   = nullptr;
    UINT                 nextLen = 0;

    WinDivertHelperParsePacket(
        pPacket, packetLen,
        ppIpHdr, ppIpv6Hdr,
        &protocol,
        &icmph, &icmp6h,
        ppTcpHdr, ppUdpHdr,
        ppData, pDataLen,
        &pNext, &nextLen);
}

static void ResolveConfigHostnames(const std::vector<std::string>& hostnames) {
    g_resolved_ips.clear();
    for (const auto& domain : hostnames) {
        addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(domain.c_str(), nullptr, &hints, &res) == 0) {
            for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
                sockaddr_in* ipv4 = (sockaddr_in*)p->ai_addr;
                g_resolved_ips.insert(ipv4->sin_addr.s_addr);
                std::cout << "[divert] Resolved " << domain << " to " << inet_ntoa(ipv4->sin_addr) << "\n";
            }
            freeaddrinfo(res);
        } else {
            std::cerr << "[divert] Failed to resolve hostname: " << domain << "\n";
        }
    }
}

static void LoadGeoIpFiles(const std::vector<std::string>& geoip_codes) {
    g_geoip_blocks.clear();
    for (const auto& code : geoip_codes) {
        std::string filename = "geoip_" + code + ".txt";
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "[divert] Warning: GeoIP file not found: " << filename << "\n";
            continue;
        }
        std::string line;
        int count = 0;
        while (std::getline(file, line)) {
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            if (line.empty() || line[0] == '#') continue;

            CidrBlock block;
            if (ParseCidr(line, block)) {
                g_geoip_blocks.push_back(block);
                count++;
            }
        }
        std::cout << "[divert] Loaded " << count << " IP ranges from " << filename << "\n";
    }
}

static bool MatchCidr(uint32_t ip_host, const std::vector<CidrBlock>& blocks) {
    for (const auto& b : blocks) {
        if ((ip_host & b.mask) == (b.base_ip & b.mask)) {
            return true;
        }
    }
    return false;
}

static bool ShouldProxyByIp(uint32_t dst_ip_net, const Config& cfg) {
    if (g_resolved_ips.count(dst_ip_net) > 0) {
        return true;
    }
    uint32_t dst_ip_host = ntohl(dst_ip_net);
    if (MatchCidr(dst_ip_host, cfg.ips)) {
        return true;
    }
    if (MatchCidr(dst_ip_host, g_geoip_blocks)) {
        return true;
    }
    return false;
}

struct UdpSessionKey {
    uint32_t src_ip;
    uint16_t src_port;
    bool operator==(const UdpSessionKey& o) const {
        return src_ip == o.src_ip && src_port == o.src_port;
    }
};

struct UdpSessionKeyHash {
    size_t operator()(const UdpSessionKey& k) const {
        return std::hash<uint64_t>()((uint64_t)k.src_ip << 16 | k.src_port);
    }
};

struct UdpProxySession {
    Socks5UdpSession socks;
    uint32_t app_ip;
    uint16_t app_port;
    uint32_t if_idx;
    uint32_t sub_if_idx;
    std::thread recv_thread;
    std::chrono::steady_clock::time_point last_active;
    bool active;
};

static std::unordered_map<UdpSessionKey, UdpProxySession*, UdpSessionKeyHash> g_udp_sessions;
static std::mutex g_udp_mutex;

static void UdpRelayRecvThread(
    HANDLE divert,
    Socks5UdpSession* socks_sess,
    uint32_t app_ip,
    uint16_t app_port,
    uint32_t if_idx,
    uint32_t sub_if_idx,
    const std::atomic<bool>* running)
{
    uint8_t payload[65535];
    uint32_t orig_src_ip;
    uint16_t orig_src_port;

    while (*running) {
        DWORD timeout_ms = 2000;
        setsockopt(socks_sess->udp_sock, SOL_SOCKET, SO_RCVTIMEO,
                   (const char*)&timeout_ms, sizeof(timeout_ms));

        int n = Socks5UdpRecv(*socks_sess, orig_src_ip, orig_src_port, payload, sizeof(payload));
        if (n <= 0) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
                continue;
            }
            break;
        }

        size_t pkt_size = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + n;
        std::vector<uint8_t> pkt(pkt_size, 0);

        auto* iph  = (WINDIVERT_IPHDR*)pkt.data();
        auto* udph = (WINDIVERT_UDPHDR*)(pkt.data() + sizeof(WINDIVERT_IPHDR));
        uint8_t* data = pkt.data() + sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR);

        iph->Version   = 4;
        iph->HdrLength = sizeof(WINDIVERT_IPHDR) / 4;
        iph->Length    = htons((uint16_t)pkt_size);
        iph->TTL       = 64;
        iph->Protocol  = IPPROTO_UDP;
        iph->SrcAddr   = orig_src_ip;
        iph->DstAddr   = app_ip;

        udph->SrcPort = orig_src_port;
        udph->DstPort = app_port;
        udph->Length  = htons((uint16_t)(sizeof(WINDIVERT_UDPHDR) + n));

        memcpy(data, payload, n);

        WINDIVERT_ADDRESS addr{};
        addr.Outbound = FALSE;
        addr.Loopback = FALSE;
        addr.Network.IfIdx = if_idx;
        addr.Network.SubIfIdx = sub_if_idx;
        WinDivertHelperCalcChecksums(pkt.data(), (UINT)pkt_size, &addr, 0);

        UINT sent_len;
        WinDivertSend(divert, pkt.data(), (UINT)pkt_size, &sent_len, &addr);
    }
}

static void TcpProxyWorker(SOCKET client_sock, sockaddr_in client_addr, Config cfg) {
    NatKey key{ static_cast<uint32_t>(ntohl(client_addr.sin_addr.s_addr)), ntohs(client_addr.sin_port) };
    NatEntry entry;

    if (!g_tcp_nat.Lookup(key, entry)) {
        std::cerr << "[divert] Connection rejected: No NAT entry for "
                  << FmtIP(client_addr.sin_addr.s_addr) << ":" << ntohs(client_addr.sin_port) << "\n";
        closesocket(client_sock);
        return;
    }

    std::cout << "[divert] Routing TCP stream through proxy for "
              << FmtIP(entry.orig_dst_ip) << ":" << ntohs(entry.orig_dst_port) << "\n";

    SOCKET remote_sock = Socks5TcpConnect(cfg.proxy_host, cfg.proxy_port, entry.orig_dst_ip, entry.orig_dst_port);
    if (remote_sock == INVALID_SOCKET) {
        std::cerr << "[divert] Failed to establish SOCKS5 TCP tunnel\n";
        closesocket(client_sock);
        return;
    }

    auto pump = [](SOCKET s1, SOCKET s2) {
        char buf[16384];
        DWORD timeout_ms = 1000;
        setsockopt(s1, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));

        while (g_running) {
            int n = recv(s1, buf, sizeof(buf), 0);
            if (n <= 0) {
                int err = WSAGetLastError();
                if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
                    continue;
                }
                break;
            }
            int sent = 0;
            while (sent < n) {
                int r = send(s2, buf + sent, n - sent, 0);
                if (r <= 0) {
                    goto end;
                }
                sent += r;
            }
        }
    end:
        shutdown(s1, SD_BOTH);
        shutdown(s2, SD_BOTH);
    };

    std::thread t1(pump, client_sock, remote_sock);
    std::thread t2(pump, remote_sock, client_sock);

    t1.join();
    t2.join();

    closesocket(client_sock);
    closesocket(remote_sock);
}

static void TcpProxyAcceptThread(SOCKET listen_sock, Config cfg) {
    while (g_running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listen_sock, &readfds);

        timeval tv{ 1, 0 };
        int ret = select(0, &readfds, nullptr, nullptr, &tv);

        if (ret > 0 && FD_ISSET(listen_sock, &readfds)) {
            sockaddr_in client_addr{};
            int addrlen = sizeof(client_addr);
            SOCKET client_sock = accept(listen_sock, (sockaddr*)&client_addr, &addrlen);
            if (client_sock != INVALID_SOCKET) {
                std::cout << "[divert] Local TCP Proxy accepted connection from virtual port " << ntohs(client_addr.sin_port) << "\n";
                std::thread(TcpProxyWorker, client_sock, client_addr, cfg).detach();
            }
        }
    }
    closesocket(listen_sock);
}

void RunDivertEngine(const Config& cfg) {
    g_running = true;
    uint16_t local_tcp_port = 0;
    SOCKET tcp_listener = INVALID_SOCKET;

    if (cfg.intercept_tcp) {
        tcp_listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (tcp_listener != INVALID_SOCKET) {
            sockaddr_in bind_addr{};
            bind_addr.sin_family = AF_INET;
            bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
            bind_addr.sin_port = 0;

            bind(tcp_listener, (sockaddr*)&bind_addr, sizeof(bind_addr));
            listen(tcp_listener, SOMAXCONN);

            int len = sizeof(bind_addr);
            getsockname(tcp_listener, (sockaddr*)&bind_addr, &len);
            local_tcp_port = ntohs(bind_addr.sin_port);

            std::thread(TcpProxyAcceptThread, tcp_listener, cfg).detach();
            std::cout << "[divert] Started local TCP proxy listener on port " << local_tcp_port << "\n";
        }
    }

    if (cfg.intercept_tcp) {
        std::cout << "[divert] Loading GeoIP routing tables...\n";
        LoadGeoIpFiles(cfg.geoip);
        std::cout << "[divert] Resolving configured hostnames...\n";
        ResolveConfigHostnames(cfg.hostnames);
    }

    std::string exclude_proxy = "";
    if (cfg.proxy_host != "127.0.0.1" && cfg.proxy_host != "localhost") {
        exclude_proxy = " and ip.DstAddr != " + cfg.proxy_host;
    }

    std::string filter = "outbound and ";
    if (cfg.intercept_tcp && cfg.intercept_udp) {
        filter += "( ( !loopback and (tcp or udp) " + exclude_proxy + " ) or ( tcp.SrcPort == " + std::to_string(local_tcp_port) + " ) )";
    } else if (cfg.intercept_tcp) {
        filter += "( ( !loopback and tcp " + exclude_proxy + " ) or ( tcp.SrcPort == " + std::to_string(local_tcp_port) + " ) )";
    } else if (cfg.intercept_udp) {
        filter += "( !loopback and udp " + exclude_proxy + " )";
    } else {
        std::cerr << "[divert] Error: No transport protocols enabled for interception\n";
        return;
    }

    std::cout << "[divert] Interception Filter: " << filter << "\n";
    std::cout << "[divert] Proxy Target Configured: " << cfg.proxy_host << ":" << cfg.proxy_port << "\n";

    HANDLE handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::cerr << "[divert] WinDivertOpen() failed with error: " << err << "\n";
        if (err == ERROR_ACCESS_DENIED) {
            std::cerr << "[divert] Administrator privileges required!\n";
        }
        return;
    }

    g_divert_handle = handle;
    std::cout << "[divert] Packet redirection loop started\n";

    std::thread expire_thread([&cfg]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            if (!g_running) {
                break;
            }

            auto now = std::chrono::steady_clock::now();
            std::vector<UdpProxySession*> to_delete;

            {
                std::lock_guard<std::mutex> lock(g_udp_mutex);
                for (auto i = g_udp_sessions.begin(); i != g_udp_sessions.end(); ) {
                    auto* sess = i->second;
                    auto idle_sec = std::chrono::duration_cast<std::chrono::seconds>(now - sess->last_active).count();

                    if (idle_sec > cfg.udp_session_timeout_sec) {
                        to_delete.push_back(sess);
                        i = g_udp_sessions.erase(i);
                    } else {
                        ++i;
                    }
                }
            }

            for (auto* sess : to_delete) {
                std::cout << "[divert] Cleaning up inactive UDP session on port: " << ntohs(sess->app_port) << " (Timeout)\n";
                sess->active = false;
                Socks5UdpClose(sess->socks);
                if (sess->recv_thread.joinable()) {
                    sess->recv_thread.join();
                }
                delete sess;
            }

            if (cfg.intercept_tcp) {
                g_tcp_nat.Expire(cfg.udp_session_timeout_sec * 30);
            }
        }
    });

    constexpr size_t BUFSIZE = 65535 + 40;
    std::vector<uint8_t> packet(BUFSIZE);
    WINDIVERT_ADDRESS    addr{};
    UINT                 recv_len = 0;

    while (g_running) {
        if (!WinDivertRecv(handle, packet.data(), (UINT)packet.size(), &recv_len, &addr)) {
            if (g_running) {
                std::cerr << "[divert] WinDivertRecv failed with error: " << GetLastError() << "\n";
            }
            break;
        }

        WINDIVERT_IPHDR*   iph       = nullptr;
        WINDIVERT_IPV6HDR* ip6h      = nullptr;
        WINDIVERT_TCPHDR*  tcph      = nullptr;
        WINDIVERT_UDPHDR*  udph      = nullptr;
        uint8_t*           payload   = nullptr;
        UINT               payload_len = 0;

        ParsePacket(packet.data(), recv_len, &iph, &ip6h, &tcph, &udph, (PVOID*)&payload, &payload_len);

        if (!iph) {
            WinDivertSend(handle, packet.data(), recv_len, nullptr, &addr);
            continue;
        }

        uint32_t src_ip   = iph->SrcAddr;
        uint32_t dst_ip   = iph->DstAddr;
        uint16_t src_port = udph ? udph->SrcPort : (tcph ? tcph->SrcPort : 0);
        uint16_t dst_port = udph ? udph->DstPort : (tcph ? tcph->DstPort : 0);

        if (tcph && cfg.intercept_tcp && ntohs(src_port) == local_tcp_port) {
            NatKey key{ static_cast<uint32_t>(ntohl(dst_ip)), ntohs(dst_port) };
            NatEntry entry;
            if (g_tcp_nat.Lookup(key, entry)) {
                uint32_t tmp_dst = iph->DstAddr;
                tcph->SrcPort = entry.orig_dst_port;
                iph->DstAddr = iph->SrcAddr;
                iph->SrcAddr = tmp_dst;

                addr.Outbound = FALSE;
                addr.Loopback = FALSE;
                addr.Network.IfIdx = entry.if_idx;
                addr.Network.SubIfIdx = entry.sub_if_idx;

                WinDivertHelperCalcChecksums(packet.data(), recv_len, &addr, 0);
                WinDivertSend(handle, packet.data(), recv_len, nullptr, &addr);
                continue;
            }
        }

        bool should_proxy = false;
        UdpProxySession* sess = nullptr;
        NatEntry tcp_entry;

        if (udph) {
            UdpSessionKey key{ src_ip, src_port };
            std::lock_guard<std::mutex> lock(g_udp_mutex);
            auto it = g_udp_sessions.find(key);
            if (it != g_udp_sessions.end()) {
                sess = it->second;
                sess->last_active = std::chrono::steady_clock::now();
                should_proxy = true;
            }
        } else if (tcph && cfg.intercept_tcp) {
            NatKey key{ static_cast<uint32_t>(ntohl(dst_ip)), ntohs(src_port) };
            if (g_tcp_nat.Lookup(key, tcp_entry)) {
                should_proxy = true;
            } else if (ShouldProxyByIp(dst_ip, cfg)) {
                should_proxy = true;
                tcp_entry.orig_dst_ip = dst_ip;
                tcp_entry.orig_dst_port = dst_port;
                tcp_entry.if_idx = addr.Network.IfIdx;
                tcp_entry.sub_if_idx = addr.Network.SubIfIdx;
                g_tcp_nat.Insert(key, tcp_entry);
                std::cout << "[divert] Intercepted connection to bypassed IP: " << FmtIP(dst_ip) << ":" << ntohs(dst_port) << "\n";
            }
        }

        std::string proc_name;
        if (!should_proxy) {
            uint32_t pid = 0;
            if (udph) {
                pid = GetPidByUdpEndpoint(src_ip, src_port);
            } else if (tcph && cfg.intercept_tcp && tcph->Syn && !tcph->Ack) {
                pid = GetPidByTcpEndpoint(src_ip, src_port, dst_ip, dst_port);
            }

            if (pid > 0) {
                proc_name = GetProcessName(pid);
                should_proxy = !proc_name.empty() && IsBlacklisted(proc_name, cfg);

                if (should_proxy && tcph) {
                    NatKey key{ static_cast<uint32_t>(ntohl(dst_ip)), ntohs(src_port) };
                    tcp_entry.orig_dst_ip = dst_ip;
                    tcp_entry.orig_dst_port = dst_port;
                    tcp_entry.if_idx = addr.Network.IfIdx;
                    tcp_entry.sub_if_idx = addr.Network.SubIfIdx;
                    g_tcp_nat.Insert(key, tcp_entry);
                }
            }
        }

        if (!should_proxy) {
            WinDivertSend(handle, packet.data(), recv_len, nullptr, &addr);
            continue;
        }

        if (!proc_name.empty()) {
            std::cout << "[divert] [" << proc_name << " PID="
                      << (udph ? GetPidByUdpEndpoint(src_ip, src_port) : GetPidByTcpEndpoint(src_ip, src_port, dst_ip, dst_port))
                      << "] " << FmtIP(src_ip) << ":" << ntohs(src_port)
                      << " -> " << FmtIP(dst_ip) << ":" << ntohs(dst_port)
                      << (udph ? " UDP" : " TCP") << "\n";
        }

        if (udph && payload && payload_len > 0) {
            UdpSessionKey key{ src_ip, src_port };

            if (!sess) {
                std::lock_guard<std::mutex> lock(g_udp_mutex);
                auto it = g_udp_sessions.find(key);
                if (it != g_udp_sessions.end()) {
                    sess = it->second;
                    sess->last_active = std::chrono::steady_clock::now();
                } else {
                    auto* ns = new UdpProxySession{};
                    ns->app_ip   = src_ip;
                    ns->app_port = src_port;
                    ns->if_idx   = addr.Network.IfIdx;
                    ns->sub_if_idx = addr.Network.SubIfIdx;
                    ns->active   = true;
                    ns->last_active = std::chrono::steady_clock::now();

                    if (Socks5UdpAssociate(cfg.proxy_host, cfg.proxy_port, ns->socks)) {
                        ns->recv_thread = std::thread(
                            UdpRelayRecvThread,
                            handle, &ns->socks,
                            src_ip, src_port,
                            addr.Network.IfIdx, addr.Network.SubIfIdx,
                            &g_running);
                        g_udp_sessions[key] = ns;
                        sess = ns;
                        std::cout << "[divert] Started background UDP tunnel worker\n";
                    } else {
                        std::cerr << "[divert] SOCKS5 UDP Associate handshake failed - packet dropped\n";
                        delete ns;
                        WinDivertSend(handle, packet.data(), recv_len, nullptr, &addr);
                        continue;
                    }
                }
            }

            if (!Socks5UdpSend(sess->socks, dst_ip, dst_port, payload, payload_len)) {
                std::cerr << "[divert] SOCKS5 UDP payload delivery failed\n";
            }
            continue;
        }

        if (tcph && cfg.intercept_tcp) {
            uint32_t tmp_dst = iph->DstAddr;
            tcph->DstPort = htons(local_tcp_port);
            iph->DstAddr = iph->SrcAddr;
            iph->SrcAddr = tmp_dst;

            addr.Outbound = FALSE;
            addr.Loopback = FALSE;

            WinDivertHelperCalcChecksums(packet.data(), recv_len, &addr, 0);
            WinDivertSend(handle, packet.data(), recv_len, nullptr, &addr);
            continue;
        }

        WinDivertSend(handle, packet.data(), recv_len, nullptr, &addr);
    }

    {
        std::lock_guard<std::mutex> lock(g_udp_mutex);
        for (auto& [k, sess] : g_udp_sessions) {
            sess->active = false;
            Socks5UdpClose(sess->socks);
            if (sess->recv_thread.joinable()) {
                sess->recv_thread.join();
            }
            delete sess;
        }
        g_udp_sessions.clear();
    }

    WinDivertClose(handle);
    g_divert_handle = INVALID_HANDLE_VALUE;

    expire_thread.join();
    std::cout << "[divert] Packet redirection loop stopped\n";
}
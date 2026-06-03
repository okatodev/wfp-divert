#define NOMINMAX
#include "divert.h"
#include "process_info.h"
#include "socks5_udp.h"
#include "socks5_tcp.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include "windivert.h"

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <algorithm>
#include <chrono>

static std::atomic<bool> g_running{ true };
static HANDLE            g_divert_handle = INVALID_HANDLE_VALUE;

void StopDivertEngine() {
    g_running = false;
    if (g_divert_handle != INVALID_HANDLE_VALUE)
        WinDivertClose(g_divert_handle);
}

static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static bool IsBlacklisted(const std::string& exe_name, const Config& cfg) {
    return cfg.blacklist.count(ToLower(exe_name)) > 0;
}

static std::string FmtIP(uint32_t ip_net) {
    in_addr a; a.s_addr = ip_net;
    return inet_ntoa(a);
}

static uint32_t GetPidByUdpEndpoint(uint32_t src_ip, uint16_t src_port) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<uint8_t> buf(size);

    if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
        return 0;

    auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        /* CRITICAL: Compare ports in host-byte order to account for client 0.0.0.0 local bindings */
        if ((row.dwLocalAddr == src_ip || row.dwLocalAddr == 0) &&
            ntohs((uint16_t)row.dwLocalPort) == ntohs(src_port))
            return row.dwOwningPid;
    }
    return 0;
}

static uint32_t GetPidByTcpEndpoint(uint32_t src_ip, uint16_t src_port,
                                     uint32_t dst_ip, uint16_t dst_port) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<uint8_t> buf(size);

    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return 0;

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if ((row.dwLocalAddr == src_ip || row.dwLocalAddr == 0) &&
            ntohs((uint16_t)row.dwLocalPort)  == ntohs(src_port) &&
            row.dwRemoteAddr == dst_ip  &&
            ntohs((uint16_t)row.dwRemotePort) == ntohs(dst_port))
            return row.dwOwningPid;
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
            /* CRITICAL: Break if socket gets closed/reset to prevent high CPU spin cycles */
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
        /* CRITICAL: Assign physical adapter interface index so Windows WFP accepts the faked inbound frame */
        addr.Network.IfIdx = if_idx;
        addr.Network.SubIfIdx = sub_if_idx;
        WinDivertHelperCalcChecksums(pkt.data(), (UINT)pkt_size, &addr, 0);

        UINT sent_len;
        WinDivertSend(divert, pkt.data(), (UINT)pkt_size, &sent_len, &addr);
    }
}

void RunDivertEngine(const Config& cfg) {
    std::string proxy_ip = cfg.proxy_host;
    std::string proto_filter;

    if (cfg.intercept_udp && cfg.intercept_tcp) {
        proto_filter = "(udp or tcp)";
    } else if (cfg.intercept_udp) {
        proto_filter = "udp";
    } else if (cfg.intercept_tcp) {
        proto_filter = "tcp";
    } else {
        std::cerr << "[divert] Error: No transport protocols enabled for interception\n";
        return;
    }

    std::string filter = "outbound and !loopback and " + proto_filter;

    if (proxy_ip != "127.0.0.1" && proxy_ip != "localhost") {
        std::string port_exclude;
        if (cfg.intercept_udp && cfg.intercept_tcp) {
            port_exclude = "(tcp? tcp.DstPort != " + std::to_string(cfg.proxy_port) +
                           " : (udp? udp.DstPort != " + std::to_string(cfg.proxy_port) + " : true))";
        } else if (cfg.intercept_udp) {
            port_exclude = "udp.DstPort != " + std::to_string(cfg.proxy_port);
        } else if (cfg.intercept_tcp) {
            port_exclude = "tcp.DstPort != " + std::to_string(cfg.proxy_port);
        }
        filter += " and (ip.DstAddr != " + proxy_ip + " or " + port_exclude + ")";
    }

    std::cout << "[divert] Interception Filter: " << filter << "\n";
    std::cout << "[divert] Proxy Target Configured: " << cfg.proxy_host << ":" << cfg.proxy_port << "\n";

    HANDLE handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::cerr << "[divert] WinDivertOpen() failed with error: " << err << "\n";
        if (err == ERROR_ACCESS_DENIED)
            std::cerr << "[divert] Administrator privileges required!\n";
        return;
    }

    g_divert_handle = handle;
    std::cout << "[divert] Packet redirection loop started\n";

    /* Active UDP session clean-up worker to prevent system resource leakage */
    std::thread expire_thread([&cfg]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            if (!g_running) break;

            auto now = std::chrono::steady_clock::now();
            std::vector<UdpProxySession*> to_delete;

            {
                std::lock_guard<std::mutex> lock(g_udp_mutex);
                for (auto it = g_udp_sessions.begin(); it != g_udp_sessions.end(); ) {
                    auto* sess = it->second;
                    auto idle_sec = std::chrono::duration_cast<std::chrono::seconds>(now - sess->last_active).count();

                    if (idle_sec > cfg.udp_session_timeout_sec) {
                        to_delete.push_back(sess);
                        it = g_udp_sessions.erase(it);
                    } else {
                        ++it;
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
        }
    });

    constexpr size_t BUFSIZE = 65535 + 40;
    std::vector<uint8_t> packet(BUFSIZE);
    WINDIVERT_ADDRESS    addr{};
    UINT                 recv_len = 0;

    while (g_running) {
        if (!WinDivertRecv(handle, packet.data(), (UINT)packet.size(), &recv_len, &addr)) {
            if (g_running)
                std::cerr << "[divert] WinDivertRecv failed with error: " << GetLastError() << "\n";
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

        /* CRITICAL: Query cache map first to skip costly PID queries on every single active packet stream */
        bool should_proxy = false;
        UdpProxySession* sess = nullptr;

        if (udph) {
            UdpSessionKey key{ src_ip, src_port };
            std::lock_guard<std::mutex> lock(g_udp_mutex);
            auto it = g_udp_sessions.find(key);
            if (it != g_udp_sessions.end()) {
                sess = it->second;
                sess->last_active = std::chrono::steady_clock::now();
                should_proxy = true;
            }
        }

        std::string proc_name;
        if (!should_proxy) {
            uint32_t pid = 0;
            if (udph)
                pid = GetPidByUdpEndpoint(src_ip, src_port);
            else if (tcph)
                pid = GetPidByTcpEndpoint(src_ip, src_port, dst_ip, dst_port);

            if (pid > 0)
                proc_name = GetProcessName(pid);

            should_proxy = !proc_name.empty() && IsBlacklisted(proc_name, cfg);
        }

        if (!should_proxy) {
            WinDivertSend(handle, packet.data(), recv_len, nullptr, &addr);
            continue;
        }

        if (!proc_name.empty()) {
            std::cout << "[divert] [" << proc_name << " PID=" << GetPidByUdpEndpoint(src_ip, src_port) << "] "
                      << FmtIP(src_ip) << ":" << ntohs(src_port)
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
                        std::cerr << "[divert] SOCKS5 UDP Associate handshakes failed - packet dropped\n";
                        delete ns;
                        WinDivertSend(handle, packet.data(), recv_len, nullptr, &addr);
                        continue;
                    }
                }
            }

            if (!Socks5UdpSend(sess->socks, dst_ip, dst_port, payload, payload_len))
                std::cerr << "[divert] SOCKS5 UDP payload delivery failed\n";
            continue;
        }

        if (tcph) {
            bool is_syn = (tcph->Syn && !tcph->Ack);
            if (!is_syn) {
                WinDivertSend(handle, packet.data(), recv_len, nullptr, &addr);
                continue;
            }
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
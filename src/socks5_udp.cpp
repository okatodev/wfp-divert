#define NOMINMAX
#include "socks5_udp.h"
#include <ws2tcpip.h>
#include <iostream>
#include <cstring>
#include <vector>

static bool SendAll(SOCKET s, const uint8_t* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, (const char*)(buf + sent), len - sent, 0);
        if (n == SOCKET_ERROR) return false;
        sent += n;
    }
    return true;
}

static bool RecvAll(SOCKET s, uint8_t* buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(s, (char*)(buf + got), len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

bool Socks5UdpAssociate(
    const std::string& proxy_host,
    uint16_t           proxy_port,
    Socks5UdpSession&  out)
{
    SOCKET ctrl = socket(AF_INET, SOCK_STREAM, 0);
    if (ctrl == INVALID_SOCKET) {
        std::cerr << "[socks5_udp] Failed to create control socket: " << WSAGetLastError() << "\n";
        return false;
    }

    sockaddr_in proxy_addr{};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port   = htons(proxy_port);
    inet_pton(AF_INET, proxy_host.c_str(), &proxy_addr.sin_addr);

    if (connect(ctrl, (sockaddr*)&proxy_addr, sizeof(proxy_addr)) == SOCKET_ERROR) {
        std::cerr << "[socks5_udp] Control connection failed: " << WSAGetLastError() << "\n";
        closesocket(ctrl);
        return false;
    }

    uint8_t handshake[] = { 0x05, 0x01, 0x00 };
    if (!SendAll(ctrl, handshake, sizeof(handshake))) {
        closesocket(ctrl); return false;
    }

    uint8_t hs_resp[2];
    if (!RecvAll(ctrl, hs_resp, 2) || hs_resp[0] != 0x05 || hs_resp[1] != 0x00) {
        std::cerr << "[socks5_udp] SOCKS5 handshake rejected\n";
        closesocket(ctrl); return false;
    }

    uint8_t req[] = { 0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    if (!SendAll(ctrl, req, sizeof(req))) {
        closesocket(ctrl); return false;
    }

    uint8_t resp[10];
    if (!RecvAll(ctrl, resp, 10) || resp[0] != 0x05 || resp[1] != 0x00) {
        std::cerr << "[socks5_udp] UDP ASSOCIATE rejected with code: " << (int)resp[1] << "\n";
        closesocket(ctrl); return false;
    }
    if (resp[3] != 0x01) {
        std::cerr << "[socks5_udp] Non-IPv4 binding addresses are not supported\n";
        closesocket(ctrl); return false;
    }

    uint32_t relay_ip;
    uint16_t relay_port;
    memcpy(&relay_ip,   resp + 4, 4);
    memcpy(&relay_port, resp + 8, 2);

    if (relay_ip == 0)
        relay_ip = proxy_addr.sin_addr.s_addr;

    std::cout << "[socks5_udp] UDP relay target bound to: "
              << inet_ntoa(*(in_addr*)&relay_ip) << ":" << ntohs(relay_port) << "\n";

    SOCKET udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock == INVALID_SOCKET) {
        closesocket(ctrl); return false;
    }
    sockaddr_in local{};
    local.sin_family      = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port        = 0;
    if (bind(udp_sock, (sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        closesocket(ctrl); closesocket(udp_sock); return false;
    }

    int local_len = sizeof(local);
    getsockname(udp_sock, (sockaddr*)&local, &local_len);

    out.ctrl_sock       = ctrl;
    out.udp_sock        = udp_sock;
    out.relay_ip        = relay_ip;
    out.relay_port      = relay_port;
    out.local_udp_port  = local.sin_port;

    return true;
}

bool Socks5UdpSend(
    const Socks5UdpSession& s,
    uint32_t dst_ip,
    uint16_t dst_port,
    const uint8_t* payload,
    size_t payload_len)
{
    std::vector<uint8_t> buf;
    buf.resize(10 + payload_len);
    buf[0] = 0x00; buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x01;
    memcpy(buf.data() + 4, &dst_ip,   4);
    memcpy(buf.data() + 8, &dst_port, 2);
    memcpy(buf.data() + 10, payload, payload_len);

    sockaddr_in relay_addr{};
    relay_addr.sin_family      = AF_INET;
    relay_addr.sin_addr.s_addr = s.relay_ip;
    relay_addr.sin_port        = s.relay_port;

    int n = sendto(s.udp_sock, (const char*)buf.data(), (int)buf.size(), 0,
                   (sockaddr*)&relay_addr, sizeof(relay_addr));
    return (n == (int)buf.size());
}

int Socks5UdpRecv(
    const Socks5UdpSession& s,
    uint32_t& out_src_ip,
    uint16_t& out_src_port,
    uint8_t*  buf,
    size_t    buf_len)
{
    std::vector<uint8_t> raw(buf_len + 10);
    sockaddr_in from{};
    int from_len = sizeof(from);

    int n = recvfrom(s.udp_sock, (char*)raw.data(), (int)raw.size(), 0,
                     (sockaddr*)&from, &from_len);
    if (n < 10) return -1;

    if (raw[3] != 0x01) return -1;

    memcpy(&out_src_ip,   raw.data() + 4, 4);
    memcpy(&out_src_port, raw.data() + 8, 2);

    int payload_len = n - 10;
    if (payload_len <= 0) return 0;
    memcpy(buf, raw.data() + 10, static_cast<size_t>(payload_len) < buf_len ? static_cast<size_t>(payload_len) : buf_len);
    return payload_len;
}

void Socks5UdpClose(Socks5UdpSession& s) {
    if (s.ctrl_sock != INVALID_SOCKET) { closesocket(s.ctrl_sock); s.ctrl_sock = INVALID_SOCKET; }
    if (s.udp_sock  != INVALID_SOCKET) { closesocket(s.udp_sock);  s.udp_sock  = INVALID_SOCKET; }
}
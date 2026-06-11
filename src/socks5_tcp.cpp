#define NOMINMAX
#include "socks5_tcp.h"
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

SOCKET Socks5TcpConnect(
    const std::string& proxy_host,
    uint16_t           proxy_port,
    uint32_t           dst_ip,
    uint16_t           dst_port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in proxy_addr{};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port   = htons(proxy_port);
    inet_pton(AF_INET, proxy_host.c_str(), &proxy_addr.sin_addr);

    if (connect(s, (sockaddr*)&proxy_addr, sizeof(proxy_addr)) == SOCKET_ERROR) {
        std::cerr << "[socks5_tcp] TCP connection to proxy failed: " << WSAGetLastError() << "\n";
        closesocket(s);
        return INVALID_SOCKET;
    }

    uint8_t hs[] = { 0x05, 0x01, 0x00 };
    if (!SendAll(s, hs, 3)) { closesocket(s); return INVALID_SOCKET; }

    uint8_t hs_resp[2];
    if (!RecvAll(s, hs_resp, 2) || hs_resp[0] != 0x05 || hs_resp[1] != 0x00) {
        std::cerr << "[socks5_tcp] Authentication method rejected\n";
        closesocket(s); return INVALID_SOCKET;
    }

    uint8_t req[10] = { 0x05, 0x01, 0x00, 0x01 };
    memcpy(req + 4, &dst_ip,   4);
    memcpy(req + 8, &dst_port, 2);

    if (!SendAll(s, req, 10)) { closesocket(s); return INVALID_SOCKET; }

    uint8_t resp_header[4];
    if (!RecvAll(s, resp_header, 4)) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    if (resp_header[0] != 0x05 || resp_header[1] != 0x00) {
        std::cerr << "[socks5_tcp] CONNECT request rejected with code: " << (int)resp_header[1] << "\n";
        closesocket(s);
        return INVALID_SOCKET;
    }

    int remaining = 0;
    if (resp_header[3] == 0x01) {
        remaining = 6;
    } else if (resp_header[3] == 0x03) {
        uint8_t len_byte;
        if (!RecvAll(s, &len_byte, 1)) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        remaining = len_byte + 2;
    } else if (resp_header[3] == 0x04) {
        remaining = 18;
    } else {
        std::cerr << "[socks5_tcp] Unknown address type in response: " << (int)resp_header[3] << "\n";
        closesocket(s);
        return INVALID_SOCKET;
    }

    if (remaining > 0) {
        std::vector<uint8_t> dummy(remaining);
        if (!RecvAll(s, dummy.data(), remaining)) {
            closesocket(s);
            return INVALID_SOCKET;
        }
    }

    return s;
}
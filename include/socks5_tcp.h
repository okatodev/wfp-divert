#pragma once
#include <winsock2.h>
#include <string>

SOCKET Socks5TcpConnect(
    const std::string& proxy_host,
    uint16_t           proxy_port,
    uint32_t           dst_ip,
    uint16_t           dst_port);
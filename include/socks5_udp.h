#pragma once
#include <winsock2.h>
#include <string>

struct Socks5UdpSession {
    SOCKET  ctrl_sock;
    SOCKET  udp_sock;
    uint32_t relay_ip;
    uint16_t relay_port;
    uint16_t local_udp_port;
};

bool Socks5UdpAssociate(
    const std::string& proxy_host,
    uint16_t           proxy_port,
    Socks5UdpSession&  out_session);

bool Socks5UdpSend(
    const Socks5UdpSession& session,
    uint32_t dst_ip,
    uint16_t dst_port,
    const uint8_t* payload,
    size_t payload_len);

int Socks5UdpRecv(
    const Socks5UdpSession& session,
    uint32_t& out_src_ip,
    uint16_t& out_src_port,
    uint8_t*  buf,
    size_t    buf_len);

void Socks5UdpClose(Socks5UdpSession& session);
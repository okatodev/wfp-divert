#define NOMINMAX
#include "embark_bypass.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <iostream>

static std::unordered_set<uint32_t> g_embark_ips;

void ResolveEmbarkIPs() {
    g_embark_ips.clear();

    const std::vector<std::string> domains = {
        "embark.games",
        "id.embark.games",
        "embark-studios.com",
        "es-pio.net",
        "api-gateway.europe.es-pio.net",
        "client2pubsub.europe.es-pio.net"
    };

    for (const auto& domain : domains) {
        addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(domain.c_str(), nullptr, &hints, &res) == 0) {
            for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
                sockaddr_in* ipv4 = (sockaddr_in*)p->ai_addr;
                g_embark_ips.insert(ipv4->sin_addr.s_addr);
                std::cout << "[embark] Resolved " << domain << " to " << inet_ntoa(ipv4->sin_addr) << "\n";
            }
            freeaddrinfo(res);
        } else {
            std::cerr << "[embark] Failed to resolve: " << domain << "\n";
        }
    }
}

bool IsEmbarkIP(uint32_t ip) {
    return g_embark_ips.count(ip) > 0;
}
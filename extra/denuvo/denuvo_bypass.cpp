#define NOMINMAX
#include "denuvo_bypass.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <iostream>

static std::unordered_set<uint32_t> g_denuvo_ips;

void ResolveDenuvoIPs() {
    g_denuvo_ips.clear();
    g_denuvo_ips.insert(inet_addr("46.137.146.164"));
    g_denuvo_ips.insert(inet_addr("18.200.121.106"));
    g_denuvo_ips.insert(inet_addr("13.33.235.92"));
    g_denuvo_ips.insert(inet_addr("18.202.98.236"));

    const std::vector<std::string> domains = {
        "ac-upd.codefusion.technology",
        "ac-trg.codefusion.technology",
        "ac-rep.codefusion.technology",
        "ac-fileshare.codefusion.technology",
        "ac-knock.codefusion.technology",
        "ac-prp-ap.codefusion.technology",
        "ac-survey.codefusion.technology",
        "ac-fallback.codefusion.technology",
        "support.codefusion.technology",
        "srv01.codefusion.technology",
        "srv02.codefusion.technology",
        "srv03.codefusion.technology"
    };

    for (const auto& domain : domains) {
        addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(domain.c_str(), nullptr, &hints, &res) == 0) {
            for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
                sockaddr_in* ipv4 = (sockaddr_in*)p->ai_addr;
                g_denuvo_ips.insert(ipv4->sin_addr.s_addr);
                std::cout << "[denuvo] Resolved " << domain << " to " << inet_ntoa(ipv4->sin_addr) << "\n";
            }
            freeaddrinfo(res);
        } else {
            std::cerr << "[denuvo] Failed to resolve: " << domain << "\n";
        }
    }
}

bool IsDenuvoIP(uint32_t ip) {
    return g_denuvo_ips.count(ip) > 0;
}
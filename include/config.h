#pragma once
#include <string>
#include <unordered_set>
#include <vector>

struct CidrBlock {
    uint32_t base_ip;
    uint32_t mask;
};

struct Config {
    std::string proxy_host = "127.0.0.1";
    uint16_t    proxy_port = 10808;

    std::unordered_set<std::string> apps;
    std::vector<std::string> hostnames;
    std::vector<CidrBlock> ips;
    std::vector<std::string> geoip;

    bool intercept_tcp = true;
    bool intercept_udp = true;

    int udp_session_timeout_sec = 60;
};

bool ParseCidr(const std::string& str, CidrBlock& out);
Config LoadConfig(const std::string& path);
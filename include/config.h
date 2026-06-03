#pragma once
#include <string>
#include <unordered_set>

struct Config {
    std::string proxy_host = "127.0.0.1";
    uint16_t    proxy_port = 10808; // Default v2rayN mixed port

    std::unordered_set<std::string> blacklist;

    bool intercept_tcp = false;
    bool intercept_udp = true;

    int udp_session_timeout_sec = 60;
};

Config LoadConfig(const std::string& path);
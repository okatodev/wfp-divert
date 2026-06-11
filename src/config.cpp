#include "config.h"
#include <fstream>
#include <algorithm>
#include <iostream>
#include <regex>
#include <ws2tcpip.h>

static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

bool ParseCidr(const std::string& str, CidrBlock& out) {
    size_t slash = str.find('/');
    std::string ip_str = (slash == std::string::npos) ? str : str.substr(0, slash);
    int bits = 32;
    if (slash != std::string::npos) {
        try {
            bits = std::stoi(str.substr(slash + 1));
        } catch (...) {
            return false;
        }
    }
    if (bits < 0 || bits > 32) return false;

    in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) return false;

    out.base_ip = ntohl(addr.s_addr);
    out.mask = (bits == 0) ? 0 : (0xFFFFFFFF << (32 - bits));
    return true;
}

Config LoadConfig(const std::string& path) {
    Config cfg;

    std::ifstream f(path);
    if (!f.is_open()) {
        std::cerr << "[config] Config file not found at: " << path << " - using default settings\n";
        return cfg;
    }

    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());

    {
        std::regex re("\"proxy_host\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch m;
        if (std::regex_search(content, m, re))
            cfg.proxy_host = m[1].str();
    }
    {
        std::regex re("\"proxy_port\"\\s*:\\s*(\\d+)");
        std::smatch m;
        if (std::regex_search(content, m, re))
            cfg.proxy_port = static_cast<uint16_t>(std::stoi(m[1].str()));
    }
    {
        std::regex re("\"intercept_tcp\"\\s*:\\s*(true|false)");
        std::smatch m;
        if (std::regex_search(content, m, re))
            cfg.intercept_tcp = (m[1].str() == "true");
    }
    {
        std::regex re("\"intercept_udp\"\\s*:\\s*(true|false)");
        std::smatch m;
        if (std::regex_search(content, m, re))
            cfg.intercept_udp = (m[1].str() == "true");
    }
    {
        std::regex re("\"udp_session_timeout_sec\"\\s*:\\s*(\\d+)");
        std::smatch m;
        if (std::regex_search(content, m, re))
            cfg.udp_session_timeout_sec = std::stoi(m[1].str());
    }
    {
        std::regex re_arr("\"apps\"\\s*:\\s*\\[([^\\]]*)\\]");
        std::smatch m_arr;
        if (std::regex_search(content, m_arr, re_arr)) {
            std::string arr = m_arr[1].str();
            std::regex re_item("\"([^\"]+)\"");
            auto begin = std::sregex_iterator(arr.begin(), arr.end(), re_item);
            auto end   = std::sregex_iterator();
            for (auto it = begin; it != end; ++it)
                cfg.apps.insert(ToLower((*it)[1].str()));
        }
    }
    {
        std::regex re_arr("\"hostnames\"\\s*:\\s*\\[([^\\]]*)\\]");
        std::smatch m_arr;
        if (std::regex_search(content, m_arr, re_arr)) {
            std::string arr = m_arr[1].str();
            std::regex re_item("\"([^\"]+)\"");
            auto begin = std::sregex_iterator(arr.begin(), arr.end(), re_item);
            auto end   = std::sregex_iterator();
            for (auto it = begin; it != end; ++it)
                cfg.hostnames.push_back((*it)[1].str());
        }
    }
    {
        std::regex re_arr("\"ips\"\\s*:\\s*\\[([^\\]]*)\\]");
        std::smatch m_arr;
        if (std::regex_search(content, m_arr, re_arr)) {
            std::string arr = m_arr[1].str();
            std::regex re_item("\"([^\"]+)\"");
            auto begin = std::sregex_iterator(arr.begin(), arr.end(), re_item);
            auto end   = std::sregex_iterator();
            for (auto it = begin; it != end; ++it) {
                CidrBlock block;
                if (ParseCidr((*it)[1].str(), block)) {
                    cfg.ips.push_back(block);
                }
            }
        }
    }
    {
        std::regex re_arr("\"geoip\"\\s*:\\s*\\[([^\\]]*)\\]");
        std::smatch m_arr;
        if (std::regex_search(content, m_arr, re_arr)) {
            std::string arr = m_arr[1].str();
            std::regex re_item("\"([^\"]+)\"");
            auto begin = std::sregex_iterator(arr.begin(), arr.end(), re_item);
            auto end   = std::sregex_iterator();
            for (auto it = begin; it != end; ++it)
                cfg.geoip.push_back(ToLower((*it)[1].str()));
        }
    }

    std::cout << "[config] Settings loaded successfully. Proxy: "
              << cfg.proxy_host << ":" << cfg.proxy_port
              << " | Apps: " << cfg.apps.size() << " | Hostnames: " << cfg.hostnames.size()
              << " | Manual IPs: " << cfg.ips.size() << " | GeoIP Countries: " << cfg.geoip.size() << "\n";

    return cfg;
}
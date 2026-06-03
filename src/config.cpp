#include "config.h"
#include <fstream>
#include <algorithm>
#include <iostream>
#include <regex>

static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
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

    // Regex parsing to avoid external JSON dependency overhead
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
        std::regex re_arr("\"blacklist\"\\s*:\\s*\\[([^\\]]+)\\]");
        std::smatch m_arr;
        if (std::regex_search(content, m_arr, re_arr)) {
            std::string arr = m_arr[1].str();
            std::regex re_item("\"([^\"]+)\"");
            auto begin = std::sregex_iterator(arr.begin(), arr.end(), re_item);
            auto end   = std::sregex_iterator();
            for (auto it = begin; it != end; ++it)
                cfg.blacklist.insert(ToLower((*it)[1].str()));
        }
    }

    std::cout << "[config] Settings loaded successfully. Proxy: "
              << cfg.proxy_host << ":" << cfg.proxy_port
              << " | Blacklist: " << cfg.blacklist.size() << " apps\n";

    for (const auto& app : cfg.blacklist)
        std::cout << "  -> " << app << "\n";

    return cfg;
}
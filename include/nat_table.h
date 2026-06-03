#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <winsock2.h>
struct NatKey {
    uint32_t src_ip;
    uint16_t src_port;

    bool operator==(const NatKey& o) const {
        return src_ip == o.src_ip && src_port == o.src_port;
    }
};

struct NatKeyHash {
    size_t operator()(const NatKey& k) const {
        return std::hash<uint64_t>()(
            (uint64_t)k.src_ip << 16 | k.src_port);
    }
};

struct NatEntry {
    uint32_t orig_dst_ip;
    uint16_t orig_dst_port;
    uint16_t proxy_local_port;
    std::chrono::steady_clock::time_point last_seen;
};

class NatTable {
public:
    NatTable() = default;

    void Insert(NatKey key, NatEntry entry);
    bool Lookup(NatKey key, NatEntry& out);
    void Remove(NatKey key);

    void Expire(int timeout_sec);

private:
    std::unordered_map<NatKey, NatEntry, NatKeyHash> table_;
    std::shared_mutex mutex_;
};

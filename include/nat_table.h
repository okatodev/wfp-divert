#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <winsock2.h>

struct NatKey {
    uint32_t remote_ip;
    uint16_t remote_port;

    bool operator==(const NatKey& o) const {
        return remote_ip == o.remote_ip && remote_port == o.remote_port;
    }
};

struct NatKeyHash {
    size_t operator()(const NatKey& k) const {
        return std::hash<uint64_t>()((uint64_t)k.remote_ip << 16 | k.remote_port);
    }
};

struct NatEntry {
    uint32_t orig_dst_ip;
    uint16_t orig_dst_port;
    uint32_t if_idx;
    uint32_t sub_if_idx;
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
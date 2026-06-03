#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <winsock2.h>

// ── UDP NAT-таблица ──────────────────────────────────────────────────────────
//
// Проблема: UDP не имеет понятия «соединение». Когда игра (cs2.exe) шлёт пакет
// на gameserver:27015, мы перехватываем его и пересылаем через SOCKS5.
// Ответный пакет придёт от прокси-сервера. ОС передаст его в нашу программу,
// а нам нужно понять:
//   «Этот пакет — ответ для cs2.exe, и у игры есть локальный порт 54321»
//
// Ключ таблицы: {локальный IP игры, локальный порт игры}
// Значение: {оригинальный dst IP, оригинальный dst порт, время последней активности}
//
// TCP-соединения ведёт ОС — там NAT-таблица не нужна.

struct NatKey {
    uint32_t src_ip;   // IP приложения (network byte order)
    uint16_t src_port; // порт приложения (network byte order)

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
    uint32_t orig_dst_ip;   // оригинальный адрес назначения
    uint16_t orig_dst_port;
    uint16_t proxy_local_port; // UDP-порт, который нам выдал SOCKS5 (UDP ASSOCIATE)
    std::chrono::steady_clock::time_point last_seen;
};

class NatTable {
public:
    NatTable() = default;

    void Insert(NatKey key, NatEntry entry);
    bool Lookup(NatKey key, NatEntry& out);
    void Remove(NatKey key);

    // Удаляет устаревшие записи. Вызывай периодически из отдельного потока.
    void Expire(int timeout_sec);

private:
    std::unordered_map<NatKey, NatEntry, NatKeyHash> table_;
    std::shared_mutex mutex_;
};

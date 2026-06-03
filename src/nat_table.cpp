#define NOMINMAX
#include "nat_table.h"
#include <iostream>

void NatTable::Insert(NatKey key, NatEntry entry) {
    entry.last_seen = std::chrono::steady_clock::now();
    std::unique_lock<std::shared_mutex> lock(mutex_);
    table_[key] = entry;
}

bool NatTable::Lookup(NatKey key, NatEntry& out) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = table_.find(key);
    if (it == table_.end()) return false;
    out = it->second;
    // Обновляем время последней активности (нужен exclusive lock)
    lock.unlock();
    std::unique_lock<std::shared_mutex> wlock(mutex_);
    auto it2 = table_.find(key);
    if (it2 != table_.end())
        it2->second.last_seen = std::chrono::steady_clock::now();
    return true;
}

void NatTable::Remove(NatKey key) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    table_.erase(key);
}

void NatTable::Expire(int timeout_sec) {
    auto now = std::chrono::steady_clock::now();
    std::unique_lock<std::shared_mutex> lock(mutex_);
    int expired = 0;
    for (auto it = table_.begin(); it != table_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_seen).count();
        if (age > timeout_sec) {
            it = table_.erase(it);
            ++expired;
        } else {
            ++it;
        }
    }
    if (expired > 0)
        std::cout << "[nat] Удалено устаревших UDP-сессий: " << expired << "\n";
}

#define NOMINMAX
#include "process_info.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>

struct CacheEntry {
    std::string name;
    std::string path;
    std::chrono::steady_clock::time_point expires;
};

static std::unordered_map<uint32_t, CacheEntry> g_cache;
static std::shared_mutex                         g_mutex;
static constexpr int CACHE_TTL_SEC = 5;

static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static std::string BaseName(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

static bool QueryProcess(uint32_t pid, std::string& out_path, std::string& out_name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    out_name = ToLower(pe.szExeFile);
                    out_path = out_name;
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    char buf[MAX_PATH] = {};
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameA(hProc, 0, buf, &size)) {
        out_path = ToLower(buf);
        out_name = ToLower(BaseName(out_path));
        CloseHandle(hProc);
        return true;
    }
    CloseHandle(hProc);
    return false;
}

static const CacheEntry* GetCached(uint32_t pid) {
    auto now = std::chrono::steady_clock::now();

    {
        std::shared_lock<std::shared_mutex> rlock(g_mutex);
        auto it = g_cache.find(pid);
        if (it != g_cache.end() && it->second.expires > now)
            return &it->second;
    }

    std::string path, name;
    bool ok = QueryProcess(pid, path, name);

    {
        std::unique_lock<std::shared_mutex> wlock(g_mutex);
        CacheEntry& e = g_cache[pid];
        if (ok) {
            e.path    = path;
            e.name    = name;
            e.expires = now + std::chrono::seconds(CACHE_TTL_SEC);
        } else {
            e.path    = "";
            e.name    = "";
            e.expires = now + std::chrono::seconds(1);
        }
        return &g_cache[pid];
    }
}

std::string GetProcessName(uint32_t pid) {
    return GetCached(pid)->name;
}

std::string GetProcessPath(uint32_t pid) {
    return GetCached(pid)->path;
}
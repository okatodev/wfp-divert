#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <iostream>
#include <string>
#include <filesystem>

#include "config.h"
#include "divert.h"

#pragma comment(lib, "ws2_32.lib")

static bool IsRunAsAdmin() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&authority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin == TRUE;
}

static BOOL WINAPI ConsoleHandler(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT) {
        std::cout << "\n[main] Termination request received. Shutting down...\n";
        StopDivertEngine();
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleA("WFP Divert - Selective SOCKS5 Redirector");

    std::cout << "==========================================\n";
    std::cout << "  WFP Divert v1.0 | UDP Packet Redirector \n";
    std::cout << "==========================================\n\n";

    if (!IsRunAsAdmin()) {
        std::cerr << "[main] ERROR: Administrator privileges required!\n";
        std::cerr << "       WinDivert requires admin access to load the kernel-mode driver.\n";
        MessageBoxA(nullptr,
            "Administrator privileges required!\n\n"
            "WinDivert requires admin access to load the kernel-mode driver.",
            "WFP Divert - Privilege Error", MB_ICONERROR | MB_OK);
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "[main] ERROR: Winsock initialization failed\n";
        return 1;
    }

    std::string config_path;
    if (argc > 1) {
        config_path = argv[1];
    } else {
        char exe_path[MAX_PATH];
        GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
        std::filesystem::path p(exe_path);
        config_path = (p.parent_path() / "config.json").string();
    }

    std::cout << "[main] Loading configuration file: " << config_path << "\n";
    Config cfg = LoadConfig(config_path);

    if (cfg.blacklist.empty()) {
        std::cout << "[main] WARNING: Blacklist is empty. All packet traffic will route directly.\n";
    }

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    std::cout << "\n[main] Starting WinDivert engine (Press Ctrl+C to stop)...\n\n";
    RunDivertEngine(cfg);

    WSACleanup();
    std::cout << "[main] Application exited successfully.\n";
    return 0;
}
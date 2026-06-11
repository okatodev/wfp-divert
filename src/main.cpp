#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <thread>

#include "config.h"
#include "divert.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001
#define ID_TRAY_TOGGLE 1002
#define ID_TRAY_CONFIG 1003
#define ID_TRAY_RELOAD 1004

static DWORD g_main_thread_id = 0;
static std::string g_config_path;
static std::thread g_engine_thread;
static Config g_cfg;
static HWND g_hwnd = nullptr;

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
        PostThreadMessageA(g_main_thread_id, WM_QUIT, 0, 0);
        return TRUE;
    }
    return FALSE;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_TRAYICON) {
        if (lParam == WM_RBUTTONUP) {
            POINT pt;
            GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();

            bool is_visible = IsWindowVisible(GetConsoleWindow());

            AppendMenuA(hMenu, MF_STRING, ID_TRAY_TOGGLE, is_visible ? "Hide Console Logs" : "Show Console Logs");
            AppendMenuA(hMenu, MF_STRING, ID_TRAY_RELOAD, "Reload Config");
            AppendMenuA(hMenu, MF_STRING, ID_TRAY_CONFIG, "Edit Config");
            AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuA(hMenu, MF_STRING, ID_TRAY_EXIT, "Exit");

            SetForegroundWindow(hwnd);

            int selection = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                                           pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(hMenu);

            if (selection == ID_TRAY_TOGGLE) {
                if (is_visible) {
                    ShowWindow(GetConsoleWindow(), SW_HIDE);
                } else {
                    ShowWindow(GetConsoleWindow(), SW_SHOW);
                    SetForegroundWindow(GetConsoleWindow());
                }
            } else if (selection == ID_TRAY_RELOAD) {
                std::cout << "[main] Reloading configuration...\n";
                StopDivertEngine();
                if (g_engine_thread.joinable()) {
                    g_engine_thread.join();
                }
                g_cfg = LoadConfig(g_config_path);
                g_engine_thread = std::thread(RunDivertEngine, g_cfg);
            } else if (selection == ID_TRAY_CONFIG) {
                ShellExecuteA(nullptr, "open", "notepad.exe", "config.json", nullptr, SW_SHOW);
            } else if (selection == ID_TRAY_EXIT) {
                StopDivertEngine();
                PostThreadMessageA(g_main_thread_id, WM_QUIT, 0, 0);
            }
        }
        return 0;
    }
    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

int main(int argc, char* argv[]) {
    g_main_thread_id = GetCurrentThreadId();

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleA("WFP Divert - Selective SOCKS5 Redirector");

    HWND hConsole = GetConsoleWindow();
    if (hConsole) {
        ShowWindow(hConsole, SW_HIDE);

        HMENU hMenu = GetSystemMenu(hConsole, FALSE);
        if (hMenu) {
            EnableMenuItem(hMenu, SC_CLOSE, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
        }
    }

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

    if (argc > 1) {
        g_config_path = argv[1];
    } else {
        char exe_path[MAX_PATH];
        GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
        std::filesystem::path p(exe_path);
        std::filesystem::path cfg_p = p.parent_path() / "config.json";
        std::filesystem::path exp_p = p.parent_path() / "config.example.json";

        if (!std::filesystem::exists(cfg_p) && std::filesystem::exists(exp_p)) {
            std::filesystem::copy_file(exp_p, cfg_p, std::filesystem::copy_options::overwrite_existing);
        }
        g_config_path = cfg_p.string();
    }

    std::cout << "[main] Loading configuration file: " << g_config_path << "\n";
    g_cfg = LoadConfig(g_config_path);

    if (g_cfg.apps.empty()) {
        std::cout << "[main] WARNING: Blacklist is empty. All packet traffic will route directly.\n";
    }

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "WfpDivertTrayClass";
    RegisterClassA(&wc);

    g_hwnd = CreateWindowExA(0, "WfpDivertTrayClass", "WfpDivertTray",
                                0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, GetModuleHandle(nullptr), nullptr);

    if (!g_hwnd) {
        std::cerr << "[main] ERROR: Failed to create hidden message window for system tray\n";
        WSACleanup();
        return 1;
    }

    NOTIFYICONDATAA nid = {};
    nid.cbSize = sizeof(NOTIFYICONDATAA);
    nid.hWnd = g_hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    strcpy_s(nid.szTip, "WFP Divert Proxy");
    Shell_NotifyIconA(NIM_ADD, &nid);

    std::cout << "\n[main] Starting WinDivert engine (Press Ctrl+C to stop)...\n\n";

    g_engine_thread = std::thread(RunDivertEngine, g_cfg);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    Shell_NotifyIconA(NIM_DELETE, &nid);

    StopDivertEngine();
    if (g_engine_thread.joinable()) {
        g_engine_thread.join();
    }

    WSACleanup();
    std::cout << "[main] Application exited successfully.\n";
    return 0;
}
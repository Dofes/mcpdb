#include <windows.h>
#include <iostream>
#include <thread>
#include "api/CompilerPredefine.h"

extern void UninstallBreakpointHook();

extern void InstallBreakpointHook();

// DAP 调试器初始化
extern void initDAPDebugger(int port);


static DWORD WINAPI unloadDLL(LPVOID) {
    UninstallBreakpointHook();
    FreeLibraryAndExitThread((HMODULE)getCurrentModuleHandle(), 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        std::thread([]() {
            while (true) {
                if (GetAsyncKeyState(VK_END) & 0x8000) // 检测 End 键
                {
                    HANDLE hThread = CreateThread(nullptr, 0, unloadDLL, nullptr, 0, nullptr);
                    if (hThread != nullptr) CloseHandle(hThread);
                    break;
                }
                Sleep(100);
            }
        }).detach();

        InstallBreakpointHook();

    }
    return TRUE;
}

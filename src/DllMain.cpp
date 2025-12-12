#include <windows.h>
#include <thread>
#include <mutex>
#include "api/CompilerPredefine.h"
#include "api/InjectorConfig.h"

extern void UninstallBreakpointHook();

extern void InstallBreakpointHook();

extern void initDAPDebugger(int port);
extern void shutdownDAPDebugger();

static mcpdb::SharedConfig& getConfig() {
    static std::once_flag      initFlag;
    static mcpdb::SharedConfig config;

    std::call_once(initFlag, []() { config = mcpdb::ConfigReader::readOrDefault(); });

    return config;
}

int getConfiguredPort() { return getConfig().port; }

static DWORD WINAPI unloadDLL(LPVOID) {
    UninstallBreakpointHook();
    shutdownDAPDebugger();
    FreeLibraryAndExitThread((HMODULE)getCurrentModuleHandle(), 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        std::thread([]() {
            initDAPDebugger(getConfiguredPort());
            // while (true) {
            //     if (GetAsyncKeyState(VK_END) & 0x8000) // 检测 End 键
            //     {
            //         HANDLE hThread = CreateThread(nullptr, 0, unloadDLL, nullptr, 0, nullptr);
            //         if (hThread != nullptr) CloseHandle(hThread);
            //         break;
            //     }
            //     Sleep(100);
            // }
        }).detach();

        InstallBreakpointHook();
    }
    return TRUE;
}

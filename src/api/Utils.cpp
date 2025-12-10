#include "Utils.h"

#include <Windows.h>
#include <dxgi.h>
#include <thread>


#define LOG(...) printf(__VA_ARGS__)

static BOOL CALLBACK enumWindowsCallback(HWND handle, LPARAM lParam) {
    const auto isMainWindow = [handle]() { return GetWindow(handle, GW_OWNER) == nullptr && IsWindowVisible(handle); };

    DWORD pID = 0;
    GetWindowThreadProcessId(handle, &pID);

    if (GetCurrentProcessId() != pID || !isMainWindow() || handle == GetConsoleWindow()) return TRUE;

    *reinterpret_cast<HWND*>(lParam) = handle;

    return FALSE;
}

HWND getProcessWindow() {
    HWND hwnd = nullptr;

    EnumWindows(::enumWindowsCallback, reinterpret_cast<LPARAM>(&hwnd));

    while (!hwnd) {
        EnumWindows(::enumWindowsCallback, reinterpret_cast<LPARAM>(&hwnd));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return hwnd;
}

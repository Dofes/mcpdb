#include "api/thread/GlobalThreadPauser.h"

#include "windows.h"

#include "tlhelp32.h"
#include <stdexcept>
#include <string>

#include <iostream>

namespace thread {
GlobalThreadPauser::GlobalThreadPauser() {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create snapshot: " << GetLastError() << std::endl;
    }
    static auto processId = GetCurrentProcessId();
    auto        threadId  = GetCurrentThreadId();

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(h, &te)) {
        do {
            if (te.dwSize >= offsetof(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) {
                if (te.th32OwnerProcessID == processId && te.th32ThreadID != threadId) {
                    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID);
                    if (thread != nullptr) {
                        if ((int)SuspendThread(thread) != -1) {
                            pausedIds.emplace_back(te.th32ThreadID);
                        }
                        CloseHandle(thread);
                    }
                }
            }
            te.dwSize = sizeof(te);
        } while (Thread32Next(h, &te));
    }
    CloseHandle(h);
}
GlobalThreadPauser::~GlobalThreadPauser() {
    for (auto id : pausedIds) {
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, false, id);
        if (thread != nullptr) {
            ResumeThread(thread);
            CloseHandle(thread);
        }
    }
}

} // namespace thread

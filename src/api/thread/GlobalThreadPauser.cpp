#include "api/thread/GlobalThreadPauser.h"

#include "windows.h"

#include "tlhelp32.h"
#include <stdexcept>
#include <string>
#include <algorithm>

#include <iostream>

namespace thread {

static void pauseThreadsExcept(const std::vector<unsigned int>& exemptIds, std::vector<unsigned int>& pausedIds) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create snapshot: " << GetLastError() << std::endl;
        return;
    }
    static auto processId = GetCurrentProcessId();
    auto        threadId  = GetCurrentThreadId();

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(h, &te)) {
        do {
            if (te.dwSize >= offsetof(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) {
                if (te.th32OwnerProcessID == processId && te.th32ThreadID != threadId) {
                    // 检查是否在豁免列表中
                    bool isExempt = std::find(exemptIds.begin(), exemptIds.end(), te.th32ThreadID) != exemptIds.end();
                    if (!isExempt) {
                        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID);
                        if (thread != nullptr) {
                            if ((int)SuspendThread(thread) != -1) {
                                pausedIds.emplace_back(te.th32ThreadID);
                            }
                            CloseHandle(thread);
                        }
                    }
                }
            }
            te.dwSize = sizeof(te);
        } while (Thread32Next(h, &te));
    }
    CloseHandle(h);
}

GlobalThreadPauser::GlobalThreadPauser() {
    std::vector<unsigned int> exemptIds;
    pauseThreadsExcept(exemptIds, pausedIds);
}

GlobalThreadPauser::GlobalThreadPauser(std::initializer_list<unsigned int> exemptThreadIds)
    : GlobalThreadPauser(std::vector<unsigned int>(exemptThreadIds)) {}

GlobalThreadPauser::GlobalThreadPauser(const std::vector<unsigned int>& exemptThreadIds) {
    pauseThreadsExcept(exemptThreadIds, pausedIds);
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

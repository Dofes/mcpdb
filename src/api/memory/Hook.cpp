#include "Hook.h"

#include <Windows.h>
#include <iostream>
#include <mutex>
#include <set>
#include <unordered_map>

#include "detours/detours.h"

#include "api/thread/GlobalThreadPauser.h"

namespace memory {

FuncPtr resolveIdentifier(char const* identifier) {
    // don't have symbol resolver yet
    return resolveSignature(identifier);
}

struct HookElement {
    FuncPtr      detour{};
    FuncPtr*     originalFunc{};
    HookPriority priority{};
    int          id{};

    bool operator<(const HookElement& other) const {
        if (priority != other.priority) return priority < other.priority;
        return id < other.id;
    }
};

struct HookData {
    FuncPtr               target{};
    FuncPtr               origin{};
    FuncPtr               start{};
    FuncPtr               thunk{};
    int                   hookId{};
    std::set<HookElement> hooks{};

    inline ~HookData() {
        if (this->thunk != nullptr) {
            VirtualFree(this->thunk, 0, MEM_RELEASE);
            this->thunk = nullptr;
        }
    }

    inline void updateCallList() {
        FuncPtr* last = nullptr;
        for (auto& item : this->hooks) {
            if (last == nullptr) {
                this->start = item.detour;
                last        = item.originalFunc;
            } else {
                *last = item.detour;
                last  = item.originalFunc;
            }
        }
        if (last == nullptr) this->start = this->origin;
        else *last = this->origin;
    }

    inline int incrementHookId() { return ++hookId; }
};

std::unordered_map<FuncPtr, std::shared_ptr<HookData>>& getHooks() {
    static std::unordered_map<FuncPtr, std::shared_ptr<HookData>> hooks;
    return hooks;
}

static std::mutex hooksMutex{};

FuncPtr createThunk(FuncPtr* target) {
    constexpr auto THUNK_SIZE            = 18;
    unsigned char  thunkData[THUNK_SIZE] = {0};
    // generate a thunk:
    // mov rax hooker1
    thunkData[0] = 0x48;
    thunkData[1] = 0xB8;
    memcpy(thunkData + 2, &target, sizeof(FuncPtr*));
    // mov rax [rax]
    thunkData[10] = 0x48;
    thunkData[11] = 0x8B;
    thunkData[12] = 0x00;
    // jmp rax
    thunkData[13] = 0xFF;
    thunkData[14] = 0xE0;

    auto thunk = VirtualAlloc(nullptr, THUNK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    memcpy(thunk, thunkData, THUNK_SIZE);
    DWORD dummy;
    VirtualProtect(thunk, THUNK_SIZE, PAGE_EXECUTE_READ, &dummy);
    return thunk;
}

int processHook(FuncPtr target, FuncPtr detour, FuncPtr* originalFunc) {
    FuncPtr tmp = target;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    int rv = DetourAttach(&tmp, detour);
    DetourTransactionCommit();
    *originalFunc = tmp;
    return rv;
}

[[maybe_unused]] int
hook(FuncPtr target, FuncPtr detour, FuncPtr* originalFunc, HookPriority priority, bool suspendThreads) {
    std::lock_guard lock(hooksMutex);

    std::unique_ptr<thread::GlobalThreadPauser> pauser;
    if (suspendThreads) {
        pauser = std::make_unique<thread::GlobalThreadPauser>();
    }
    auto it = getHooks().find(target);
    if (it != getHooks().end()) {
        auto hookData = it->second;
        hookData->hooks.insert({detour, originalFunc, priority, hookData->incrementHookId()});
        hookData->updateCallList();
        return ERROR_SUCCESS;
    }
    auto hookData   = new HookData{target, target, detour, nullptr, {}, {}};
    hookData->thunk = createThunk(&hookData->start);
    hookData->hooks.insert({detour, originalFunc, priority, hookData->incrementHookId()});
    auto ret = processHook(target, hookData->thunk, &hookData->origin);
    if (ret) {
        delete hookData;
        return ret;
    }
    hookData->updateCallList();
    getHooks().emplace(target, std::shared_ptr<HookData>(hookData));
    return ERROR_SUCCESS;
}

[[maybe_unused]] bool unhook(FuncPtr target, FuncPtr detour, bool suspendThreads) {
    std::lock_guard lock(hooksMutex);

    std::unique_ptr<thread::GlobalThreadPauser> pauser;
    if (suspendThreads) {
        pauser = std::make_unique<thread::GlobalThreadPauser>();
    }

    if (target == nullptr) {
        return false;
    }
    auto hookDataIter = getHooks().find(target);
    if (hookDataIter == getHooks().end()) {
        return false;
    }
    auto& hookData = hookDataIter->second;
    for (auto it = hookData->hooks.begin(); it != hookData->hooks.end(); ++it) {
        if (it->detour == detour) {
            hookData->hooks.erase(it);
            hookData->updateCallList();
            break;
        }
    }

    if (hookData->hooks.empty()) {
        FuncPtr tmp = hookData->start;
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&tmp, hookData->thunk);
        DetourTransactionCommit();

        getHooks().erase(target);
    }

    return true;
}

[[maybe_unused]] void unhookAll() {
    std::lock_guard lock(hooksMutex);

    std::unique_ptr<thread::GlobalThreadPauser> pauser;
    pauser = std::make_unique<thread::GlobalThreadPauser>();

    std::vector<std::pair<FuncPtr, std::shared_ptr<HookData>>> hooksCopy(getHooks().begin(), getHooks().end());

    for (auto& [target, hookData] : hooksCopy) {
        FuncPtr tmp = hookData->origin;

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        int detachResult = DetourDetach(&tmp, hookData->thunk);
        int commitResult = DetourTransactionCommit();

        if (detachResult != NO_ERROR || commitResult != NO_ERROR) {
            std::cerr << "Failed to unhook function at: " << target << std::endl;
        }
    }

    getHooks().clear();
}

} // namespace memory

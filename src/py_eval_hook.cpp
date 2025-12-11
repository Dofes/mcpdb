#include "debugger.h"

#include "api/memory/Hook.h"
#include "api/memory/Memory.h"
#include "api/memory/Patch.h"

#define register
#include "py/Python.h" // IWYU pragma: keep

#include "py/code.h" // IWYU pragma: keep
#include "py/frameobject.h"

#include <windows.h>
#include <iostream>

extern void PyEval_EvalFrameEx_eval_opcode_loop();


SKY_AUTO_STATIC_HOOK(
    BedrockLogOutHook,
    HookPriority::Normal,
    "48 89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 55 53 56 57 41 54 41 56 41 57 48 8D AC 24 A0 F0 FF FF B8 60 10 00 00 "
    "E8 ? ? ? ? 48 2B E0 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 50 0F 00 00 48 ",
    void,
    unsigned int priority,
    char const*  pszFormat,
    ...
) {}

bool isStdCout(std::ostream* a1) {
    const void* vtable = *(void**)a1;
    const void* StdCoutVTableAddr =
        *reinterpret_cast<const void**>(const_cast<void*>(reinterpret_cast<const void*>(&std::cout)));
    return vtable == StdCoutVTableAddr;
}

bool CanDereference(void* ptr) { return (ptr != nullptr) && !IsBadReadPtr(ptr, sizeof(void*)); }


std::ostream* getNullStream() {
    static std::ostringstream nullStream; // Create once as a shared "null" stream
    return &nullStream;
}

SKY_AUTO_STATIC_HOOK(
    STDCOUT,
    HookPriority::Normal,
    "48 89 5C 24 10 48 89 74 24 20 48 89 4C 24 08 57 41 54 41 55 41 56 41 57 48 83 EC 30 4C 8B E2 48 ",
    std::ostream*,
    std::ostream* Ostr,
    const char*   Val
) {
    // Check if the stream can be dereferenced
    if (!CanDereference(Ostr)) {
        return origin(Ostr, Val);
    }

    // Check if the stream is std::cout
    if (isStdCout(Ostr)) {
        // Check specific error strings
        if (strstr(Val, "get_rider_cur_health error: player isn't riding")
            || strstr(Val, "entity type str server entity not exists")) {
            return getNullStream(); // Return the null/empty stream instead of modifying std::cout
        }
    }

    // Default behavior: forward to origin
    return origin(Ostr, Val);
}


// 保存原始字节和地址
static uint8_t originalBytes[14]; // 保存被覆盖的原始指令
static void*   hookAddress   = nullptr;
static void*   returnAddress = nullptr;

// 用于跳板的代码 - 需要在可执行内存中
static uint8_t* trampolineCode = nullptr;

void UninstallBreakpointHook() {
    if (!hookAddress || !trampolineCode) {
        std::cout << "Hook not installed!" << std::endl;
        return;
    }

    constexpr size_t HOOK_SIZE = 6; // 改成 6

    DWORD oldProtect;
    VirtualProtect(hookAddress, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(hookAddress, originalBytes, HOOK_SIZE);
    VirtualProtect(hookAddress, HOOK_SIZE, oldProtect, &oldProtect);

    VirtualFree(trampolineCode, 0, MEM_RELEASE);

    std::cout << "Hook uninstalled from: " << hookAddress << std::endl;

    hookAddress    = nullptr;
    returnAddress  = nullptr;
    trampolineCode = nullptr;
}

void InstallBreakpointHook() {
    auto addr = memory::resolveSignature("81 FD FC 00 00 00 0F 87 ? ? 00 00 48 63 C5 41");

    if (!addr) {
        std::cout << "Failed to find signature!" << std::endl;
        return;
    }

    hookAddress = addr;

    trampolineCode  = nullptr;
    auto targetAddr = (uintptr_t)addr;

    for (uintptr_t tryAddr = targetAddr - 0x70000000; tryAddr < targetAddr + 0x70000000; tryAddr += 0x10000) {

        trampolineCode = (uint8_t*)VirtualAlloc((void*)tryAddr, 256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (trampolineCode) {
            int64_t diff = (int64_t)trampolineCode - (int64_t)addr;
            if (diff > INT32_MIN && diff < INT32_MAX) {
                break;
            }
            VirtualFree(trampolineCode, 0, MEM_RELEASE);
            trampolineCode = nullptr;
        }
    }

    if (!trampolineCode) {
        std::cout << "Failed to allocate nearby memory!" << std::endl;
        return;
    }

    constexpr size_t HOOK_SIZE = 6;
    returnAddress              = (void*)((uintptr_t)addr + HOOK_SIZE);

    memcpy(originalBytes, addr, HOOK_SIZE);

    size_t offset = 0;

    trampolineCode[offset++] = 0x9C; // pushfq
    trampolineCode[offset++] = 0x50; // push rax
    trampolineCode[offset++] = 0x51; // push rcx
    trampolineCode[offset++] = 0x52; // push rdx
    trampolineCode[offset++] = 0x53; // push rbx
    trampolineCode[offset++] = 0x56; // push rsi
    trampolineCode[offset++] = 0x57; // push rdi
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x50; // push r8
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x51; // push r9
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x52; // push r10
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x53; // push r11
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x54; // push r12
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x55; // push r13
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x56; // push r14
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x57; // push r15

    trampolineCode[offset++] = 0x55; // push rbp
    trampolineCode[offset++] = 0x48;
    trampolineCode[offset++] = 0x89;
    trampolineCode[offset++] = 0xE5; // mov rbp, rsp
    trampolineCode[offset++] = 0x48;
    trampolineCode[offset++] = 0x83;
    trampolineCode[offset++] = 0xE4;
    trampolineCode[offset++] = 0xF0; // and rsp, -16
    trampolineCode[offset++] = 0x48;
    trampolineCode[offset++] = 0x83;
    trampolineCode[offset++] = 0xEC;
    trampolineCode[offset++] = 0x20; // sub rsp, 0x20

    trampolineCode[offset++]               = 0x48;
    trampolineCode[offset++]               = 0xB8;
    *(uint64_t*)(trampolineCode + offset)  = (uint64_t)&PyEval_EvalFrameEx_eval_opcode_loop;
    offset                                += 8;
    trampolineCode[offset++]               = 0xFF;
    trampolineCode[offset++]               = 0xD0; // call rax

    trampolineCode[offset++] = 0x48;
    trampolineCode[offset++] = 0x89;
    trampolineCode[offset++] = 0xEC; // mov rsp, rbp
    trampolineCode[offset++] = 0x5D; // pop rbp

    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x5F; // pop r15
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x5E; // pop r14
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x5D; // pop r13
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x5C; // pop r12
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x5B; // pop r11
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x5A; // pop r10
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x59; // pop r9
    trampolineCode[offset++] = 0x41;
    trampolineCode[offset++] = 0x58; // pop r8
    trampolineCode[offset++] = 0x5F; // pop rdi
    trampolineCode[offset++] = 0x5E; // pop rsi
    trampolineCode[offset++] = 0x5B; // pop rbx
    trampolineCode[offset++] = 0x5A; // pop rdx
    trampolineCode[offset++] = 0x59; // pop rcx
    trampolineCode[offset++] = 0x58; // pop rax
    trampolineCode[offset++] = 0x9D; // popfq

    // original instructions
    trampolineCode[offset++] = 0x81;
    trampolineCode[offset++] = 0xFD;
    trampolineCode[offset++] = 0xFC;
    trampolineCode[offset++] = 0x00;
    trampolineCode[offset++] = 0x00;
    trampolineCode[offset++] = 0x00;

    trampolineCode[offset++] = 0xE9;
    int32_t relReturn        = (int32_t)((uintptr_t)returnAddress - (uintptr_t)(trampolineCode + offset + 4));
    *(int32_t*)(trampolineCode + offset)  = relReturn;
    offset                               += 4;


    DWORD oldProtect;
    VirtualProtect(addr, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);

    auto* hookPos = (uint8_t*)addr;


    hookPos[0]               = 0xE9;
    auto relJump             = (int32_t)((uintptr_t)trampolineCode - (uintptr_t)(addr)-5);
    *(int32_t*)(hookPos + 1) = relJump;

    hookPos[5] = 0x90;

    VirtualProtect(addr, HOOK_SIZE, oldProtect, &oldProtect);
}


thread_local PyFrameObject* currentFrame  = nullptr;
thread_local bool           isShouldDebug = false;

static bool g_dapInitialized = false;

void initDAPDebugger(int port) {
    if (!g_dapInitialized) {
        g_dapInitialized = true;
        getDebugger().initialize(port);
        std::cout << "[DAP] Debugger initialized on port " << port << std::endl;
    }
}


SKY_AUTO_STATIC_HOOK(
    EvalFrameExHook,
    HookPriority::Normal,
    "40 56 41 57 48 81 EC F8 00 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 D8 00 00 00 48 8B 41 20 8B F2 4C 8B F9 48 "
    "89 4C 24 38 44 8B 80 80 00 00 00 41 8D 80 F1 4D B6 35",
    _object*,
    PyFrameObject* f,
    int            throwflag
) {
    auto ver = *(int*)(((__int64*)f)[4] + 128);
    if (ver != 0xCA49B20F && ver != 0xBC58DBD5) {
        initDAPDebugger(9527);
        isShouldDebug = false;
        currentFrame  = f;

        if (getDebugger().isRunning()) {
            getDebugger().onFrameEnter(f);
            isShouldDebug = getDebugger().hasBreakpointInCurrentFrame();
        }
        auto ori = origin(f, throwflag);
        if (getDebugger().isRunning()) {
            getDebugger().onFrameExit(f);
        }
        currentFrame = nullptr;
        return ori;
    }

    return origin(f, throwflag);
}


void PyEval_EvalFrameEx_eval_opcode_loop() {
    if (!isShouldDebug) return;
    if (!currentFrame) return;

    static thread_local int lastLine = -1;

    int line = PyFrame_GetLineNumber(currentFrame);

    if (line == lastLine) {
        return;
    }
    lastLine = line;

    getDebugger().onLineExecute(currentFrame, line);
}
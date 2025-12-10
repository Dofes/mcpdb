#include "Patch.h"
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>


std::unordered_map<uintptr_t, std::vector<uint16_t>> originalBytesMap;

std::vector<uint16_t> StringToBytes(const std::string& str) {
    std::vector<uint16_t> bytes;
    std::stringstream     ss(str);
    std::string           byteStr;

    while (ss >> byteStr) {
        if (byteStr == "??") {
            bytes.push_back(0xFFFF);
        } else {
            bytes.push_back(static_cast<uint16_t>(std::stoi(byteStr, nullptr, 16)));
        }
    }

    return bytes;
}

void memory::WriteEx(uintptr_t fovAddr, const std::vector<uint16_t>& bytes) {
    DWORD                 oldprotect;
    HANDLE                hProcess = GetCurrentProcess();
    std::vector<uint16_t> originalBytes;

    for (const unsigned short& byte : bytes) {
        if (byte != 0xFFFF) {
            uint16_t originalByte;
            VirtualProtect((LPVOID)fovAddr, 1, PAGE_EXECUTE_READWRITE, &oldprotect);
            ReadProcessMemory(hProcess, (LPVOID)fovAddr, &originalByte, 1, nullptr);
            originalBytes.push_back(originalByte);

            if (!WriteProcessMemory(hProcess, (LPVOID)fovAddr, &byte, 1, nullptr)) {
                std::cerr << "WriteProcessMemory failed. Error: " << GetLastError() << std::endl;
            }
            VirtualProtect((LPVOID)fovAddr, 1, oldprotect, &oldprotect);
        }
        fovAddr++;
    }

    originalBytesMap[fovAddr - bytes.size()] = originalBytes;
}

void memory::WriteEx(memory::FuncPtr fovAddr, const std::vector<uint16_t>& bytes) {
    auto address = reinterpret_cast<uintptr_t>(fovAddr);
    memory::WriteEx(address, bytes);
}

void memory::WriteEx(uintptr_t fovAddr, const std::string& byteStr) {
    std::vector<uint16_t> bytes = StringToBytes(byteStr);
    memory::WriteEx(fovAddr, bytes);
}

void memory::WriteEx(memory::FuncPtr fovAddr, const std::string& byteStr) {
    auto address = reinterpret_cast<uintptr_t>(fovAddr);
    memory::WriteEx(address, byteStr);
}

std::vector<uint8_t> memory::ReadEx(uintptr_t fovAddr, size_t count) {
    std::vector<uint8_t> buffer(count);
    HANDLE               hProcess = GetCurrentProcess();
    DWORD                oldprotect;

    VirtualProtect((LPVOID)fovAddr, count, PAGE_EXECUTE_READWRITE, &oldprotect);
    if (!ReadProcessMemory(hProcess, (LPVOID)fovAddr, buffer.data(), count, nullptr)) {
        std::cerr << "ReadProcessMemory failed. Error: " << GetLastError() << std::endl;
    }
    VirtualProtect((LPVOID)fovAddr, count, oldprotect, &oldprotect);

    return buffer;
}

std::vector<uint8_t> memory::ReadEx(memory::FuncPtr fovAddr, size_t count) {
    auto address = reinterpret_cast<uintptr_t>(fovAddr);
    return ReadEx(address, count);
}

void memory::RevertPatch(memory::FuncPtr fovAddr) { memory::RevertPatch(reinterpret_cast<uintptr_t>(fovAddr)); }

void memory::RevertPatch(uintptr_t fovAddr) {
    DWORD  oldprotect;
    HANDLE hProcess = GetCurrentProcess();

    if (originalBytesMap.find(fovAddr) != originalBytesMap.end()) {
        const std::vector<uint16_t>& originalBytes = originalBytesMap[fovAddr];
        for (size_t i = 0; i < originalBytes.size(); ++i) {
            VirtualProtect((LPVOID)(fovAddr + i), 1, PAGE_EXECUTE_READWRITE, &oldprotect);
            WriteProcessMemory(hProcess, (LPVOID)(fovAddr + i), &originalBytes[i], 1, nullptr);
            VirtualProtect((LPVOID)(fovAddr + i), 1, oldprotect, &oldprotect);
        }
        originalBytesMap.erase(fovAddr);
    } else {
        std::cerr << "No patch found for address: " << std::hex << fovAddr << std::endl;
    }
}

void memory::RevertAllPatches() {
    DWORD  oldprotect;
    HANDLE hProcess = GetCurrentProcess();
    for (const auto& [address, originalBytes] : originalBytesMap) {
        for (size_t i = 0; i < originalBytes.size(); ++i) {
            VirtualProtect((LPVOID)(address + i), 1, PAGE_EXECUTE_READWRITE, &oldprotect);
            WriteProcessMemory(hProcess, (LPVOID)(address + i), &originalBytes[i], 1, nullptr);
            VirtualProtect((LPVOID)(address + i), 1, oldprotect, &oldprotect);
        }
    }
    originalBytesMap.clear();
}
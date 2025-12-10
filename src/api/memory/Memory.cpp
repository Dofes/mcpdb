#include "Memory.h"
#include <iostream>
#include <map>
#include <unordered_map>

#include <chrono>

#define INRANGE(x, a, b) (x >= a && x <= b)
#define GET_BYTE(x)      (GET_BITS(x[0]) << 4 | GET_BITS(x[1]))
#define GET_BITS(x)                                                                                                    \
    (INRANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (INRANGE(x, '0', '9') ? x - '0' : 0))

uintptr_t operator"" _rva(uintptr_t rva) { return rva + reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr)); }

namespace memory {
std::map<uintptr_t, std::vector<unsigned char>> patchedRegions;
std::unordered_map<std::string, uintptr_t>      signatureCache;

uintptr_t getSkyBaseAddress() { return reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr)); }

void ParseSignature(const char* sig, std::vector<unsigned char>& pattern, std::vector<unsigned char>& mask) {
    while (*sig) {
        if (*sig == ' ' || *sig == '\t') {
            ++sig;
            continue;
        }
        if (*sig == '?') {
            pattern.push_back(0);
            mask.push_back(0);
            if (*(sig + 1) == '?') sig += 2;
            else ++sig;
        } else {
            char         byteStr[3] = {sig[0], sig[1], 0};
            unsigned int byteVal    = strtoul(byteStr, nullptr, 16);
            pattern.push_back(static_cast<unsigned char>(byteVal));
            mask.push_back(0xFF);
            sig += 2;
        }
    }
}

struct PatchedInterval {
    uintptr_t                         start;
    uintptr_t                         end;
    const std::vector<unsigned char>* origBytes;
};

struct MemoryRegion {
    uintptr_t base;
    size_t    size;
};

std::vector<MemoryRegion> GetModuleMemoryRegions(uintptr_t rangeStart, uintptr_t rangeEnd) {
    std::vector<MemoryRegion> regions;
    uintptr_t                 addr = rangeStart;
    while (addr < rangeEnd) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
            addr += 0x1000;
            continue;
        }
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD)) {
            MemoryRegion r{};
            r.base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            r.size = mbi.RegionSize;
            regions.push_back(r);
        }
        addr += mbi.RegionSize;
    }
    return regions;
}

unsigned char getPatchedByte(uintptr_t addr, const std::vector<PatchedInterval>& intervals) {
    for (const auto& pi : intervals) {
        if (addr >= pi.start && addr < pi.end) {
            return (*pi.origBytes)[addr - pi.start];
        }
    }
    return *(reinterpret_cast<unsigned char*>(addr));
}

uintptr_t FindSig(const char* szSignature) {
    std::vector<unsigned char> pattern;
    std::vector<unsigned char> mask;
    ParseSignature(szSignature, pattern, mask);
    const size_t patLen = pattern.size();
    if (patLen == 0) return 0;

    bool pure = true;
    for (unsigned char m : mask) {
        if (m != 0xFF) {
            pure = false;
            break;
        }
    }

    static const auto rangeStart = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    static MODULEINFO miModInfo  = {0};
    static bool       init       = false;
    if (!init) {
        init = true;
        GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(rangeStart), &miModInfo, sizeof(miModInfo));
    }
    const uintptr_t rangeEnd = rangeStart + miModInfo.SizeOfImage;

    std::vector<PatchedInterval> patchedIntervals;
    if (!patchedRegions.empty()) {
        for (const auto& p : patchedRegions) {
            PatchedInterval pi{};
            pi.start     = p.first;
            pi.end       = p.first + p.second.size();
            pi.origBytes = &p.second;
            patchedIntervals.push_back(pi);
        }
    }

    std::vector<MemoryRegion> regions = GetModuleMemoryRegions(rangeStart, rangeEnd);
    if (regions.empty()) return 0;

    for (const auto& region : regions) {
        uintptr_t regionEnd = region.base + region.size;
        for (uintptr_t addr = region.base; addr <= regionEnd - patLen; ++addr) {
            bool intersectPatch = false;
            for (const auto& pi : patchedIntervals) {
                if (addr + patLen > pi.start && addr < pi.end) {
                    intersectPatch = true;
                    break;
                }
            }

            if (!intersectPatch) {
                if (pure) {
                    if (memcmp(reinterpret_cast<const void*>(addr), pattern.data(), patLen) == 0) return addr;
                } else {
                    bool match = true;
                    for (size_t k = 0; k < patLen; k++) {
                        unsigned char byteVal = *(reinterpret_cast<unsigned char*>(addr + k));
                        if (mask[k] != 0 && byteVal != pattern[k]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) return addr;
                }
            } else {
                bool match = true;
                for (size_t k = 0; k < patLen; k++) {
                    unsigned char byteVal = getPatchedByte(addr + k, patchedIntervals);
                    if (mask[k] != 0 && byteVal != pattern[k]) {
                        match = false;
                        break;
                    }
                }
                if (match) return addr;
            }
        }
    }
    return 0;
}

void recordPatchedBytes(uintptr_t address, size_t size) {
    if (patchedRegions.find(address) != patchedRegions.end()) return;
    std::vector<unsigned char> originalBytes(size);
    memcpy(originalBytes.data(), reinterpret_cast<void*>(address), size);
    patchedRegions[address] = originalBytes;
}

FuncPtr resolveSignature(const char* signature) {
    auto start = std::chrono::high_resolution_clock::now();
    if (signatureCache.find(signature) != signatureCache.end())
        return reinterpret_cast<FuncPtr>(signatureCache[signature]);

    uintptr_t addr = FindSig(signature);
    auto      end  = std::chrono::high_resolution_clock::now();
    std::cout << "resolveSignature: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
              << "ms" << std::endl;
    std::cout << "Signature: " << signature << " Address: " << std::hex << addr << std::endl;
    if (!addr) return nullptr;
    recordPatchedBytes(addr, 8);
    signatureCache[signature] = addr;
    return reinterpret_cast<FuncPtr>(addr);
}

bool IsReadableMemory(void* ptr, size_t size) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi))) {
        return (mbi.State == MEM_COMMIT)
            && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ));
    }
    return false;
}

void modify(void* ptr, size_t len, const std::function<void()>& callback) {
    DWORD oldProtect;
    // 临时修改内存保护属性为可读写可执行
    if (VirtualProtect(ptr, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // 执行回调函数(在这里可以修改内存)
        callback();
        // 恢复原来的内存保护属性
        DWORD temp;
        VirtualProtect(ptr, len, oldProtect, &temp);
    }
}

} // namespace memory
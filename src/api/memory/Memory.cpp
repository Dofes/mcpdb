#include "Memory.h"
#include <iostream>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <chrono>
#include <intrin.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

#define INRANGE(x, a, b) (x >= a && x <= b)
#define GET_BYTE(x)      (GET_BITS(x[0]) << 4 | GET_BITS(x[1]))
#define GET_BITS(x)                                                                                                    \
    (INRANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (INRANGE(x, '0', '9') ? x - '0' : 0))

uintptr_t operator"" _rva(uintptr_t rva) { return rva + reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr)); }

namespace memory {
std::map<uintptr_t, std::vector<unsigned char>> patchedRegions;
std::unordered_map<std::string, uintptr_t>      signatureCache;

// 持久化缓存相关
static std::string                                cachedModuleHash;
static std::unordered_map<std::string, uintptr_t> persistentCache;
static bool                                       persistentCacheLoaded = false;
static const char*                                CACHE_FILE_NAME       = "sig_cache.dat";

// 计算模块的 SHA256 哈希
std::string ComputeModuleSHA256() {
    HMODULE hModule = GetModuleHandleA(nullptr);
    if (!hModule) return "";

    char modulePath[MAX_PATH];
    if (!GetModuleFileNameA(hModule, modulePath, MAX_PATH)) return "";

    HANDLE hFile =
        CreateFileA(modulePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    HCRYPTPROV  hProv = 0;
    HCRYPTHASH  hHash = 0;
    std::string result;

    if (CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            BYTE  buffer[8192];
            DWORD bytesRead;

            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
                CryptHashData(hHash, buffer, bytesRead, 0);
            }

            BYTE  hash[32];
            DWORD hashLen = 32;
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                std::ostringstream oss;
                for (DWORD i = 0; i < hashLen; i++) {
                    oss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
                }
                result = oss.str();
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(hFile);
    return result;
}

// 获取缓存文件路径 (与模块同目录)
std::string GetCacheFilePath() {
    char modulePath[MAX_PATH];
    if (!GetModuleFileNameA(GetModuleHandleA(nullptr), modulePath, MAX_PATH)) return CACHE_FILE_NAME;

    std::string path(modulePath);
    size_t      pos = path.find_last_of("\\/");
    if (pos != std::string::npos) {
        path = path.substr(0, pos + 1);
    }
    return path + CACHE_FILE_NAME;
}

// 加载持久化缓存
void LoadPersistentCache() {
    if (persistentCacheLoaded) return;
    persistentCacheLoaded = true;

    std::string currentHash = ComputeModuleSHA256();
    if (currentHash.empty()) return;
    cachedModuleHash = currentHash;

    std::ifstream file(GetCacheFilePath(), std::ios::binary);
    if (!file.is_open()) return;

    // 读取存储的哈希
    uint32_t hashLen;
    file.read(reinterpret_cast<char*>(&hashLen), sizeof(hashLen));
    if (hashLen > 256) return; // 安全检查

    std::string storedHash(hashLen, '\0');
    file.read(&storedHash[0], hashLen);

    // 校验哈希
    if (storedHash != currentHash) {
        std::cout << "[SigCache] Module hash mismatch, cache invalidated" << std::endl;
        file.close();
        return;
    }

    // 读取缓存条目数量
    uint32_t entryCount;
    file.read(reinterpret_cast<char*>(&entryCount), sizeof(entryCount));
    if (entryCount > 100000) return; // 安全检查

    // 读取所有条目
    for (uint32_t i = 0; i < entryCount; i++) {
        uint32_t sigLen;
        file.read(reinterpret_cast<char*>(&sigLen), sizeof(sigLen));
        if (sigLen > 4096) break; // 安全检查

        std::string signature(sigLen, '\0');
        file.read(&signature[0], sigLen);

        uintptr_t rva;
        file.read(reinterpret_cast<char*>(&rva), sizeof(rva));

        persistentCache[signature] = rva;
    }

    std::cout << "[SigCache] Loaded " << persistentCache.size() << " cached signatures" << std::endl;
    file.close();
}

// 保存持久化缓存
void SavePersistentCache() {
    if (cachedModuleHash.empty()) return;

    std::ofstream file(GetCacheFilePath(), std::ios::binary | std::ios::trunc);
    if (!file.is_open()) return;

    // 写入哈希
    uint32_t hashLen = static_cast<uint32_t>(cachedModuleHash.size());
    file.write(reinterpret_cast<const char*>(&hashLen), sizeof(hashLen));
    file.write(cachedModuleHash.c_str(), hashLen);

    // 写入条目数量
    uint32_t entryCount = static_cast<uint32_t>(persistentCache.size());
    file.write(reinterpret_cast<const char*>(&entryCount), sizeof(entryCount));

    // 写入所有条目
    for (const auto& [sig, rva] : persistentCache) {
        uint32_t sigLen = static_cast<uint32_t>(sig.size());
        file.write(reinterpret_cast<const char*>(&sigLen), sizeof(sigLen));
        file.write(sig.c_str(), sigLen);
        file.write(reinterpret_cast<const char*>(&rva), sizeof(rva));
    }

    file.close();
}

// 从持久化缓存获取 RVA
bool GetFromPersistentCache(const char* signature, uintptr_t& outAddr) {
    LoadPersistentCache();

    auto it = persistentCache.find(signature);
    if (it != persistentCache.end()) {
        // RVA 转换为实际地址
        outAddr = it->second + getSkyBaseAddress();
        return true;
    }
    return false;
}

// 添加到持久化缓存
void AddToPersistentCache(const char* signature, uintptr_t addr) {
    // 存储 RVA (相对地址)
    uintptr_t rva              = addr - getSkyBaseAddress();
    persistentCache[signature] = rva;
    SavePersistentCache();
}

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

// 查找第一个非通配符字节的位置，用于快速预筛选
int FindFirstNonWildcard(const std::vector<unsigned char>& mask) {
    for (size_t i = 0; i < mask.size(); i++) {
        if (mask[i] == 0xFF) return static_cast<int>(i);
    }
    return -1;
}

// 构建坏字符跳跃表 (Boyer-Moore 变体)
void BuildBadCharTable(
    const std::vector<unsigned char>& pattern,
    const std::vector<unsigned char>& mask,
    size_t                            patLen,
    int                               badChar[256]
) {
    // 默认跳跃整个模式长度
    for (int i = 0; i < 256; i++) {
        badChar[i] = static_cast<int>(patLen);
    }
    // 对于模式中的每个非通配符字节，设置跳跃距离
    for (size_t i = 0; i < patLen - 1; i++) {
        if (mask[i] == 0xFF) {
            badChar[pattern[i]] = static_cast<int>(patLen - 1 - i);
        }
    }
    // 通配符位置允许任意字节
    for (size_t i = 0; i < patLen - 1; i++) {
        if (mask[i] == 0) {
            // 通配符位置，所有字节都可能匹配，设置较小的跳跃
            for (int j = 0; j < 256; j++) {
                if (badChar[j] > static_cast<int>(patLen - 1 - i)) {
                    badChar[j] = static_cast<int>(patLen - 1 - i);
                }
            }
        }
    }
}

// AVX2 加速的纯模式搜索 (无通配符)
uintptr_t FindPurePatternAVX2(const unsigned char* data, size_t dataLen, const unsigned char* pattern, size_t patLen) {
    if (patLen == 0 || dataLen < patLen) return 0;

    const unsigned char firstByte = pattern[0];
    const unsigned char lastByte  = pattern[patLen - 1];
    const __m256i       first     = _mm256_set1_epi8(static_cast<char>(firstByte));
    const __m256i       last      = _mm256_set1_epi8(static_cast<char>(lastByte));

    const size_t alignedLen = (dataLen - patLen + 1) & ~31ULL;

    for (size_t i = 0; i < alignedLen; i += 32) {
        const __m256i blockFirst = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
        const __m256i blockLast  = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + patLen - 1));

        const __m256i eqFirst = _mm256_cmpeq_epi8(first, blockFirst);
        const __m256i eqLast  = _mm256_cmpeq_epi8(last, blockLast);

        uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_and_si256(eqFirst, eqLast)));

        while (mask != 0) {
            unsigned long bitPos;
            _BitScanForward(&bitPos, mask);

            if (memcmp(data + i + bitPos, pattern, patLen) == 0) {
                return reinterpret_cast<uintptr_t>(data + i + bitPos);
            }
            mask &= mask - 1; // 清除最低位的1
        }
    }

    // 处理剩余部分
    for (size_t i = alignedLen; i <= dataLen - patLen; i++) {
        if (memcmp(data + i, pattern, patLen) == 0) {
            return reinterpret_cast<uintptr_t>(data + i);
        }
    }

    return 0;
}

// AVX2 加速的带通配符模式搜索
uintptr_t FindPatternWithMaskAVX2(
    const unsigned char*              data,
    size_t                            dataLen,
    const std::vector<unsigned char>& pattern,
    const std::vector<unsigned char>& mask,
    int                               firstNonWildcard
) {
    const size_t patLen = pattern.size();
    if (patLen == 0 || dataLen < patLen || firstNonWildcard < 0) return 0;

    const unsigned char keyByte = pattern[firstNonWildcard];
    const __m256i       key     = _mm256_set1_epi8(static_cast<char>(keyByte));

    const size_t searchLen  = dataLen - patLen + 1;
    const size_t alignedLen = searchLen & ~31ULL;

    for (size_t i = 0; i < alignedLen; i += 32) {
        const __m256i block = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + firstNonWildcard));
        const __m256i eq    = _mm256_cmpeq_epi8(key, block);

        uint32_t matches = static_cast<uint32_t>(_mm256_movemask_epi8(eq));

        while (matches != 0) {
            unsigned long bitPos;
            _BitScanForward(&bitPos, matches);

            const unsigned char* candidate = data + i + bitPos;
            bool                 found     = true;

            for (size_t k = 0; k < patLen; k++) {
                if (mask[k] != 0 && candidate[k] != pattern[k]) {
                    found = false;
                    break;
                }
            }

            if (found) {
                return reinterpret_cast<uintptr_t>(candidate);
            }
            matches &= matches - 1;
        }
    }

    // 处理剩余部分
    for (size_t i = alignedLen; i < searchLen; i++) {
        const unsigned char* candidate = data + i;
        bool                 found     = true;

        for (size_t k = 0; k < patLen; k++) {
            if (mask[k] != 0 && candidate[k] != pattern[k]) {
                found = false;
                break;
            }
        }

        if (found) {
            return reinterpret_cast<uintptr_t>(candidate);
        }
    }

    return 0;
}

// Boyer-Moore 变体搜索 (用于补丁区域或不支持 AVX2 时的回退)
uintptr_t FindPatternBoyerMoore(
    const unsigned char*              data,
    size_t                            dataLen,
    const std::vector<unsigned char>& pattern,
    const std::vector<unsigned char>& mask,
    const int                         badChar[256]
) {
    const size_t patLen = pattern.size();
    if (patLen == 0 || dataLen < patLen) return 0;

    size_t       i    = 0;
    const size_t maxI = dataLen - patLen;

    while (i <= maxI) {
        bool match = true;

        // 从后向前匹配
        for (int j = static_cast<int>(patLen) - 1; j >= 0; j--) {
            if (mask[j] != 0 && data[i + j] != pattern[j]) {
                match = false;
                // 使用坏字符表计算跳跃距离
                int skip  = badChar[data[i + patLen - 1]];
                i        += (skip > 0) ? skip : 1;
                break;
            }
        }

        if (match) {
            return reinterpret_cast<uintptr_t>(data + i);
        }
    }

    return 0;
}

uintptr_t FindSig(const char* szSignature) {
    std::vector<unsigned char> pattern;
    std::vector<unsigned char> mask;
    ParseSignature(szSignature, pattern, mask);
    const size_t patLen = pattern.size();
    if (patLen == 0) return 0;

    // 检查是否为纯模式 (无通配符)
    bool pure = true;
    for (unsigned char m : mask) {
        if (m != 0xFF) {
            pure = false;
            break;
        }
    }

    // 查找第一个非通配符字节
    int firstNonWildcard = FindFirstNonWildcard(mask);

    // 构建坏字符跳跃表
    int badChar[256];
    BuildBadCharTable(pattern, mask, patLen, badChar);

    static const auto rangeStart = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    static MODULEINFO miModInfo  = {0};
    static bool       init       = false;
    if (!init) {
        init = true;
        GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(rangeStart), &miModInfo, sizeof(miModInfo));
    }
    const uintptr_t rangeEnd = rangeStart + miModInfo.SizeOfImage;

    // 预处理补丁区域
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
        const unsigned char* data    = reinterpret_cast<const unsigned char*>(region.base);
        const size_t         dataLen = region.size;

        // 检查此区域是否与任何补丁区域相交
        bool hasPatches = false;
        for (const auto& pi : patchedIntervals) {
            if (region.base + dataLen > pi.start && region.base < pi.end) {
                hasPatches = true;
                break;
            }
        }

        if (!hasPatches) {
            // 无补丁区域，使用 AVX2 加速搜索
            uintptr_t result;
            if (pure) {
                result = FindPurePatternAVX2(data, dataLen, pattern.data(), patLen);
            } else {
                result = FindPatternWithMaskAVX2(data, dataLen, pattern, mask, firstNonWildcard);
            }
            if (result != 0) return result;
        } else {
            // 有补丁区域，使用逐字节搜索并检查补丁
            for (size_t i = 0; i <= dataLen - patLen; i++) {
                uintptr_t addr = region.base + i;

                bool intersectPatch = false;
                for (const auto& pi : patchedIntervals) {
                    if (addr + patLen > pi.start && addr < pi.end) {
                        intersectPatch = true;
                        break;
                    }
                }

                if (!intersectPatch) {
                    // 不与补丁相交，直接比较
                    bool match = true;
                    for (size_t k = 0; k < patLen; k++) {
                        if (mask[k] != 0 && data[i + k] != pattern[k]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) return addr;
                } else {
                    // 与补丁相交，使用原始字节
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
    // 1. 先检查内存缓存
    if (signatureCache.find(signature) != signatureCache.end())
        return reinterpret_cast<FuncPtr>(signatureCache[signature]);

    // 2. 再检查持久化缓存
    uintptr_t cachedAddr;
    if (GetFromPersistentCache(signature, cachedAddr)) {
        std::cout << "[SigCache] Hit: " << signature << " -> " << std::hex << cachedAddr << std::endl;
        signatureCache[signature] = cachedAddr;
        recordPatchedBytes(cachedAddr, 8);
        return reinterpret_cast<FuncPtr>(cachedAddr);
    }

    // 3. 缓存未命中，执行搜索
    auto      start = std::chrono::high_resolution_clock::now();
    uintptr_t addr  = FindSig(signature);
    auto      end   = std::chrono::high_resolution_clock::now();

    std::cout << "[SigCache] Miss: " << signature << " search took "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << "ms -> " << std::hex
              << addr << std::endl;

    if (!addr) return nullptr;

    // 4. 保存到缓存
    recordPatchedBytes(addr, 8);
    signatureCache[signature] = addr;
    AddToPersistentCache(signature, addr);

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
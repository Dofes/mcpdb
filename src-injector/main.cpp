#include <Windows.h>

#include <TlHelp32.h>

#include <Psapi.h>

#include "api/InjectorConfig.h"

#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>


namespace fs = std::filesystem;

struct HandleDeleter {
    void operator()(HANDLE handle) const {
        if (handle && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};
using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;

LPVOID GetModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName) {
    HMODULE hMods[1024]{};
    DWORD   cbNeeded = 0;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH]{};
            if (GetModuleBaseNameW(hProcess, hMods[i], szModName, MAX_PATH)) {
                if (_wcsicmp(szModName, moduleName) == 0) {
                    return reinterpret_cast<LPVOID>(hMods[i]);
                }
            }
        }
    }
    return nullptr;
}

BOOL PatchZwProtectVirtualMemory(DWORD pid) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        return FALSE;
    }
    FARPROC pZwProtectVirtualMemory = GetProcAddress(hNtdll, "ZwProtectVirtualMemory");
    if (!pZwProtectVirtualMemory) {
        return FALSE;
    }
    BYTE originalBytes[8]{};
    memcpy(originalBytes, reinterpret_cast<void*>(pZwProtectVirtualMemory), sizeof(originalBytes));

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        return FALSE;
    }

    LPVOID ntdllBase = GetModuleBaseAddress(hProcess, L"ntdll.dll");
    if (!ntdllBase) {
        CloseHandle(hProcess);
        return FALSE;
    }

    uintptr_t offset = reinterpret_cast<uintptr_t>(pZwProtectVirtualMemory) - reinterpret_cast<uintptr_t>(hNtdll);
    LPVOID    targetFuncAddr = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(ntdllBase) + offset);

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, targetFuncAddr, sizeof(originalBytes), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, targetFuncAddr, originalBytes, sizeof(originalBytes), &bytesWritten)) {
        VirtualProtectEx(hProcess, targetFuncAddr, sizeof(originalBytes), oldProtect, &oldProtect);
        CloseHandle(hProcess);
        return FALSE;
    }

    VirtualProtectEx(hProcess, targetFuncAddr, sizeof(originalBytes), oldProtect, &oldProtect);
    CloseHandle(hProcess);
    return TRUE;
}

bool isRunningAsAdmin() {
    BOOL isAdmin     = FALSE;
    PSID adminsGroup = nullptr;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &adminsGroup
        )) {
        CheckTokenMembership(nullptr, adminsGroup, &isAdmin);
        FreeSid(adminsGroup);
    }

    return isAdmin == TRUE;
}

void elevateToAdmin() {
    wchar_t szFilePath[MAX_PATH];
    if (GetModuleFileName(nullptr, szFilePath, MAX_PATH)) {
        SHELLEXECUTEINFO sei = {sizeof(sei)};
        sei.fMask            = SEE_MASK_DEFAULT;
        sei.hwnd             = nullptr;
        sei.lpVerb           = L"runas";
        sei.lpFile           = szFilePath;
        sei.nShow            = SW_NORMAL;

        if (!ShellExecuteEx(&sei)) {
            std::cerr << "Failed to elevate: " << GetLastError() << std::endl;
        }
    }
}


static bool TitleContainsMinecraft(HWND hwnd) {
    int len = GetWindowTextLengthW(hwnd);
    if (len <= 0) return false;

    std::wstring title;
    title.resize(static_cast<size_t>(len) + 1);
    int wlen = GetWindowTextW(hwnd, title.data(), len + 1);
    if (wlen <= 0) return false;
    title.resize(static_cast<size_t>(wlen));

    return title.find(L"Minecraft") != std::wstring::npos;
}

static bool ClassIsOGLES(HWND hwnd) {
    wchar_t cls[256]{};
    if (!GetClassNameW(hwnd, cls, 256)) return false;
    return _wcsicmp(cls, L"OGLES") == 0;
}

struct FindState {
    HWND hwnd = nullptr;
};

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    auto* st = reinterpret_cast<FindState*>(lParam);
    if (st->hwnd) return FALSE;
    if (ClassIsOGLES(hwnd) && TitleContainsMinecraft(hwnd)) {
        st->hwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

static HWND FindMinecraftOGLESWindow() {
    FindState st;
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&st));
    return st.hwnd;
}

struct FindStateWithPid {
    HWND  hwnd = nullptr;
    DWORD pid  = 0;
};

static HWND FindMinecraftOGLESWindowByPid(DWORD pid) {
    FindStateWithPid st;
    st.pid = pid;

    EnumWindows(
        [](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* st = reinterpret_cast<FindStateWithPid*>(lParam);
            if (st->hwnd) return FALSE;

            DWORD windowPid = 0;
            GetWindowThreadProcessId(hwnd, &windowPid);

            // 只检查匹配PID的窗口
            if (windowPid != st->pid) {
                return TRUE;
            }

            if (ClassIsOGLES(hwnd) && TitleContainsMinecraft(hwnd)) {
                st->hwnd = hwnd;
                return FALSE;
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&st)
    );
    return st.hwnd;
}

// 检查进程是否为Minecraft（通过可执行文件名判断）
static bool IsMinecraftProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    wchar_t exePath[MAX_PATH]{};
    DWORD   size   = MAX_PATH;
    bool    result = false;

    if (QueryFullProcessImageNameW(hProcess, 0, exePath, &size)) {
        fs::path     p(exePath);
        std::wstring filename = p.filename().wstring();
        // 检查可执行文件名是否为 Minecraft.Windows.exe
        result = (_wcsicmp(filename.c_str(), L"Minecraft.Windows.exe") == 0);
    }

    CloseHandle(hProcess);
    return result;
}

// 获取进程信息结构
struct ProcessInfo {
    DWORD        pid{};
    std::wstring name;
    std::wstring title;
    bool         elevated{};
};

// 检查进程是否以管理员权限运行
static bool IsProcessElevated(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hToken   = nullptr;
    bool   elevated = false;

    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation{};
        DWORD           size = sizeof(elevation);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(hToken);
    }

    CloseHandle(hProcess);
    return elevated;
}

// 获取进程名称
static std::wstring GetProcessName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return L"";

    wchar_t      exePath[MAX_PATH]{};
    DWORD        size = MAX_PATH;
    std::wstring name;

    if (QueryFullProcessImageNameW(hProcess, 0, exePath, &size)) {
        fs::path p(exePath);
        name = p.filename().wstring();
    }

    CloseHandle(hProcess);
    return name;
}

// 枚举所有 Minecraft 进程
static std::vector<ProcessInfo> EnumerateMinecraftProcesses() {
    std::vector<ProcessInfo> processes;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return processes;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (IsMinecraftProcess(pe.th32ProcessID)) {
                ProcessInfo info;
                info.pid  = pe.th32ProcessID;
                info.name = GetProcessName(pe.th32ProcessID);
                if (info.name.empty()) info.name = pe.szExeFile;
                info.elevated = IsProcessElevated(pe.th32ProcessID);

                // 尝试获取窗口标题
                HWND hwnd = FindMinecraftOGLESWindowByPid(pe.th32ProcessID);
                if (hwnd) {
                    int len = GetWindowTextLengthW(hwnd);
                    if (len > 0) {
                        info.title.resize(static_cast<size_t>(len) + 1);
                        int wlen = GetWindowTextW(hwnd, info.title.data(), len + 1);
                        if (wlen > 0) info.title.resize(static_cast<size_t>(wlen));
                        else info.title.clear();
                    }
                }

                processes.push_back(std::move(info));
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return processes;
}

// 转义 JSON 字符串
static std::string EscapeJsonString(const std::wstring& ws) {
    std::string s;
    for (wchar_t wc : ws) {
        if (wc == L'"') s += "\\\"";
        else if (wc == L'\\') s += "\\\\";
        else if (wc == L'\n') s += "\\n";
        else if (wc == L'\r') s += "\\r";
        else if (wc == L'\t') s += "\\t";
        else if (wc < 0x80) s += static_cast<char>(wc);
        else {
            // UTF-8 编码
            if (wc < 0x800) {
                s += static_cast<char>(0xC0 | (wc >> 6));
                s += static_cast<char>(0x80 | (wc & 0x3F));
            } else {
                s += static_cast<char>(0xE0 | (wc >> 12));
                s += static_cast<char>(0x80 | ((wc >> 6) & 0x3F));
                s += static_cast<char>(0x80 | (wc & 0x3F));
            }
        }
    }
    return s;
}

// 输出进程列表为 JSON
static void PrintProcessListJson(const std::vector<ProcessInfo>& processes) {
    std::cout << "{\n  \"processes\": [\n";
    for (size_t i = 0; i < processes.size(); ++i) {
        const auto& p = processes[i];
        std::cout << "    {\n";
        std::cout << "      \"pid\": " << p.pid << ",\n";
        std::cout << "      \"name\": \"" << EscapeJsonString(p.name) << "\",\n";
        std::cout << "      \"title\": \"" << EscapeJsonString(p.title) << "\",\n";
        std::cout << "      \"elevated\": " << (p.elevated ? "true" : "false") << "\n";
        std::cout << "    }" << (i + 1 < processes.size() ? "," : "") << "\n";
    }
    std::cout << "  ]\n}\n";
}

// 命令行参数解析
struct InjectorOptions {
    uint16_t port = 5678;
    DWORD    pid  = 0;
    bool     help = false;
    bool     list = false;

    static InjectorOptions parse(int argc, char* argv[]) {
        InjectorOptions opts;
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "-h" || arg == "--help") {
                opts.help = true;
            } else if (arg == "-l" || arg == "--list") {
                opts.list = true;
            } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
                opts.port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg.starts_with("--port=")) {
                opts.port = static_cast<uint16_t>(std::stoi(arg.substr(7)));
            } else if (arg == "--pid" && i + 1 < argc) {
                opts.pid = static_cast<DWORD>(std::stoul(argv[++i]));
            } else if (arg.starts_with("--pid=")) {
                opts.pid = static_cast<DWORD>(std::stoul(arg.substr(6)));
            }
        }
        return opts;
    }

    static void printUsage() {
        std::cout << "用法: mcdbg [选项]\n"
                  << "选项:\n"
                  << "  -p, --port <端口>  指定DAP调试器端口 (默认: 5678)\n"
                  << "  --pid <进程ID>     指定目标进程ID (不指定则自动搜索)\n"
                  << "  -l, --list         列出所有目标进程 (JSON格式)\n"
                  << "  -h, --help         显示帮助信息\n";
    }
};

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    auto options = InjectorOptions::parse(argc, argv);
    if (options.help) {
        InjectorOptions::printUsage();
        return EXIT_SUCCESS;
    }

    if (options.list) {
        auto processes = EnumerateMinecraftProcesses();
        PrintProcessListJson(processes);
        return EXIT_SUCCESS;
    }

    try {
        // 获取exe所在目录
        wchar_t exePath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        fs::path exeDir = fs::path(exePath).parent_path();

        // 检查 DLL 是否存在（相对于exe路径）
        fs::path dllPath = exeDir / "mcpdb.dll";
        if (!fs::exists(dllPath)) {
            throw std::runtime_error("DLL 文件不存在: " + dllPath.string());
        }
        fs::path fullDLLPath = fs::absolute(dllPath);

        // 获取目标进程 ID
        DWORD processId = 0;
        if (options.pid != 0) {
            // 使用指定的 PID
            processId = options.pid;
            std::cout << "使用指定进程 ID: " << processId << std::endl;

            // 验证进程是否存在
            HANDLE hTest = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
            if (!hTest) {
                throw std::runtime_error("无法打开指定的进程 ID: " + std::to_string(processId));
            }
            CloseHandle(hTest);

            // 检查是否为 Minecraft 进程
            if (IsMinecraftProcess(processId)) {
                std::cout << "检测到 Minecraft 进程，等待窗口初始化...\n";
                HWND hwnd = nullptr;
                while ((hwnd = FindMinecraftOGLESWindowByPid(processId)) == nullptr) {
                    // 检查进程是否仍然存在
                    HANDLE hCheck = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
                    if (!hCheck) {
                        throw std::runtime_error("目标进程已退出");
                    }
                    CloseHandle(hCheck);
                    Sleep(100);
                }
                std::cout << "Minecraft 窗口已就绪\n";
            }
        } else {
            // 自动搜索 Minecraft 窗口
            std::cout << "等待 Minecraft 窗口...\n";
            HWND hwnd = nullptr;
            while ((hwnd = FindMinecraftOGLESWindow()) == nullptr) {
                Sleep(1000);
            }
            GetWindowThreadProcessId(hwnd, &processId);
            if (processId == 0) {
                throw std::runtime_error("无法获取目标进程 ID");
            }
            std::cout << "目标进程 ID: " << processId << std::endl;
        }


        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess) {
            throw std::runtime_error("打开进程失败");
        }
        UniqueHandle processHandle(hProcess);

        // 检查模块状态
        std::wstring dllFileName = fullDLLPath.filename().wstring();
        LPVOID       moduleBase  = GetModuleBaseAddress(processHandle.get(), dllFileName.c_str());
        if (moduleBase != nullptr) {
            std::cout << "调试器已就绪\n";
            return EXIT_SUCCESS;
        }

        // 初始化配置
        mcpdb::SharedConfig config;
        config.port = options.port;

        auto configResult = mcpdb::ConfigWriter::create(processId, config);
        if (!configResult) {
            std::cerr << "警告: 配置同步失败: " << mcpdb::toString(configResult.error()) << std::endl;
            // 继续执行，使用默认端口
        } else {
            std::cout << "调试端口: " << config.port << "\n";
        }

        // 准备运行环境
        if (!PatchZwProtectVirtualMemory(processId)) {
            throw std::runtime_error("环境初始化失败");
        }

        // 准备模块数据
        const std::string dllPathStr = fullDLLPath.string();
        size_t            allocSize  = dllPathStr.size() + 1;
        LPVOID            remoteMemory =
            VirtualAllocEx(processHandle.get(), nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMemory) {
            throw std::runtime_error("内存分配失败");
        }
        if (!WriteProcessMemory(processHandle.get(), remoteMemory, dllPathStr.c_str(), allocSize, nullptr)) {
            VirtualFreeEx(processHandle.get(), remoteMemory, 0, MEM_RELEASE);
            throw std::runtime_error("数据传输失败");
        }

        // 加载调试模块
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) {
            VirtualFreeEx(processHandle.get(), remoteMemory, 0, MEM_RELEASE);
            throw std::runtime_error("系统模块获取失败");
        }
        auto loadLibraryAddr = reinterpret_cast<LPVOID>(GetProcAddress(hKernel32, "LoadLibraryA"));
        if (!loadLibraryAddr) {
            VirtualFreeEx(processHandle.get(), remoteMemory, 0, MEM_RELEASE);
            throw std::runtime_error("入口点定位失败");
        }
        HANDLE hRemoteThread = CreateRemoteThread(
            processHandle.get(),
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr),
            remoteMemory,
            0,
            nullptr
        );
        if (!hRemoteThread) {
            VirtualFreeEx(processHandle.get(), remoteMemory, 0, MEM_RELEASE);
            throw std::runtime_error("模块加载失败");
        }
        UniqueHandle remoteThreadHandle(hRemoteThread);

        WaitForSingleObject(remoteThreadHandle.get(), INFINITE);
        VirtualFreeEx(processHandle.get(), remoteMemory, 0, MEM_RELEASE);

    } catch (const std::exception& e) {

        std::cerr << "错误: " << e.what() << std::endl;
        std::cerr << "按回车键退出..." << std::endl;
        std::cin.get();

        return EXIT_FAILURE;
    }

    std::cout << "调试器初始化完成" << std::endl;
    return EXIT_SUCCESS;
}

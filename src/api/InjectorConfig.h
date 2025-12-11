#pragma once

#include <Windows.h>

#include <nonstd/expected.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace mcpdb {

using nonstd::expected;
using nonstd::unexpected;

#pragma warning(push)
#pragma warning(disable : 4324)
struct alignas(8) SharedConfig {
    static constexpr uint32_t kMagic   = 0x4D435044; // "MCPD"
    static constexpr uint32_t kVersion = 1;

    uint32_t magic   = kMagic;
    uint32_t version = kVersion;
    uint16_t port    = 5678;
    uint16_t flags   = 0;
    uint32_t reserved[4]{};

    [[nodiscard]] bool isValid() const noexcept { return magic == kMagic && version == kVersion; }
};
#pragma warning(pop)

static_assert(sizeof(SharedConfig) == 32, "SharedConfig size must be 32 bytes");

// 错误类型
enum class ConfigError { CreateMappingFailed, OpenMappingFailed, MapViewFailed, InvalidConfig, AlreadyExists };

[[nodiscard]] constexpr std::string_view toString(ConfigError error) noexcept {
    switch (error) {
    case ConfigError::CreateMappingFailed:
        return "Failed to create file mapping";
    case ConfigError::OpenMappingFailed:
        return "Failed to open file mapping";
    case ConfigError::MapViewFailed:
        return "Failed to map view of file";
    case ConfigError::InvalidConfig:
        return "Invalid configuration data";
    case ConfigError::AlreadyExists:
        return "Mapping already exists";
    default:
        return "Unknown error";
    }
}

[[nodiscard]] inline std::wstring makeSharedMemoryName(DWORD processId) {
    return L"Local\\MCPDB_Config_" + std::to_wstring(processId);
}

class SharedMemoryView {
public:
    SharedMemoryView() = default;
    ~SharedMemoryView() { reset(); }

    SharedMemoryView(const SharedMemoryView&)            = delete;
    SharedMemoryView& operator=(const SharedMemoryView&) = delete;

    SharedMemoryView(SharedMemoryView&& other) noexcept : m_handle(other.m_handle), m_view(other.m_view) {
        other.m_handle = nullptr;
        other.m_view   = nullptr;
    }

    SharedMemoryView& operator=(SharedMemoryView&& other) noexcept {
        if (this != &other) {
            reset();
            m_handle       = other.m_handle;
            m_view         = other.m_view;
            other.m_handle = nullptr;
            other.m_view   = nullptr;
        }
        return *this;
    }

    void reset() noexcept {
        if (m_view) {
            UnmapViewOfFile(m_view);
            m_view = nullptr;
        }
        if (m_handle) {
            CloseHandle(m_handle);
            m_handle = nullptr;
        }
    }

    [[nodiscard]] bool                isValid() const noexcept { return m_handle != nullptr && m_view != nullptr; }
    [[nodiscard]] SharedConfig*       data() noexcept { return static_cast<SharedConfig*>(m_view); }
    [[nodiscard]] const SharedConfig* data() const noexcept { return static_cast<const SharedConfig*>(m_view); }

    [[nodiscard]] HANDLE handle() const noexcept { return m_handle; }

private:
    friend class ConfigWriter;
    friend class ConfigReader;

    HANDLE m_handle = nullptr;
    LPVOID m_view   = nullptr;
};

class ConfigWriter {
public:
    [[nodiscard]] static expected<SharedMemoryView, ConfigError>
    create(DWORD targetProcessId, const SharedConfig& config) {
        std::wstring name = makeSharedMemoryName(targetProcessId);

        HANDLE hMapping =
            CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(SharedConfig), name.c_str());

        if (!hMapping) {
            return unexpected(ConfigError::CreateMappingFailed);
        }

        bool alreadyExists = (GetLastError() == ERROR_ALREADY_EXISTS);

        LPVOID pView = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, sizeof(SharedConfig));

        if (!pView) {
            CloseHandle(hMapping);
            return unexpected(ConfigError::MapViewFailed);
        }

        std::memcpy(pView, &config, sizeof(SharedConfig));

        SharedMemoryView view;
        view.m_handle = hMapping;
        view.m_view   = pView;

        if (alreadyExists) {
            view.reset();
            return unexpected(ConfigError::AlreadyExists);
        }

        return view;
    }
};


class ConfigReader {
public:
    [[nodiscard]] static expected<SharedConfig, ConfigError> read(DWORD processId = GetCurrentProcessId()) {
        std::wstring name = makeSharedMemoryName(processId);

        HANDLE hMapping = OpenFileMappingW(FILE_MAP_READ, FALSE, name.c_str());

        if (!hMapping) {
            return unexpected(ConfigError::OpenMappingFailed);
        }

        LPVOID pView = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, sizeof(SharedConfig));

        if (!pView) {
            CloseHandle(hMapping);
            return unexpected(ConfigError::MapViewFailed);
        }

        SharedConfig config;
        std::memcpy(&config, pView, sizeof(SharedConfig));

        UnmapViewOfFile(pView);
        CloseHandle(hMapping);

        if (!config.isValid()) {
            return unexpected(ConfigError::InvalidConfig);
        }

        return config;
    }

    [[nodiscard]] static SharedConfig readOrDefault(DWORD processId = GetCurrentProcessId()) {
        auto result = read(processId);
        if (result) {
            return *result;
        }
        return SharedConfig{};
    }
};

} // namespace mcpdb

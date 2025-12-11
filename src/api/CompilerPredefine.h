#include <Windows.h>

extern "C" ::_IMAGE_DOS_HEADER __ImageBase; // NOLINT(bugprone-reserved-identifier)

[[nodiscard]] void* getCurrentModuleHandle() noexcept { return &__ImageBase; }
#pragma once
#pragma warning(error : 4834)

#define VA_EXPAND(...) __VA_ARGS__

#ifdef AURORA_EXPORT
#define AURORAAPI [[maybe_unused]] __declspec(dllexport)
#else
#define AURORAAPI [[maybe_unused]] __declspec(dllimport)
#endif
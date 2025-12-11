#include "memory.h"
#include <sstream>
#include <string>

namespace memory {
void WriteEx(uintptr_t fovAddr, const std::vector<uint16_t>& bytes);
void WriteEx(memory::FuncPtr fovAddr, const std::vector<uint16_t>& bytes);
void WriteEx(uintptr_t fovAddr, const std::string& byteStr);
void WriteEx(memory::FuncPtr fovAddr, const std::string& byteStr);

std::vector<uint8_t> ReadEx(uintptr_t fovAddr, size_t count);
std::vector<uint8_t> ReadEx(memory::FuncPtr fovAddr, size_t count);

void RevertPatch(uintptr_t fovAddr);
void RevertPatch(memory::FuncPtr fovAddr);
void RevertAllPatches();
} // namespace memory
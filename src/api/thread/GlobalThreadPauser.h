#pragma once

#include <vector>

namespace thread {
class GlobalThreadPauser {
    std::vector<unsigned int> pausedIds;

public:
    GlobalThreadPauser();
    ~GlobalThreadPauser();
};
} // namespace thread

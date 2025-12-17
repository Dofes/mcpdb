#pragma once

#include <vector>
#include <initializer_list>

namespace thread {
class GlobalThreadPauser {
    std::vector<unsigned int> pausedIds;

public:
    // 默认只豁免当前线程
    GlobalThreadPauser();
    // 豁免当前线程和指定的线程ID列表
    explicit GlobalThreadPauser(std::initializer_list<unsigned int> exemptThreadIds);
    explicit GlobalThreadPauser(const std::vector<unsigned int>& exemptThreadIds);
    ~GlobalThreadPauser();
};
} // namespace thread

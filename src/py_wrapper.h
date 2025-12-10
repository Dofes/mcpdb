#pragma once


#include <string>

// 使用 void* 作为不透明句柄，避免暴露 Python 类型
using PyHandle      = void*;
using PyFrameHandle = void*;
using PyCodeHandle  = void*;

namespace py {

// ============== 初始化 ==============

// 初始化类型缓存（可选，首次使用时会自动初始化）
void initTypeCache();

// ============== 引用计数管理 ==============

void incref(PyHandle obj);
void decref(PyHandle obj);
void xdecref(PyHandle obj);

// ============== RAII 包装器 ==============

class ObjectGuard {
public:
    explicit ObjectGuard(PyHandle obj = nullptr, bool incref = false);
    ~ObjectGuard();

    ObjectGuard(ObjectGuard&& other) noexcept;
    ObjectGuard& operator=(ObjectGuard&& other) noexcept;

    ObjectGuard(const ObjectGuard&)            = delete;
    ObjectGuard& operator=(const ObjectGuard&) = delete;

    PyHandle get() const;
    PyHandle release();
    explicit operator bool() const;

private:
    PyHandle obj_;
};

// ============== 类型检查 ==============

bool isNone(PyHandle obj);
bool isString(PyHandle obj);
bool isUnicode(PyHandle obj);
bool isInt(PyHandle obj);
bool isLong(PyHandle obj);
bool isFloat(PyHandle obj);
bool isBool(PyHandle obj);
bool isDict(PyHandle obj);
bool isList(PyHandle obj);
bool isTuple(PyHandle obj);
bool isModule(PyHandle obj);

// ============== 字符串操作 ==============

std::string asString(PyHandle obj);
std::string toString(PyHandle obj); // PyObject_Repr
std::string getTypeName(PyHandle obj);

// ============== 对象属性 ==============

bool     hasAttr(PyHandle obj, const char* name);
PyHandle getAttr(PyHandle obj, PyHandle name);
PyHandle getAttrString(PyHandle obj, const char* name);
PyHandle dir(PyHandle obj);

// ============== 字典操作 ==============

PyHandle dictGetItemString(PyHandle dict, const char* key);
bool     dictNext(PyHandle dict, long long* pos, PyHandle* key, PyHandle* value);

// ============== 列表操作 ==============

long long listSize(PyHandle list);
PyHandle  listGetItem(PyHandle list, long long index);

// ============== 元组操作 ==============

long long tupleSize(PyHandle tuple);
PyHandle  tupleGetItem(PyHandle tuple, long long index);

// ============== 模块操作 ==============

PyHandle moduleGetDict(PyHandle module);

// ============== 帧操作 ==============

struct FrameInfo {
    std::string   funcName;
    std::string   filename;
    int           lineNumber = 0;
    PyHandle      locals     = nullptr;
    PyHandle      globals    = nullptr;
    PyHandle      code       = nullptr;
    PyFrameHandle back       = nullptr;
};

FrameInfo     getFrameInfo(PyFrameHandle frame);
int           getFrameLineNumber(PyFrameHandle frame);
void          frameToLocals(PyFrameHandle frame);
PyFrameHandle getFrameBack(PyFrameHandle frame);

// ============== 代码执行 ==============

PyHandle compile(const char* source, const char* filename, int startType);
PyHandle evalCode(PyCodeHandle code, PyHandle globals, PyHandle locals);
void     clearError();

// ============== 编译模式常量 ==============

int getEvalInputMode();

// ============== 高级工具函数 ==============

// 判断对象是否可展开（用于变量查看）
bool isExpandable(PyHandle obj);

// 获取对象的字符串表示，带长度限制
std::string getRepr(PyHandle obj, size_t maxLen = 200);

// 安全获取字符串
std::string getString(PyHandle obj);

// ============== 帧深度计算 ==============

int calculateFrameDepth(PyFrameHandle frame);

} // namespace py

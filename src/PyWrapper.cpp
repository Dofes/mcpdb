#include "PyWrapper.h"
#define register
#include "py/Python.h"
#undef register
#include "py/frameobject.h"

// 类型转换宏
#define PY(x)     reinterpret_cast<PyObject*>(x)
#define FRAME(x)  reinterpret_cast<PyFrameObject*>(x)
#define CODE(x)   reinterpret_cast<PyCodeObject*>(x)
#define HANDLE(x) reinterpret_cast<PyHandle>(x)

namespace py {

// ============== GIL 管理 ==============

GILGuard::GILGuard() : state_(PyGILState_Ensure()) {}

GILGuard::~GILGuard() { PyGILState_Release(static_cast<PyGILState_STATE>(state_)); }

// ============== 动态类型获取==============

struct TypeCache {
    PyTypeObject* boolType       = nullptr;
    PyTypeObject* floatType      = nullptr;
    PyTypeObject* moduleType     = nullptr;
    PyTypeObject* setType        = nullptr;
    PyTypeObject* frozensetType  = nullptr;
    PyTypeObject* baseObjectType = nullptr;
    PyObject*     noneObj        = nullptr;
    bool          inited         = false;

    void ensureInit() {
        if (inited) return;

        // 通过创建对象获取类型
        // PyBool_FromLong 创建 False/True, 取其 ob_type
        // 同时通过 tp_base 链获取 PyBaseObject_Type
        PyObject* boolObj = PyBool_FromLong(0);
        if (boolObj) {
            boolType = Py_TYPE(boolObj);
            // bool -> int -> object, 所以 tp_base->tp_base 就是 object
            if (boolType->tp_base && boolType->tp_base->tp_base) {
                baseObjectType = boolType->tp_base->tp_base;
            }
            Py_DECREF(boolObj);
        }

        // PyFloat_FromDouble 创建 float, 取其 ob_type
        PyObject* floatObj = PyFloat_FromDouble(0.0);
        if (floatObj) {
            floatType = Py_TYPE(floatObj);
            // 备选: 如果上面没获取到, float->object 只需一层
            if (!baseObjectType && floatType->tp_base) {
                baseObjectType = floatType->tp_base;
            }
            Py_DECREF(floatObj);
        }

        // PyImport_AddModule 返回一个 module, 取其 ob_type
        // 注意: AddModule 返回借用引用，不需要 decref
        PyObject* moduleObj = PyImport_AddModule("__main__");
        if (moduleObj) {
            moduleType = Py_TYPE(moduleObj);
        }

        // 通过 builtins 获取 set 和 frozenset 类型
        PyObject* builtins = PyImport_AddModule("__builtin__");
        if (builtins) {
            PyObject* builtinsDict = PyModule_GetDict(builtins);
            if (builtinsDict) {
                PyObject* setTypeObj = PyDict_GetItemString(builtinsDict, "set");
                if (setTypeObj && PyType_Check(setTypeObj)) {
                    setType = reinterpret_cast<PyTypeObject*>(setTypeObj);
                }
                PyObject* frozensetTypeObj = PyDict_GetItemString(builtinsDict, "frozenset");
                if (frozensetTypeObj && PyType_Check(frozensetTypeObj)) {
                    frozensetType = reinterpret_cast<PyTypeObject*>(frozensetTypeObj);
                }
            }
        }

        // 通过 Py_BuildValue("") 获取 None
        // 返回新引用，但我们要永久持有它
        noneObj = Py_BuildValue("");

        inited = true;
    }
};

static TypeCache& g_typeCache() {
    static TypeCache cache;
    return cache;
}

// 动态获取 None 对象
PyObject* getDynNone() {
    g_typeCache().ensureInit();
    return g_typeCache().noneObj;
}

PyTypeObject* getDynBaseObjectType() {
    g_typeCache().ensureInit();
    return g_typeCache().baseObjectType;
}

// 动态类型检查函数
static bool dynBoolCheck(PyObject* op) {
    g_typeCache().ensureInit();
    return g_typeCache().boolType && Py_TYPE(op) == g_typeCache().boolType;
}

static bool dynFloatCheck(PyObject* op) {
    g_typeCache().ensureInit();
    if (!g_typeCache().floatType) return false;
    return Py_TYPE(op) == g_typeCache().floatType || PyType_IsSubtype(Py_TYPE(op), g_typeCache().floatType);
}

static bool dynModuleCheck(PyObject* op) {
    g_typeCache().ensureInit();
    if (!g_typeCache().moduleType) return false;
    return Py_TYPE(op) == g_typeCache().moduleType || PyType_IsSubtype(Py_TYPE(op), g_typeCache().moduleType);
}

static bool dynSetCheck(PyObject* op) {
    g_typeCache().ensureInit();
    auto& cache = g_typeCache();
    if (!cache.setType && !cache.frozensetType) return false;
    PyTypeObject* t = Py_TYPE(op);
    return (cache.setType && (t == cache.setType || PyType_IsSubtype(t, cache.setType)))
        || (cache.frozensetType && (t == cache.frozensetType || PyType_IsSubtype(t, cache.frozensetType)));
}

void initTypeCache() { g_typeCache().ensureInit(); }

// ============== 引用计数管理 ==============

void incref(PyHandle obj) {
    if (obj) Py_INCREF(PY(obj));
}

void decref(PyHandle obj) {
    if (obj) Py_DECREF(PY(obj));
}

void xdecref(PyHandle obj) { Py_XDECREF(PY(obj)); }

// ============== RAII 包装器 ==============

ObjectGuard::ObjectGuard(PyHandle obj, bool incref) : obj_(obj) {
    if (obj_ && incref) {
        Py_INCREF(PY(obj_));
    }
}

ObjectGuard::~ObjectGuard() { Py_XDECREF(PY(obj_)); }

ObjectGuard::ObjectGuard(ObjectGuard&& other) noexcept : obj_(other.obj_) { other.obj_ = nullptr; }

ObjectGuard& ObjectGuard::operator=(ObjectGuard&& other) noexcept {
    if (this != &other) {
        Py_XDECREF(PY(obj_));
        obj_       = other.obj_;
        other.obj_ = nullptr;
    }
    return *this;
}

PyHandle ObjectGuard::get() const { return obj_; }

PyHandle ObjectGuard::release() {
    PyHandle tmp = obj_;
    obj_         = nullptr;
    return tmp;
}

ObjectGuard::operator bool() const { return obj_ != nullptr; }

// ============== 类型检查 ==============

bool isNone(PyHandle obj) { return PY(obj) == getDynNone(); }
bool isString(PyHandle obj) { return obj && PyString_Check(PY(obj)); }
bool isUnicode(PyHandle obj) { return obj && PyUnicode_Check(PY(obj)); }
bool isInt(PyHandle obj) { return obj && PyInt_Check(PY(obj)); }
bool isLong(PyHandle obj) { return obj && PyLong_Check(PY(obj)); }
bool isFloat(PyHandle obj) { return obj && dynFloatCheck(PY(obj)); }
bool isBool(PyHandle obj) { return obj && dynBoolCheck(PY(obj)); }
bool isDict(PyHandle obj) { return obj && PyDict_Check(PY(obj)); }
bool isList(PyHandle obj) { return obj && PyList_Check(PY(obj)); }
bool isTuple(PyHandle obj) { return obj && PyTuple_Check(PY(obj)); }
bool isSet(PyHandle obj) { return obj && dynSetCheck(PY(obj)); }
bool isModule(PyHandle obj) { return obj && dynModuleCheck(PY(obj)); }
bool isType(PyHandle obj) { return obj && PyType_Check(PY(obj)); }

// ============== 字符串操作 ==============

std::string asString(PyHandle obj) {
    if (!obj) return "";
    if (PyString_Check(PY(obj))) {
        const char* str = PyString_AsString(PY(obj));
        return str ? str : "";
    }
    return "";
}

std::string toString(PyHandle obj) {
    if (!obj) return "<null>";

    PyObject* repr = PyObject_Repr(PY(obj));
    if (!repr) {
        PyErr_Clear();
        return "<error>";
    }

    std::string result;
    if (PyString_Check(repr)) {
        const char* str = PyString_AsString(repr);
        result          = str ? str : "<error>";
    }
    Py_DECREF(repr);
    return result;
}

std::string getTypeName(PyHandle obj) {
    if (!obj) return "NoneType";
    return PY(obj)->ob_type->tp_name;
}

// ============== 对象属性 ==============

bool hasAttr(PyHandle obj, const char* name) { return obj && PyObject_HasAttrString(PY(obj), name); }

PyHandle getAttr(PyHandle obj, PyHandle name) {
    if (!obj || !name) return nullptr;
    return HANDLE(PyObject_GetAttr(PY(obj), PY(name)));
}

PyHandle getAttrString(PyHandle obj, const char* name) {
    if (!obj || !name) return nullptr;
    return HANDLE(PyObject_GetAttrString(PY(obj), name));
}

PyHandle dir(PyHandle obj) {
    if (!obj) return nullptr;
    return HANDLE(PyObject_Dir(PY(obj)));
}

// ============== 字典操作 ==============

PyHandle dictGetItemString(PyHandle dict, const char* key) {
    if (!dict || !key || !PyDict_Check(PY(dict))) return nullptr;
    return HANDLE(PyDict_GetItemString(PY(dict), key));
}

bool dictNext(PyHandle dict, long long* pos, PyHandle* key, PyHandle* value) {
    if (!dict || !PyDict_Check(PY(dict))) return false;
    Py_ssize_t pyPos   = static_cast<Py_ssize_t>(*pos);
    PyObject*  pyKey   = nullptr;
    PyObject*  pyValue = nullptr;
    bool       result  = PyDict_Next(PY(dict), &pyPos, &pyKey, &pyValue) != 0;
    *pos               = static_cast<long long>(pyPos);
    *key               = HANDLE(pyKey);
    *value             = HANDLE(pyValue);
    return result;
}

// ============== 列表操作 ==============

long long listSize(PyHandle list) {
    if (!list || !PyList_Check(PY(list))) return 0;
    return static_cast<long long>(PyList_Size(PY(list)));
}

PyHandle listGetItem(PyHandle list, long long index) {
    if (!list || !PyList_Check(PY(list))) return nullptr;
    return HANDLE(PyList_GetItem(PY(list), static_cast<Py_ssize_t>(index)));
}

// ============== 元组操作 ==============

long long tupleSize(PyHandle tuple) {
    if (!tuple || !PyTuple_Check(PY(tuple))) return 0;
    return static_cast<long long>(PyTuple_Size(PY(tuple)));
}

PyHandle tupleGetItem(PyHandle tuple, long long index) {
    if (!tuple || !PyTuple_Check(PY(tuple))) return nullptr;
    return HANDLE(PyTuple_GetItem(PY(tuple), static_cast<Py_ssize_t>(index)));
}

// ============== Set 操作 ==============

long long setSize(PyHandle set) {
    if (!set || !dynSetCheck(PY(set))) return 0;
    return static_cast<long long>(reinterpret_cast<PySetObject*>(set)->used);
}

bool setNext(PyHandle set, long long* pos, PyHandle* key) {
    if (!set || !dynSetCheck(PY(set)) || !pos || !key) return false;

    PySetObject* so    = reinterpret_cast<PySetObject*>(set);
    Py_ssize_t   i     = static_cast<Py_ssize_t>(*pos);
    setentry*    table = so->table;
    Py_ssize_t   mask  = so->mask;

    while (i <= mask && (table[i].key == nullptr || table[i].key == reinterpret_cast<PyObject*>(-1))) {
        i++;
    }

    *pos = static_cast<long long>(i + 1);

    if (i > mask) {
        return false;
    }

    *key = HANDLE(table[i].key);
    return true;
}

// ============== 模块操作 ==============

PyHandle moduleGetDict(PyHandle module) {
    if (!module || !dynModuleCheck(PY(module))) return nullptr;
    return HANDLE(PyModule_GetDict(PY(module)));
}

PyHandle importAddModule(const char* name) {
    if (!name) return nullptr;
    return HANDLE(PyImport_AddModule(name));
}

PyHandle importModule(const char* name) {
    if (!name) return nullptr;
    return HANDLE(PyImport_ImportModule(name));
}

// ============== 帧操作 ==============

FrameInfo getFrameInfo(PyFrameHandle frame) {
    FrameInfo      info{};
    PyFrameObject* f = FRAME(frame);
    if (!f) return info;

    if (f->f_code) {
        if (PyString_Check(f->f_code->co_name)) {
            const char* str = PyString_AsString(f->f_code->co_name);
            info.funcName   = str ? str : "";
        }
        if (PyString_Check(f->f_code->co_filename)) {
            const char* str = PyString_AsString(f->f_code->co_filename);
            info.filename   = str ? str : "";
        }
        info.code = HANDLE(f->f_code);
    }

    info.lineNumber = PyFrame_GetLineNumber(f);
    info.locals     = HANDLE(f->f_locals);
    info.globals    = HANDLE(f->f_globals);
    info.back       = HANDLE(f->f_back);

    return info;
}

int getFrameLineNumber(PyFrameHandle frame) {
    PyFrameObject* f = FRAME(frame);
    if (!f) return 0;
    return PyFrame_GetLineNumber(f);
}

void frameToLocals(PyFrameHandle frame) {
    PyFrameObject* f = FRAME(frame);
    if (f) {
        PyFrame_FastToLocals(f);
    }
}

void localsToFast(PyFrameHandle frame) {
    PyFrameObject* f = FRAME(frame);
    if (f) {
        PyFrame_LocalsToFast(f, 0);
    }
}

PyFrameHandle getFrameBack(PyFrameHandle frame) {
    PyFrameObject* f = FRAME(frame);
    if (!f) return nullptr;
    return HANDLE(f->f_back);
}

// ============== 字典操作 ==============

int dictSetItemString(PyHandle dict, const char* key, PyHandle value) {
    if (!dict || !key || !value) return -1;
    return PyDict_SetItemString(PY(dict), key, PY(value));
}

void dictDelItemString(PyHandle dict, const char* key) {
    if (!dict || !key) return;
    PyDict_DelItemString(PY(dict), key);
    PyErr_Clear(); // 忽略 key 不存在的错误
}

// ============== 代码执行 ==============

PyHandle compile(const char* source, const char* filename, int startType) {
    if (!source || !filename) return nullptr;
    return HANDLE(Py_CompileString(source, filename, startType));
}

PyHandle evalCode(PyCodeHandle code, PyHandle globals, PyHandle locals) {
    if (!code) return nullptr;
    return HANDLE(PyEval_EvalCode(CODE(code), PY(globals), PY(locals)));
}

void clearError() { PyErr_Clear(); }

int getEvalInputMode() { return Py_eval_input; }
int getSingleInputMode() { return Py_single_input; }

// 辅助函数：格式化 Python 异常为字符串
static std::string formatPythonException() {
    std::string result;

    PyObject* ptype      = nullptr;
    PyObject* pvalue     = nullptr;
    PyObject* ptraceback = nullptr;
    PyErr_Fetch(&ptype, &pvalue, &ptraceback);

    if (!ptype && !pvalue) {
        return "Unknown error";
    }

    PyErr_NormalizeException(&ptype, &pvalue, &ptraceback);

    // 尝试使用 traceback.format_exception 获取完整的错误信息
    // 使用 PyImport_AddModule 避免重新导入可能导致的问题（返回借用引用）
    PyObject* tbModule         = PyImport_AddModule("traceback");
    bool      needDecrefModule = false;

    if (!tbModule) {
        // 如果 traceback 还没被导入，尝试导入它（返回新引用）
        PyErr_Clear();
        tbModule         = PyImport_ImportModule("traceback");
        needDecrefModule = (tbModule != nullptr);
    }

    if (tbModule) {
        PyObject* formatFunc = PyObject_GetAttrString(tbModule, "format_exception");
        if (formatFunc) {
            PyObject* args = PyTuple_Pack(
                3,
                ptype ? ptype : getDynNone(),
                pvalue ? pvalue : getDynNone(),
                ptraceback ? ptraceback : getDynNone()
            );
            if (args) {
                PyObject* tbList = PyObject_CallObject(formatFunc, args);
                if (tbList && PyList_Check(tbList)) {
                    Py_ssize_t size = PyList_Size(tbList);
                    for (Py_ssize_t i = 0; i < size; i++) {
                        PyObject* line = PyList_GetItem(tbList, i);
                        if (line) {
                            result += getString(HANDLE(line));
                        }
                    }
                }
                PyErr_Clear(); // 清除可能的错误
                if (tbList) Py_DECREF(tbList);
                Py_DECREF(args);
            }
            Py_DECREF(formatFunc);
        } else {
            PyErr_Clear();
        }
        if (needDecrefModule) {
            Py_DECREF(tbModule);
        }
    } else {
        PyErr_Clear();
    }

    // 如果 traceback 模块失败，回退到简单的错误信息
    if (result.empty() && pvalue) {
        PyObject* str = PyObject_Str(pvalue);
        if (str) {
            result = getString(HANDLE(str));
            Py_DECREF(str);
        } else {
            PyErr_Clear();
            result = "Error occurred";
        }
    }

    if (ptype) Py_DECREF(ptype);
    if (pvalue) Py_DECREF(pvalue);
    if (ptraceback) Py_XDECREF(ptraceback);

    // 移除尾部换行
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }

    return result;
}

// 辅助函数：捕获 stdout/stderr 并执行代码，返回执行结果和错误状态
static REPLResult execWithCapture(PyObject* code, PyHandle globals, PyHandle locals) {
    REPLResult result;
    result.isError      = false;
    result.resultObject = nullptr;

    // 获取 sys 模块
    PyObject* sysModule = PyImport_AddModule("sys");
    if (!sysModule) {
        PyErr_Clear();
        PyObject* evalResult = PyEval_EvalCode(CODE(code), PY(globals), PY(locals));
        if (evalResult) {
            Py_DECREF(evalResult);
        } else {
            result.output  = formatPythonException();
            result.isError = true;
            PyErr_Clear();
        }
        return result;
    }

    // 保存原始 stdout/stderr
    PyObject* oldStdout = PyObject_GetAttrString(sysModule, "stdout");
    PyObject* oldStderr = PyObject_GetAttrString(sysModule, "stderr");

    // 尝试创建 StringIO (兼容 Python 2 和 3)
    PyObject* stringIO = nullptr;

    // Python 2: from StringIO import StringIO
    // Python 3: from io import StringIO
    // 但由于嵌入式 Python 可能是 2.x，先尝试 cStringIO（更快），再 StringIO，最后 io
    PyObject* ioModule = PyImport_ImportModule("cStringIO");
    if (ioModule) {
        // cStringIO.StringIO 是一个工厂函数，直接调用
        PyObject* stringIOFunc = PyObject_GetAttrString(ioModule, "StringIO");
        if (stringIOFunc) {
            stringIO = PyObject_CallObject(stringIOFunc, nullptr);
            Py_DECREF(stringIOFunc);
        }
        Py_DECREF(ioModule);
    }

    if (!stringIO) {
        PyErr_Clear();
        ioModule = PyImport_ImportModule("StringIO");
        if (ioModule) {
            // Python 2 的 StringIO.StringIO
            PyObject* stringIOClass = PyObject_GetAttrString(ioModule, "StringIO");
            if (stringIOClass) {
                stringIO = PyObject_CallObject(stringIOClass, nullptr);
                Py_DECREF(stringIOClass);
            }
            Py_DECREF(ioModule);
        }
    }

    if (!stringIO) {
        PyErr_Clear();
        ioModule = PyImport_ImportModule("io");
        if (ioModule) {
            // Python 3 的 io.StringIO
            PyObject* stringIOClass = PyObject_GetAttrString(ioModule, "StringIO");
            if (stringIOClass) {
                stringIO = PyObject_CallObject(stringIOClass, nullptr);
                Py_DECREF(stringIOClass);
            }
            Py_DECREF(ioModule);
        }
    }

    if (!stringIO) {
        PyErr_Clear();
    }

    // 重定向 stdout/stderr
    if (stringIO) {
        PyObject_SetAttrString(sysModule, "stdout", stringIO);
        PyObject_SetAttrString(sysModule, "stderr", stringIO);
    }

    // 执行代码
    bool      execFailed = false;
    PyObject* ptype      = nullptr;
    PyObject* pvalue     = nullptr;
    PyObject* ptraceback = nullptr;

    PyObject* evalResult = PyEval_EvalCode(CODE(code), PY(globals), PY(locals));

    if (evalResult) {
        Py_DECREF(evalResult);
    } else {
        execFailed     = true;
        result.isError = true;
        // 立即保存异常信息，防止后续操作清除它
        PyErr_Fetch(&ptype, &pvalue, &ptraceback);
    }

    // 获取捕获的输出（仅成功时）
    if (stringIO && !execFailed) {
        PyObject* getvalue = PyObject_GetAttrString(stringIO, "getvalue");
        if (getvalue) {
            PyObject* output = PyObject_CallObject(getvalue, nullptr);
            if (output) {
                result.output = getString(HANDLE(output));
                Py_DECREF(output);
            }
            Py_DECREF(getvalue);
        }
    }

    // 恢复 stdout/stderr
    if (stringIO) {
        if (oldStdout) {
            PyObject_SetAttrString(sysModule, "stdout", oldStdout);
        }
        if (oldStderr) {
            PyObject_SetAttrString(sysModule, "stderr", oldStderr);
        }
        Py_DECREF(stringIO);
    }

    if (oldStdout) Py_DECREF(oldStdout);
    if (oldStderr) Py_DECREF(oldStderr);

    // 在恢复 stdout/stderr 之后格式化异常
    if (execFailed) {
        // 恢复异常状态，然后格式化
        PyErr_Restore(ptype, pvalue, ptraceback);
        result.output = formatPythonException();
    }

    // 移除尾部换行
    while (!result.output.empty() && (result.output.back() == '\n' || result.output.back() == '\r')) {
        result.output.pop_back();
    }

    return result;
}

// 执行 REPL 代码，返回结果字符串或捕获的输出
REPLResult execREPL(const char* source, PyHandle globals, PyHandle locals) {
    REPLResult result;
    result.isError      = false;
    result.resultObject = nullptr;

    // 首先尝试作为表达式编译
    PyObject* code = Py_CompileString(source, "<repl>", Py_eval_input);
    if (code) {
        // 成功编译为表达式，执行并获取结果
        PyObject* evalResult = PyEval_EvalCode(CODE(code), PY(globals), PY(locals));
        Py_DECREF(code);

        if (evalResult) {
            // 如果结果不是 None，返回其 repr 并保留对象引用
            if (evalResult != getDynNone()) {
                result.output       = getRepr(HANDLE(evalResult), 10000);
                result.resultType   = getTypeName(HANDLE(evalResult));
                result.resultObject = HANDLE(evalResult); // 保留引用，由调用者负责 decref
            } else {
                Py_DECREF(evalResult);
            }
        } else {
            // 执行出错，获取完整的错误信息
            result.output  = formatPythonException();
            result.isError = true;
        }
        return result;
    }

    // 表达式编译失败，清除错误，尝试作为语句编译
    PyErr_Clear();

    code = Py_CompileString(source, "<repl>", Py_single_input);
    if (code) {
        // 语句可能有 print 输出，需要捕获
        result = execWithCapture(code, globals, locals);
        Py_DECREF(code);
    } else {
        // 语句也编译失败，获取完整的错误信息
        result.output  = formatPythonException();
        result.isError = true;
    }

    return result;
}

// ============== 自动补全 ==============

std::vector<std::string> getCompletions(PyHandle obj, const std::string& prefix) {
    std::vector<std::string> completions;

    PyObject* dirList = PyObject_Dir(PY(obj));
    if (!dirList) {
        PyErr_Clear();
        return completions;
    }

    if (PyList_Check(dirList)) {
        Py_ssize_t size = PyList_Size(dirList);
        for (Py_ssize_t i = 0; i < size; i++) {
            PyObject* item = PyList_GetItem(dirList, i);
            if (item) {
                std::string name = getString(HANDLE(item));
                if (prefix.empty() || name.find(prefix) == 0) {
                    completions.push_back(name);
                }
            }
        }
    }

    Py_DECREF(dirList);
    return completions;
}

std::vector<std::string> getDictKeys(PyHandle dict) {
    std::vector<std::string> keys;

    if (!dict || !PyDict_Check(PY(dict))) {
        return keys;
    }

    Py_ssize_t pos   = 0;
    PyObject*  key   = nullptr;
    PyObject*  value = nullptr;

    while (PyDict_Next(PY(dict), &pos, &key, &value)) {
        if (key) {
            std::string keyStr = getString(HANDLE(key));
            if (!keyStr.empty()) {
                keys.push_back(keyStr);
            }
        }
    }

    return keys;
}

// ============== 高级工具函数 ==============

bool isExpandable(PyHandle obj) {
    if (!obj) return false;
    PyObject* o = PY(obj);

    // 基本容器类型
    if (PyDict_Check(o) || PyList_Check(o) || PyTuple_Check(o) || dynSetCheck(o) || dynModuleCheck(o)) {
        return true;
    }

    // 有 __dict__ 属性的对象
    if (PyObject_HasAttrString(o, "__dict__")) {
        return true;
    }

    // 排除基本类型
    if (PyInt_Check(o) || PyLong_Check(o) || dynFloatCheck(o) || PyString_Check(o) || PyUnicode_Check(o)
        || dynBoolCheck(o) || o == getDynNone()) {
        return false;
    }

    return true;
}

std::string getRepr(PyHandle obj, size_t maxLen) {
    if (!obj) return "<null>";

    PyObject* repr = PyObject_Repr(PY(obj));
    if (!repr) {
        PyErr_Clear();
        return "<error>";
    }

    std::string result;
    if (PyString_Check(repr)) {
        const char* str = PyString_AsString(repr);
        result          = str ? str : "<error>";
    }
    Py_DECREF(repr);

    if (result.length() > maxLen) {
        result = result.substr(0, maxLen) + "...";
    }
    return result;
}

std::string getString(PyHandle obj) {
    if (!obj) return "";
    PyObject* o = PY(obj);

    if (PyString_Check(o)) {
        const char* str = PyString_AsString(o);
        return str ? str : "";
    }

    if (PyUnicode_Check(o)) {
        PyObject* encoded = PyUnicode_AsUTF8String(o);
        if (encoded) {
            const char* str    = PyString_AsString(encoded);
            std::string result = str ? str : "";
            Py_DECREF(encoded);
            return result;
        }
    }

    return "";
}

// ============== 帧深度计算 ==============

int calculateFrameDepth(PyFrameHandle frame) {
    int            depth = 0;
    PyFrameObject* f     = FRAME(frame);
    while (f) {
        depth++;
        f = f->f_back;
    }
    return depth;
}

} // namespace py

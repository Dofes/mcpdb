#include "py_wrapper.h"
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

// ============== 动态类型获取（避免直接引用全局变量）==============

// 缓存结构，延迟初始化
struct TypeCache {
    PyTypeObject* boolType       = nullptr;
    PyTypeObject* floatType      = nullptr;
    PyTypeObject* moduleType     = nullptr;
    PyTypeObject* baseObjectType = nullptr;
    PyObject*     noneObj        = nullptr;
    bool          inited         = false;

    void ensureInit() {
        if (inited) return;

        // 通过创建对象获取类型 - 这些函数容易找特征码
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
    // 模拟 PyObject_TypeCheck: 直接比较或子类检查
    return Py_TYPE(op) == g_typeCache().floatType || PyType_IsSubtype(Py_TYPE(op), g_typeCache().floatType);
}

static bool dynModuleCheck(PyObject* op) {
    g_typeCache().ensureInit();
    if (!g_typeCache().moduleType) return false;
    return Py_TYPE(op) == g_typeCache().moduleType || PyType_IsSubtype(Py_TYPE(op), g_typeCache().moduleType);
}

// 初始化类型缓存（可选，可在程序启动时调用）
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
bool isModule(PyHandle obj) { return obj && dynModuleCheck(PY(obj)); }

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

// ============== 模块操作 ==============

PyHandle moduleGetDict(PyHandle module) {
    if (!module || !dynModuleCheck(PY(module))) return nullptr;
    return HANDLE(PyModule_GetDict(PY(module)));
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

PyFrameHandle getFrameBack(PyFrameHandle frame) {
    PyFrameObject* f = FRAME(frame);
    if (!f) return nullptr;
    return HANDLE(f->f_back);
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

// ============== 高级工具函数 ==============

bool isExpandable(PyHandle obj) {
    if (!obj) return false;
    PyObject* o = PY(obj);

    // 基本容器类型
    if (PyDict_Check(o) || PyList_Check(o) || PyTuple_Check(o) || dynModuleCheck(o)) {
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

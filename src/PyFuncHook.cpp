#include "api/memory/Memory.h"

#define register
#include "py/Python.h" // IWYU pragma: keep
#include "py/frameobject.h"

#include <vector>
#include <iostream>
#include <ostream>
#include <fstream>

// clang-format off
#define PYFUNC_SIGNATURE_TABLE(PYFUNC) \
    PYFUNC(PyObject_GetAttrString,        "40 57 48 83 EC 20 48 8B 41 08 48 8B F9 4C 8B 40") \
    PYFUNC(PyObject_HasAttrString,        "48 83 EC 28 E8 47 FF FF FF 48 85 C0 74 1A 48 83") \
    PYFUNC(PyObject_GetAttr,              "48 89 5C 24 08 57 48 83 EC 20 4C 8B 42 08 48 8B F9 48 8B 59 08 48 8B C2") \
    PYFUNC(PyObject_Dir,                  "40 53 48 83 EC 20 48 85 C9 75 7F E8 C0 65 04 00") \
    PYFUNC(PyUnicodeUCS2_AsUTF8String,    "48 83 EC 28 48 8B 41 08 F7 80 A8 00 00 00 00 00 00 10 75 0C E8 B7 65 FE FF") \
    PYFUNC(PyBool_FromLong,               "48 8B 15 ? ? ? ? 4C 8D 05 ? ? ? ? 85 C9") \
    PYFUNC(PyFloat_FromDouble,            "48 83 EC 38 48 8B 15 ? ? ? ? 0F 29 74 24 20") \
    PYFUNC(PyList_GetItem,                "48 83 EC 28 48 8B 41 08 F7 80 A8 00 00 00 00 00 00 02 75 18 BA B6 00 00") \
    PYFUNC(PyDict_GetItemString,          "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B CA E8 FB 2B FF FF 48 8B D8") \
    PYFUNC(PyErr_Clear,                   "48 89 5C 24 08 57 48 83 EC 20 48 8B 05 ? ? ? ? 33 D2 48 8B 48 48") \
    PYFUNC(Py_BuildValue,                 "48 89 4C 24 08 48 89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 8D 54 24 38 45 33 C0") \
    PYFUNC(Py_CompileStringFlags,         "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 30 49 8B D9 41 8B E8") \
    PYFUNC(PyImport_AddModule,            "40 57 48 83 EC 20 E8 ? ? ? ? 48 8B F8 48 85 C0 75 ? 48 83 C4 20 5F C3 48 8B 05 ? ? ? ?") \
    PYFUNC(PyEval_EvalCodeEx,             "48 89 4C 24 08 41 54 41 55 41 57 48 81 EC 90 00 00 00") \
    PYFUNC(PyModule_GetDict,              "40 53 48 83 EC 20 48 8B D9 48 8D 15 ? ? ? ? 48 8B 49 08 48 3B CA 74 20 E8 ? ? ? ? 85 C0") \
    PYFUNC(PyFrame_GetLineNumber,         "48 83 79 50 00 74 04 8B 41 7C C3 8B 51 78 48 8B") \
    PYFUNC(PyFrame_FastToLocals,          "48 85 C9 0F 84 E5 01 00 00 53 48 83 EC 70 48 8B") \
    PYFUNC(PyObject_Repr,                 "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 E8 ? ? ? ? 85 C0 0F 85 ? ? ? ? 48 85 DB 75 ? 48 8D 0D ? ? ? ?") \
    PYFUNC(PyString_AsString,             "48 83 EC 28 4C 8B 41 08 41 8B 80 A8 00 00 00 0F BA E0 1B 72 39 0F BA E0") \
    PYFUNC(PyEval_SetTrace,               "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B 1D ? ? ? ? 45 33 C0 48 8B F1") \
    PYFUNC(PyGILState_Ensure,             "48 89 5C 24 10 57 48 83 EC 20 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B D8 48 85 C0 75 33") \
    PYFUNC(PyGILState_Release,            "48 89 5C 24 08 57 48 83 EC 20 8B F9 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B D8") \
    PYFUNC(PyEval_SaveThread,             "40 53 48 83 EC 20 33 C9 E8 ? ? ? ? 48 8B D8") \
    PYFUNC(PyEval_RestoreThread,          "40 57 48 83 EC 20 48 8B F9 48 85 C9 75 0C") \
    PYFUNC(PyFrame_LocalsToFast,          "48 85 C9 0F 84 2E 02 00 00 4C 8B DC 53 41 56") \
    PYFUNC(PyDict_SetItemString,          "48 89 5C 24 20 57 48 83 EC 30 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 28 48 8B D9 49 8B F8 48 8B CA") \
    PYFUNC(PyDict_DelItemString,          "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B CA E8 ? ? ? ? 48 8B D8 48 85 C0 75 0E") \
    PYFUNC(PyImport_ImportModule,         "48 83 EC 28 E8 ? ? ? ? 48 89 44 24 38") \
    PYFUNC(PyEval_CallObjectWithKeywords, "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F8 48 8B DA 48 8B F1 48 85 D2 75 11") \
    PYFUNC(PyObject_SetAttrString,        "40 55 56 48 83 EC 48 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 38 48 8B 41 08") \
    PYFUNC(PyObject_Str,                  "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 85 C9 75 0E 48 8D 0D ? ? ? ? E8 ? ? ? ? EB 36") \
    PYFUNC(PyErr_Fetch,                   "4C 8B 0D ? ? ? ? 49 8B 41 48 48 89 01 49 8B 41 50") \
    PYFUNC(PyErr_NormalizeException,      "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 41 54 41 56 41 57 48 83 EC 20 48 8B 39") \
    PYFUNC(PyTuple_New,                   "40 53 48 83 EC 20 48 8B D9 48 85 C9 79 19 BA 36 00 00 00 48 8D 0D ? ? ? ? E8 ? ? ? ? 33 C0") \
    PYFUNC(PyErr_Restore,                 "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 20 48 8B 35 ? ? ? ? 48 8B EA 4C 8B F1 4D 85 C0 74 1F 49 8B 40 08")
// clang-format on

#define GET_SIGNATURE(name, sig) sig
#define PYFUNC_GET_SIG(name)     GET_SIGNATURE_##name

#define DEFINE_SIG_CONSTANT(name, sig) inline constexpr const char* SIG_##name = sig;

PYFUNC_SIGNATURE_TABLE(DEFINE_SIG_CONSTANT)

#define RESOLVE_CACHED(name)                                                                                           \
    static auto funcptr = memory::resolveSignature(SIG_##name);                                                        \
    static bool logged  = false;                                                                                       \
    if (!logged) {                                                                                                     \
        std::cout << "[PyHook] " #name " funcptr = " << funcptr << std::endl;                                          \
        logged = true;                                                                                                 \
    }

namespace py {
extern PyTypeObject* getDynBaseObjectType();
}
int PyType_IsSubtype(_typeobject* a, _typeobject* b) {
    _object*      tp_mro;
    __int64       ob_refcnt;
    __int64       v5;
    _typeobject** i;

    if ((a->tp_flags & 0x100) != 0) {
        tp_mro = a->tp_mro;
        if (tp_mro) {
            ob_refcnt = tp_mro[1].ob_refcnt;
            v5        = 0;
            if (ob_refcnt <= 0) return 0;
            for (i = &tp_mro[1].ob_type; *i != b; ++i) {
                if (++v5 >= ob_refcnt) return 0;
            }
        } else {
            while (a != b) {
                a = a->tp_base;
                if (!a) return b == py::getDynBaseObjectType();
            }
        }
    } else if (b != a && b != py::getDynBaseObjectType()) {
        return 0;
    }
    return 1;
}

PyObject* PyObject_GetAttrString(PyObject* a, const char* b) {
    RESOLVE_CACHED(PyObject_GetAttrString)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*, const char*);
        return reinterpret_cast<FuncType>(funcptr)(a, b);
    }
    return nullptr;
}

int PyObject_HasAttrString(PyObject* a, const char* b) {
    RESOLVE_CACHED(PyObject_HasAttrString)
    if (funcptr) {
        using FuncType = int(__fastcall*)(PyObject*, const char*);
        return reinterpret_cast<FuncType>(funcptr)(a, b);
    }
    return 0;
}

PyObject* PyObject_GetAttr(PyObject* a, PyObject* b) {
    RESOLVE_CACHED(PyObject_GetAttr)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*, PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(a, b);
    }
    return nullptr;
}

PyObject* PyObject_Dir(PyObject* a) {
    RESOLVE_CACHED(PyObject_Dir)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(a);
    }
    return nullptr;
}

PyObject* PyUnicodeUCS2_AsUTF8String(_object* unicode) {
    RESOLVE_CACHED(PyUnicodeUCS2_AsUTF8String)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(_object*);
        return reinterpret_cast<FuncType>(funcptr)(unicode);
    }
    return nullptr;
}

PyObject* PyBool_FromLong(long v) {
    RESOLVE_CACHED(PyBool_FromLong)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(long);
        return reinterpret_cast<FuncType>(funcptr)(v);
    }
    return nullptr;
}

PyObject* PyFloat_FromDouble(double v) {
    RESOLVE_CACHED(PyFloat_FromDouble)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(double);
        return reinterpret_cast<FuncType>(funcptr)(v);
    }
    return nullptr;
}

Py_ssize_t PyTuple_Size(PyObject* op) {
    if ((op->ob_type->tp_flags & 0x4000000) != 0) return op[1].ob_refcnt;
    return -1;
}

PyObject* PyTuple_GetItem(_object* op, __int64 i) {
    if ((op->ob_type->tp_flags & 0x4000000) != 0) {
        if (i < 0 || i >= op[1].ob_refcnt) {
            return nullptr;
        } else {
            return (_object*)*((__int64*)&op[1].ob_type + i);
        }
    } else {
        return nullptr;
    }
}

__int64 __fastcall PyList_Size(_object* op) {
    if ((op->ob_type->tp_flags & 0x2000000) != 0) return op[1].ob_refcnt;
    return -1;
}

PyObject* PyList_GetItem(PyObject* a, Py_ssize_t b) {
    RESOLVE_CACHED(PyList_GetItem)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*, Py_ssize_t);
        return reinterpret_cast<FuncType>(funcptr)(a, b);
    }
    return nullptr;
}

PyObject* PyDict_GetItemString(PyObject* dp, const char* key) {
    RESOLVE_CACHED(PyDict_GetItemString)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*, const char*);
        return reinterpret_cast<FuncType>(funcptr)(dp, key);
    }
    return nullptr;
}

void PyErr_Clear(void) {
    RESOLVE_CACHED(PyErr_Clear)
    if (funcptr) {
        using FuncType = void(__fastcall*)();
        reinterpret_cast<FuncType>(funcptr)();
    }
}

PyObject* Py_BuildValue(const char* format, ...) {
    RESOLVE_CACHED(Py_BuildValue)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(const char*, ...);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        va_list  args;
        va_start(args, format);
        PyObject* result = func(format, args);
        va_end(args);
        return result;
    }
    return nullptr;
}

PyObject* Py_CompileStringFlags(const char* a, const char* b, int c, PyCompilerFlags* d) {
    RESOLVE_CACHED(Py_CompileStringFlags)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(const char*, const char*, int, PyCompilerFlags*);
        return reinterpret_cast<FuncType>(funcptr)(a, b, c, d);
    }
    return nullptr;
}

PyObject* PyImport_AddModule(const char* name) {
    RESOLVE_CACHED(PyImport_AddModule)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(const char*);
        return reinterpret_cast<FuncType>(funcptr)(name);
    }
    return nullptr;
}

PyObject* PyEval_EvalCodeEx(
    PyCodeObject* co,
    PyObject*     globals,
    PyObject*     locals,
    PyObject**    args,
    int           argc,
    PyObject**    kwds,
    int           kwdc,
    PyObject**    defs,
    int           defc,
    PyObject*     closure
) {
    RESOLVE_CACHED(PyEval_EvalCodeEx)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyCodeObject*,
                                                PyObject*,
                                                PyObject*,
                                                PyObject**,
                                                int,
                                                PyObject**,
                                                int,
                                                PyObject**,
                                                int,
                                                PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(co, globals, locals, args, argc, kwds, kwdc, defs, defc, closure);
    }
    return nullptr;
}


PyObject* PyEval_EvalCode(PyCodeObject* a, PyObject* b, PyObject* c) {
    return PyEval_EvalCodeEx(a, b, c, nullptr, 0, nullptr, 0, nullptr, 0, nullptr);
}

PyObject* PyModule_GetDict(PyObject* module) {
    RESOLVE_CACHED(PyModule_GetDict)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(module);
    }
    return nullptr;
}

int PyFrame_GetLineNumber(PyFrameObject* f) {
    RESOLVE_CACHED(PyFrame_GetLineNumber)
    if (funcptr) {
        using FuncType = int(__fastcall*)(PyFrameObject*);
        return reinterpret_cast<FuncType>(funcptr)(f);
    }
    return -1;
}

void PyFrame_FastToLocals(PyFrameObject* f) {
    RESOLVE_CACHED(PyFrame_FastToLocals)
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyFrameObject*);
        reinterpret_cast<FuncType>(funcptr)(f);
    }
}

int PyDict_Next(PyObject* mp, Py_ssize_t* pos, PyObject** key, PyObject** value) {
    register Py_ssize_t   i;
    register Py_ssize_t   mask;
    register PyDictEntry* ep;

    if (!PyDict_Check(mp)) return 0;
    i = *pos;
    if (i < 0) return 0;
    ep   = ((PyDictObject*)mp)->ma_table;
    mask = ((PyDictObject*)mp)->ma_mask;
    while (i <= mask && ep[i].me_value == nullptr) i++;
    *pos = i + 1;
    if (i > mask) return 0;
    if (key) *key = ep[i].me_key;
    if (value) *value = ep[i].me_value;
    return 1;
}

PyObject* PyObject_Repr(PyObject* o) {
    RESOLVE_CACHED(PyObject_Repr)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(o);
    }
    return nullptr;
}

char* PyString_AsString(PyObject* o) {
    RESOLVE_CACHED(PyString_AsString)
    if (funcptr) {
        using FuncType = char*(__fastcall*)(PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(o);
    }
    return nullptr;
}

void PyEval_SetTrace(Py_tracefunc func, PyObject* arg) {
    RESOLVE_CACHED(PyEval_SetTrace)
    if (funcptr) {
        using FuncType = void(__fastcall*)(Py_tracefunc, PyObject*);
        reinterpret_cast<FuncType>(funcptr)(func, arg);
    }
}

int _PyCode_CheckLineNumber(PyCodeObject* co, int lasti, PyAddrPair* bounds) {
    int            size, addr, line;
    unsigned char* p;

    p    = (unsigned char*)PyString_AS_STRING(co->co_lnotab);
    size = PyString_GET_SIZE(co->co_lnotab) / 2;

    addr = 0;
    line = co->co_firstlineno;
    assert(line > 0);

    /* possible optimization: if f->f_lasti == instr_ub
       (likely to be a common case) then we already know
       instr_lb -- if we stored the matching value of p
       somewhere we could skip the first while loop. */

    /* See lnotab_notes.txt for the description of
       co_lnotab.  A point to remember: increments to p
       come in (addr, line) pairs. */

    bounds->ap_lower = 0;
    while (size > 0) {
        if (addr + *p > lasti) break;
        addr += *p++;
        if (*p) bounds->ap_lower = addr;
        line += *p++;
        --size;
    }

    if (size > 0) {
        while (--size >= 0) {
            addr += *p++;
            if (*p++) break;
        }
        bounds->ap_upper = addr;
    } else {
        bounds->ap_upper = INT_MAX;
    }

    return line;
}


// int PyString_AsStringAndSize(
//     PyObject*   obj, /* string or Unicode object */
//     char**      s,   /* pointer to buffer variable */
//     Py_ssize_t* len  /* pointer to length variable or NULL
//                 (only possible for 0-terminated
//                 strings) */
// ) {
//     static auto funcptr = memory::resolveSignature(
//         "48 89 5C 24 08 57 48 83 EC 20 49 8B D8 48 8B FA 48 85 D2 75 1F BA 24 03 00 00 48 8D 0D 9F FC 91"
//     );
//     if (funcptr) {
//         using FuncType = int(__fastcall*)(PyObject*, char**, Py_ssize_t*);
//         FuncType func  = reinterpret_cast<FuncType>(funcptr);
//         return func(obj, s, len);
//     }
//     return -1;
// }

PyGILState_STATE PyGILState_Ensure() {
    RESOLVE_CACHED(PyGILState_Ensure)
    if (funcptr) {
        using FuncType = PyGILState_STATE(__fastcall*)();
        return reinterpret_cast<FuncType>(funcptr)();
    }
    return PyGILState_UNLOCKED;
}

void PyGILState_Release(PyGILState_STATE state) {
    RESOLVE_CACHED(PyGILState_Release)
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyGILState_STATE);
        reinterpret_cast<FuncType>(funcptr)(state);
    }
}

PyThreadState* PyEval_SaveThread() {
    RESOLVE_CACHED(PyEval_SaveThread)
    if (funcptr) {
        using FuncType = PyThreadState*(__fastcall*)();
        return reinterpret_cast<FuncType>(funcptr)();
    }
    return nullptr;
}

void PyEval_RestoreThread(PyThreadState* tstate) {
    RESOLVE_CACHED(PyEval_RestoreThread)
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyThreadState*);
        reinterpret_cast<FuncType>(funcptr)(tstate);
    }
}

void PyFrame_LocalsToFast(PyFrameObject* f, int clear) {
    RESOLVE_CACHED(PyFrame_LocalsToFast)
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyFrameObject*, int);
        reinterpret_cast<FuncType>(funcptr)(f, clear);
    }
}

int PyDict_SetItemString(PyObject* dp, const char* key, PyObject* item) {
    RESOLVE_CACHED(PyDict_SetItemString)
    if (funcptr) {
        using FuncType = int(__fastcall*)(PyObject*, const char*, PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(dp, key, item);
    }
    return -1;
}

int PyDict_DelItemString(PyObject* dp, const char* key) {
    RESOLVE_CACHED(PyDict_DelItemString)
    if (funcptr) {
        using FuncType = int(__fastcall*)(PyObject*, const char*);
        return reinterpret_cast<FuncType>(funcptr)(dp, key);
    }
    return -1;
}

PyObject* PyImport_ImportModule(const char* name) {
    RESOLVE_CACHED(PyImport_ImportModule)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(const char*);
        return reinterpret_cast<FuncType>(funcptr)(name);
    }
    return nullptr;
}

PyObject* PyEval_CallObjectWithKeywords(PyObject* callable, PyObject* args, PyObject* kwds) {
    RESOLVE_CACHED(PyEval_CallObjectWithKeywords)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*, PyObject*, PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(callable, args, kwds);
    }
    return nullptr;
}

PyObject* PyObject_CallObject(PyObject* callable, PyObject* args) {
    return PyEval_CallObjectWithKeywords(callable, args, NULL);
}

int PyObject_SetAttrString(PyObject* o, const char* attr_name, PyObject* v) {
    RESOLVE_CACHED(PyObject_SetAttrString)
    if (funcptr) {
        using FuncType = int(__fastcall*)(PyObject*, const char*, PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(o, attr_name, v);
    }
    return -1;
}

PyObject* PyObject_Str(PyObject* o) {
    RESOLVE_CACHED(PyObject_Str)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(o);
    }
    return nullptr;
}

void PyErr_Fetch(PyObject** ptype, PyObject** pvalue, PyObject** ptraceback) {
    RESOLVE_CACHED(PyErr_Fetch)
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyObject**, PyObject**, PyObject**);
        reinterpret_cast<FuncType>(funcptr)(ptype, pvalue, ptraceback);
    }
}

void PyErr_NormalizeException(PyObject** exc, PyObject** val, PyObject** tb) {
    RESOLVE_CACHED(PyErr_NormalizeException)
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyObject**, PyObject**, PyObject**);
        reinterpret_cast<FuncType>(funcptr)(exc, val, tb);
    }
}

PyObject* PyTuple_New(Py_ssize_t size) {
    RESOLVE_CACHED(PyTuple_New)
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(Py_ssize_t);
        return reinterpret_cast<FuncType>(funcptr)(size);
    }
    return nullptr;
}

PyObject* PyTuple_Pack(Py_ssize_t n, ...) {
    Py_ssize_t i;
    PyObject*  o;
    PyObject*  result;
    PyObject** items;
    va_list    vargs;

    va_start(vargs, n);
    result = PyTuple_New(n);
    if (result == NULL) {
        va_end(vargs);
        return NULL;
    }
    items = ((PyTupleObject*)result)->ob_item;
    for (i = 0; i < n; i++) {
        o = va_arg(vargs, PyObject*);
        Py_INCREF(o);
        items[i] = o;
    }
    va_end(vargs);
    return result;
}

void PyErr_Restore(PyObject* a, PyObject* b, PyObject* c) {
    RESOLVE_CACHED(PyErr_Restore)
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyObject*, PyObject*, PyObject*);
        reinterpret_cast<FuncType>(funcptr)(a, b, c);
    }
}


#ifdef MCPDB_SIGSCAN_TEST

namespace test {

struct SigScanTest {
    const char* name;
    const char* signature;
    void*       result;
};

#define GEN_TEST_ENTRY(name, sig) {#name, sig, nullptr},

int a = []() {
    std::vector<SigScanTest> tests = {PYFUNC_SIGNATURE_TABLE(GEN_TEST_ENTRY)};

    std::cout << "[SigScan Test] Starting signature scan tests...\n" << std::endl;

    std::vector<std::string> failed_scans;
    int                      successful_count = 0;

    auto testSigScan = [](const char* name, const char* signature) -> void* {
        std::cout << "[Testing] " << name << "..." << std::flush;
        void* result = memory::resolveSignature(signature);
        if (result) {
            std::cout << " SUCCESS (0x" << std::hex << result << std::dec << ")" << std::endl;
        } else {
            std::cout << " FAILED" << std::endl;
        }
        return result;
    };

    for (auto& test : tests) {
        test.result = testSigScan(test.name, test.signature);

        if (test.result) {
            successful_count++;
        } else {
            failed_scans.push_back(std::string(test.name) + ": " + test.signature);
        }
    }

    std::cout << "\n=== Test Results ===" << std::endl;
    std::cout << "Total tests: " << tests.size() << std::endl;
    std::cout << "Successful: " << successful_count << std::endl;
    std::cout << "Failed: " << failed_scans.size() << std::endl;

    // Write failed scans to file
    if (!failed_scans.empty()) {
        std::ofstream failed_file("failed_scan.txt");
        if (failed_file.is_open()) {
            failed_file << "Failed Signature Scans:\n\n";
            for (const auto& failed : failed_scans) {
                failed_file << failed << "\n";
            }
            failed_file.close();
            std::cout << "\nFailed scans written to failed_scan.txt" << std::endl;
        }
    } else {
        std::cout << "\nAll signature scans successful!" << std::endl;
    }

    return 0;
}();

} // namespace test

#endif // MCPDB_SIGSCAN_TEST
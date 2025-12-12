#include "api/memory/Memory.h"

#define register
#include "py/Python.h" // IWYU pragma: keep
#include "py/frameobject.h"

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
    static auto funcptr = memory::resolveSignature("40 57 48 83 EC 20 48 8B 41 08 48 8B F9 4C 8B 40");
    static bool logged  = false;
    if (!logged) {
        std::cout << "[PyHook] PyObject_GetAttrString funcptr = " << funcptr << std::endl;
        logged = true;
    }
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*, const char*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(a, b);
    }
    return nullptr;
}

int PyObject_HasAttrString(PyObject* a, const char* b) {
    static auto funcptr = memory::resolveSignature("48 83 EC 28 E8 47 FF FF FF 48 85 C0 74 1A 48 83");
    if (funcptr) {
        using FuncType = int(__fastcall*)(PyObject*, const char*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(a, b);
    }
    return 0;
}

PyObject* PyObject_GetAttr(PyObject* a, PyObject* b) {
    static auto funcptr =
        memory::resolveSignature("48 89 5C 24 08 57 48 83 EC 20 4C 8B 42 08 48 8B F9 48 8B 59 08 48 8B C2");
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*, PyObject*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(a, b);
    }
    return nullptr;
}

PyObject* PyObject_Dir(PyObject* a) {
    static auto funcptr = memory::resolveSignature("40 53 48 83 EC 20 48 85 C9 75 7F E8 C0 65 04 00");
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(a);
    }
    return nullptr;
}

PyObject* PyUnicodeUCS2_AsUTF8String(_object* unicode) {
    static auto funcptr =
        memory::resolveSignature("48 83 EC 28 48 8B 41 08 F7 80 A8 00 00 00 00 00 00 10 75 0C E8 B7 65 FE FF");
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(_object*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(unicode);
    }
    return nullptr;
}

PyObject* PyBool_FromLong(long v) {
    static auto funcptr = memory::resolveSignature("48 8B 15 ? ? ? ? 4C 8D 05 ? ? ? ? 85 C9");
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(long);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(v);
    }
    return nullptr;
}

PyObject* PyFloat_FromDouble(double v) {
    static auto funcptr = memory::resolveSignature("48 83 EC 38 48 8B 15 ? ? ? ? 0F 29 74 24 20");
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(double);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(v);
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
    static auto funcptr =
        memory::resolveSignature("48 83 EC 28 48 8B 41 08 F7 80 A8 00 00 00 00 00 00 02 75 18 BA B6 00 00");
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*, Py_ssize_t);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(a, b);
    }
    return nullptr;
}

PyObject* PyDict_GetItemString(PyObject* dp, const char* key) {
    static auto funcptr =
        memory::resolveSignature("48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B CA E8 FB 2B FF FF 48 8B D8");
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*, const char*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(dp, key);
    }
    return nullptr;
}

void PyErr_Clear(void) {
    static auto funcptr = memory::resolveSignature("48 89 5C 24 08 57 48 83 EC 20 48 8B 05 ? ? ? ? 33 D2 48 8B 48 48");
    if (funcptr) {
        using FuncType = void(__fastcall*)();
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func();
    }
}

PyObject* Py_BuildValue(const char* format, ...) {
    static auto funcptr = memory::resolveSignature(
        "48 89 4C 24 08 48 89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 8D 54 24 38 45 33 C0"
    );
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
    static auto funcptr = memory::resolveSignature(
        "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 30 49 8B D9 41 8B E8"
    );
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(const char*, const char*, int, PyCompilerFlags*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(a, b, c, d);
    }
    return nullptr;
}

PyObject* PyImport_AddModule(const char* name) {
    static auto funcptr = memory::resolveSignature("40 57 48 83 EC 20 E8 85 5B FB FF 48 8B F8 48 85");
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(const char*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(name);
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
    static auto funcptr = memory::resolveSignature("48 89 4C 24 08 41 54 41 55 41 57 48 81 EC 90 00 00 00");
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
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(co, globals, locals, args, argc, kwds, kwdc, defs, defc, closure);
    }
    return nullptr;
}


PyObject* PyEval_EvalCode(PyCodeObject* a, PyObject* b, PyObject* c) {
    return PyEval_EvalCodeEx(a, b, c, nullptr, 0, nullptr, 0, nullptr, 0, nullptr);
}

PyObject* PyModule_GetDict(PyObject* module) {
    static auto funcptr = memory::resolveSignature(
        "40 53 48 83 EC 20 48 8B D9 48 8D 15 ? ? ? ? 48 8B 49 08 48 3B CA 74 20 E8 ? ? ? ? 85 C0"
    );
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(module);
    }
    return nullptr;
}

int PyFrame_GetLineNumber(PyFrameObject* f) {
    static auto funcptr = memory::resolveSignature("48 83 79 50 00 74 04 8B 41 7C C3 8B 51 78 48 8B");
    if (funcptr) {
        using FuncType = int(__fastcall*)(PyFrameObject*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(f);
    }
    return -1;
}

void PyFrame_FastToLocals(PyFrameObject* f) {
    static auto funcptr = memory::resolveSignature("48 85 C9 0F 84 E5 01 00 00 53 48 83 EC 70 48 8B");
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyFrameObject*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(f);
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
    static auto funcptr = memory::resolveSignature("48 89 5C 24 08 57 48 83 EC 20 48 8B D9 E8 7E 7A");
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(o);
    }
    return nullptr;
}

char* PyString_AsString(PyObject* o) {
    static auto funcptr =
        memory::resolveSignature("48 83 EC 28 4C 8B 41 08 41 8B 80 A8 00 00 00 0F BA E0 1B 72 39 0F BA E0");
    if (funcptr) {
        using FuncType = char*(__fastcall*)(PyObject*);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(o);
    }
    return nullptr;
}

void PyEval_SetTrace(Py_tracefunc func, PyObject* arg) {

    static auto funcptr =
        memory::resolveSignature("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B 1D ? ? ? ? 45 33 C0 48 8B F1");
    if (funcptr) {
        using FuncType = void(__fastcall*)(Py_tracefunc, PyObject*);
        FuncType func2 = reinterpret_cast<FuncType>(funcptr);
        return func2(func, arg);
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
    static auto funcptr =
        memory::resolveSignature("48 89 5C 24 10 57 48 83 EC 20 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B D8 48 85 C0 75 33");
    if (funcptr) {
        using FuncType = PyGILState_STATE(__fastcall*)();
        return reinterpret_cast<FuncType>(funcptr)();
    }
    return PyGILState_UNLOCKED;
}

void PyGILState_Release(PyGILState_STATE state) {
    static auto funcptr =
        memory::resolveSignature("48 89 5C 24 08 57 48 83 EC 20 8B F9 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B D8");
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyGILState_STATE);
        reinterpret_cast<FuncType>(funcptr)(state);
    }
}

PyThreadState* PyEval_SaveThread() {
    static auto funcptr = memory::resolveSignature("40 53 48 83 EC 20 33 C9 E8 ? ? ? ? 48 8B D8");
    if (funcptr) {
        using FuncType = PyThreadState*(__fastcall*)();
        return reinterpret_cast<FuncType>(funcptr)();
    }
    return nullptr;
}

void PyEval_RestoreThread(PyThreadState* tstate) {
    static auto funcptr = memory::resolveSignature("40 57 48 83 EC 20 48 8B  F9 48 85 C9 75 0C");
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyThreadState*);
        reinterpret_cast<FuncType>(funcptr)(tstate);
    }
}

void PyFrame_LocalsToFast(PyFrameObject* f, int clear) {
    static auto funcptr = memory::resolveSignature("48 85 C9 0F 84 2E 02 00 00 4C 8B DC 53 41 56");
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyFrameObject*, int);
        reinterpret_cast<FuncType>(funcptr)(f, clear);
    }
}

int PyDict_SetItemString(PyObject* dp, const char* key, PyObject* item) {
    static auto funcptr = memory::resolveSignature(
        "48 89 5C 24 20 57 48 83 EC 30 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 28 48 8B D9 49 8B F8 48 8B CA"
    );
    if (funcptr) {
        using FuncType = int(__fastcall*)(PyObject*, const char*, PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(dp, key, item);
    }
    return -1;
}

int PyDict_DelItemString(PyObject* dp, const char* key) {
    static auto funcptr =
        memory::resolveSignature("48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B CA E8 ? ? ? ? 48 8B D8 48 85 C0 75 0E");
    if (funcptr) {
        using FuncType = int(__fastcall*)(PyObject*, const char*);
        return reinterpret_cast<FuncType>(funcptr)(dp, key);
    }
    return -1;
}

PyObject* PyImport_ImportModule(const char* name) {
    static auto funcptr = memory::resolveSignature("48 83 EC 28 E8 ? ? ? ? 48 89 44 24 38");
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(const char*);
        return reinterpret_cast<FuncType>(funcptr)(name);
    }
    return nullptr;
}

PyObject* PyEval_CallObjectWithKeywords(PyObject* callable, PyObject* args, PyObject* kwds) {
    static auto funcptr = memory::resolveSignature(
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F8 48 8B DA 48 8B F1 48 85 D2 75 11"
    );
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
    static auto funcptr =
        memory::resolveSignature("40 55 56 48 83 EC 48 48 8B 05 ? ?  ? ? 48 33 C4 48 89 44 24 38 48 8B 41 08");
    if (funcptr) {
        using FuncType = int(__fastcall*)(PyObject*, const char*, PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(o, attr_name, v);
    }
    return -1;
}

PyObject* PyObject_Str(PyObject* o) {
    static auto funcptr = memory::resolveSignature(
        "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 85 C9 75 0E 48 8D 0D ?  ? ? ? E8 ? ? ? ? EB 36"
    );
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(PyObject*);
        return reinterpret_cast<FuncType>(funcptr)(o);
    }
    return nullptr;
}

void PyErr_Fetch(PyObject** ptype, PyObject** pvalue, PyObject** ptraceback) {
    static auto funcptr = memory::resolveSignature("4C 8B 0D ? ? ? ? 49 8B 41 48 48 89 01 49 8B 41 50");
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyObject**, PyObject**, PyObject**);
        reinterpret_cast<FuncType>(funcptr)(ptype, pvalue, ptraceback);
    }
}

void PyErr_NormalizeException(PyObject** exc, PyObject** val, PyObject** tb) {
    static auto funcptr =
        memory::resolveSignature("48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 41 54 41 56 41 57 48 83 EC 20 48 8B 39");
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyObject**, PyObject**, PyObject**);
        reinterpret_cast<FuncType>(funcptr)(exc, val, tb);
    }
}

PyObject* PyTuple_New(Py_ssize_t size) {
    static auto funcptr = memory::resolveSignature(
        "40 53 48 83 EC 20 48 8B D9 48 85 C9 79 19 BA 36 00 00 00 48 8D 0D ? ? ? ? E8 ? ? ? ? 33 C0"
    );
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(Py_ssize_t);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(size);
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

    static auto funcptr = memory::resolveSignature(
        "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 20 48 8B 35 ? ? ? ? 48 8B EA "
        "4C 8B F1 4D 85 C0 74 1F 49 8B 40 08"
    );
    if (funcptr) {
        using FuncType = void(__fastcall*)(PyObject*, PyObject*, PyObject*);
        reinterpret_cast<FuncType>(funcptr)(a, b, c);
    }
}
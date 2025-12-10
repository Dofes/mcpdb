#include "api/memory/Memory.h"

#define register
#include "py/Python.h" // IWYU pragma: keep
#include "py/frameobject.h"

namespace py {
extern PyTypeObject* getDynBaseObjectType();
}
int PyType_IsSubtype(_typeobject* a, _typeobject* b) {
    _object*      tp_mro;    // r9
    __int64       ob_refcnt; // r8
    __int64       v5;        // rax
    _typeobject** i;         // rcx

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
    static auto funcptr = memory::resolveSignature("48 8B 15 11 61 0F 06 4C 8D 05 0A 61 0F 06");
    if (funcptr) {
        using FuncType = PyObject*(__fastcall*)(long);
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func(v);
    }
    return nullptr;
}

PyObject* PyFloat_FromDouble(double v) {
    static auto funcptr = memory::resolveSignature("48 83 EC 38 48 8B 15 85 3F 4A 07 0F 29 74 24 20");
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
    static auto funcptr = memory::resolveSignature("48 89 5C 24 08 57 48 83 EC 20 48 8B 05 9F 70 47");
    if (funcptr) {
        using FuncType = void(__fastcall*)();
        FuncType func  = reinterpret_cast<FuncType>(funcptr);
        return func();
    }
}

PyObject* Py_BuildValue(const char* format, ...) {
    static auto funcptr = memory::resolveSignature("48 89 4C 24 08 48 89 54 24 10 4C 89 44 24 18 4C");
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
    static auto funcptr = memory::resolveSignature("40 53 48 83 EC 20 48 8B D9 48 8D 15 20 A0 0B 06");
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

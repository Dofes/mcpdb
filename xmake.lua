add_rules("mode.debug", "mode.releasedbg", "mode.release")


add_repositories("liteldev-repo https://github.com/LiteLDev/xmake-repo.git")

add_requires("nlohmann_json v3.11.3")
add_requires("detours v4.0.1-xmake.1")
add_requires("expected-lite v0.8.0")
add_requires("fmt 10.2.1", {configs = {runtimes = "MD"}}) 

target("bedrock")
    set_kind("shared")
    add_files("src/**.cpp")
    add_links("Advapi32","user32","comctl32","kernel32","ws2_32","comdlg32","shell32","ole32","oleaut32","uuid")
    add_packages("detours","fmt","nlohmann_json","expected-lite")
    set_languages("c++20")
    add_includedirs("src")
    add_defines("AURORA_EXPORT")
    add_cxflags("/utf-8", "/permissive-", "/MP", "/MD")
    add_defines("_HAS_CXX23=1")
    add_defines("_UNICODE", "UNICODE")
    set_symbols("debug")
    add_defines(
        "_AMD64_",
        "NOMINMAX",
        "WIN32_LEAN_AND_MEAN",
        "_USRDLL",
        "Py_BUILD_CORE"
        
        )



target("bedrock-injector")
    set_kind("binary")
    add_files("src-injector/**.cpp")
    add_links("Advapi32","user32","Shell32")
    add_packages("expected-lite")
    set_languages("c++20")
    add_includedirs("src")
    add_cxflags("/utf-8", "/permissive-", "/W4", "/MP")
    add_defines("_UNICODE", "UNICODE")
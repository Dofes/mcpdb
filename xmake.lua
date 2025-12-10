add_rules("mode.debug", "mode.releasedbg", "mode.release")


add_repositories("liteldev-repo https://github.com/LiteLDev/xmake-repo.git")

add_requires("nlohmann_json v3.11.3","minhook v1.3.3","ctre 3.8.1","magic_enum v0.9.7")
add_requires("cpr 1.11.1", {configs = {ssl = true}})
add_requires("imgui[dx11=y,dx12=y] v1.91.0-docking")
add_requires("detours v4.0.1-xmake.1")
add_requires("entt v3.14.0")
add_requires("gsl v4.0.0")
add_requires("glm 1.0.1")
add_requires("rapidjson v1.1.0")
add_requires("type_safe v0.2.4")
add_requires("expected-lite v0.8.0")
add_requires("fmt 10.2.1", {configs = {runtimes = "MD"}}) 

target("bedrock")
    set_kind("shared")
    add_files("src/**.cpp")
    add_links("Advapi32","user32","comctl32","kernel32","ws2_32","comdlg32","shell32","ole32","oleaut32","uuid")
    add_packages("detours","fmt","ctre","magic_enum","imgui","nlohmann_json","entt","glm","gsl","rapidjson","type_safe","expected-lite")
    -- add_packages("cpr")
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
    add_packages("detours","fmt","ctre","magic_enum")
    set_languages("c++20")
    add_includedirs("src")
    add_packages("nlohmann_json")
    add_defines("SKY_EXPORT")
    add_cxflags("/utf-8", "/permissive-", "/W4", "/MP")
    add_defines("_UNICODE", "UNICODE")
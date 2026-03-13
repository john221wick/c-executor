cmake_minimum_required(VERSION 3.25)

project(c-executor
    VERSION 0.1.0
    DESCRIPTION "Linux-native sandboxed code executor"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Dependencies ──────────────────────────────────────────────────────────

include(FetchContent)

# nlohmann/json — header-only, used only in environment.cpp
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

# libseccomp — system package: apt install libseccomp-dev
find_library(SECCOMP_LIB seccomp REQUIRED)
find_path(SECCOMP_INCLUDE seccomp.h REQUIRED)

# libcap — for cap_get_proc / cap_set_proc in worker.cpp
find_library(CAP_LIB cap REQUIRED)

# ── Sources ───────────────────────────────────────────────────────────────
#
# worker.cpp is #include'd by engine.cpp.
# engine.cpp is #include'd by main.cpp.
# Only main.cpp is listed as a compilation unit.

add_executable(${PROJECT_NAME}
    src/main.cpp
    src/environment.cpp
    src/sandbox.cpp
    src/tracer.cpp
    src/io.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE
    include
    ${SECCOMP_INCLUDE}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    pthread
    ${SECCOMP_LIB}
    ${CAP_LIB}
    nlohmann_json::nlohmann_json
)

target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror=return-type
)

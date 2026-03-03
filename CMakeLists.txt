cmake_minimum_required(VERSION 3.25...4.2)

project(c-executor
    VERSION 0.1.0
    DESCRIPTION "My modern C++ project"
    LANGUAGES CXX
)

add_executable(${PROJECT_NAME} src/main.cpp)

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_23)
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_EXTENSIONS OFF
    EXPORT_COMPILE_COMMANDS ON
)

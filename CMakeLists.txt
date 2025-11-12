cmake_minimum_required(VERSION 3.16)
project(Medivh LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 生成 compile_commands.json 文件给 LSP 使用
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 默认构建类型为 Release，可通过 -DCMAKE_BUILD_TYPE=Debug 切换
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# 开启调试选项
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Building in Debug mode")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Building in Release mode")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
endif()

# 编译子模块
add_subdirectory(PcapPlusPlus-25.05)
add_subdirectory(SketchLib)

file(GLOB_RECURSE MEDIVH_SOURCES "src/*.cpp")

add_library(medivh STATIC ${MEDIVH_SOURCES})

# Release 模式下对 Medivh 开启严格警告
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(medivh PRIVATE -O3 -DNDEBUG -Wall -Wextra)
endif()

target_include_directories(medivh
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/SketchLib/include
)

# 链接子模块
target_link_libraries(medivh
    PUBLIC
        Packet++
        SketchLib
)

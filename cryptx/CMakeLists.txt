# 目标名称
set(tgt_name cryptx)

# 收集头文件和源文件
file(GLOB_RECURSE HEADERS include/${tgt_name}/*.h include/${tgt_name}/*.hpp)
file(GLOB_RECURSE SOURCES src/*.c src/*.cpp src/*.cc src/*.cxx)

add_library(${tgt_name} ${HEADERS} ${SOURCES})

# 添加头文件路径
target_include_directories(${tgt_name} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>)

# 查找 OpenSSL
find_package(OpenSSL REQUIRED)

# 链接 OpenSSL
target_link_libraries(${tgt_name} PUBLIC OpenSSL::Crypto)

# ================================
# 定义宏，让高版本 OpenSSL 不触发弃用警告
target_compile_definitions(${tgt_name} PRIVATE OPENSSL_SUPPRESS_DEPRECATED)

if (MSVC)
    # /wd4996 用于屏蔽 MSVC 的 deprecated 警告
    target_compile_options(${tgt_name} PRIVATE /wd4996)
else()
    # GCC / Clang
    target_compile_options(${tgt_name} PRIVATE -Wno-deprecated-declarations)
endif()
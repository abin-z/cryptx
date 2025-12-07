# 目标名称
set(tgt_name utest)

# 自动收集所有 cpp 文件
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS src/*.c src/*.cpp src/*.cc src/*.cxx)

add_executable(${tgt_name} ${SOURCES})

# 链接线程库（如果有的话）
target_link_libraries(${tgt_name} PRIVATE ${THREAD_LIB})
# 链接 cryptx 库
target_link_libraries(${tgt_name} PRIVATE cryptx)
# Catch2 测试框架
target_include_directories(${tgt_name}  PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd/catch2_v2/single_include
)
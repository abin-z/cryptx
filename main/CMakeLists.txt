# 目标名称
set(tgt_name main)

# 收集头文件和源文件
file(GLOB_RECURSE HEADERS include/${tgt_name}/*.h include/${tgt_name}/*.hpp)
file(GLOB_RECURSE SOURCES src/*.c src/*.cpp src/*.cc src/*.cxx)

add_executable(${tgt_name} ${HEADERS} ${SOURCES})

# 添加头文件路径
target_include_directories(${tgt_name} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>)

# 链接 cryptx 库
target_link_libraries(${tgt_name} PRIVATE cryptx)
# 链接线程库（如果有的话）
target_link_libraries(${tgt_name} PRIVATE ${THREAD_LIB})


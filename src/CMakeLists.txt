aux_source_directory (. SRC_LIST)

include_directories (../include)

add_executable (testapp ${SRC_LIST})

# EXECUTABLE_OUTPUT_PATH: 目标二进制文件存放位置
# PROJECT_SOURCE_DIR: 工程的根目录
set (EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
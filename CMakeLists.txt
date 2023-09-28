cmake_minimum_required (VERSION 3.5)

SET(CMAKE_C_COMPILER /usr/bin/clang)
SET(CMAKE_CXX_COMPILER /usr/bin/clang++)
project (mqtt_testapp)

# 默认开启 compile_commands.json
# compile_commands.json https://edward852.github.io/post/%E7%94%9F%E6%88%90compile_commands.json%E6%96%87%E4%BB%B6/
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

set (CMAKE_C_STANDARD 99)
set (CMAKE_C_STANDARD_REQUIRED ON)

# 设置生成目录
set (EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set (LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

aux_source_directory (src SRC_LIST)

include_directories (include)

add_compile_options(-std=gnu99
                    -Wall
                    -Wno-deprecated-declarations
                    -DLOG_USE_COLOR)

# set shared and static library
add_library (testapp_shared SHARED ${SRC_LIST})
add_library (testapp_static STATIC ${SRC_LIST})

set_target_properties (testapp_shared PROPERTIES OUTPUT_NAME "testapp")
set_target_properties (testapp_static PROPERTIES OUTPUT_NAME "testapp")

add_executable(testapp ${SRC_LIST})

# 查找libubox
find_library(UBOX_LIBRARY NAMES ubox PATHS /usr/local/lib)

include_directories(/usr/local/include)

TARGET_LINK_LIBRARIES(testapp ssl crypto paho-mqtt3as paho-mqtt3cs pthread ${UBOX_LIBRARY} mosquitto)
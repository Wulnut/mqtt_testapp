cmake_minimum_required (VERSION 3.5)

project (mqtt_testapp)

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
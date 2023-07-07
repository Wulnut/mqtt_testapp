cmake_minimum_required (VERSION 2.8)

project (mqtt_testapp)

set (EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

aux_source_directory (src SRC_LIST)

include_directories (include)

add_executable(testapp ${SRC_LIST})

add_library (testapp_shared SHARED ${SRC_LIST})
add_library (testapp_static STATIC ${SRC_LIST})

set_target_properties (testapp_shared PROPERTIES OUTPUT_NAME "testapp")
set_target_properties (testapp_static PROPERTIES OUTPUT_NAME "testapp")

set (LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)


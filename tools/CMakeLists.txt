cmake_minimum_required(VERSION 3.18.0 FATAL_ERROR)
project(tools LANGUAGES C)

set(_TARGETS)
set(_TOOLS_LIST strliteral)

if(CMAKE_CROSSCOMPILING)
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/host_tools)
  file(TO_NATIVE_PATH ${CMAKE_COMMAND} native_cmake_command)
  file(TO_NATIVE_PATH ${CMAKE_CURRENT_SOURCE_DIR}
       native_cmake_current_source_dir)

  execute_process(
    COMMAND_ECHO STDOUT
    COMMAND
      sh -c
      "CC= ${native_cmake_command} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} ${native_cmake_current_source_dir}"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/host_tools)

  add_custom_target(
    host_tools
    COMMAND ${CMAKE_COMMAND} --build . --target host_tools --config $<CONFIG>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/host_tools)

  include(${CMAKE_CURRENT_BINARY_DIR}/host_tools/host_tools.cmake)

  foreach(tgt IN ITEMS ${_TOOLS_LIST})
    add_custom_target(
      host${tgt}ninja
      COMMAND echo ''
      DEPENDS host_tools
      BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/host_tools/${tgt})
    add_dependencies(host${tgt} host${tgt}ninja)
  endforeach()

else(!CMAKE_CROSSCOMPILING)
  add_custom_target(host_tools DEPENDS ${_TOOLS_LIST})
endif(CMAKE_CROSSCOMPILING)

add_executable(strliteral strliteral.c)

if(NOT CMAKE_CROSSCOMPILING)
  foreach(tgt IN ITEMS ${_TOOLS_LIST})
    add_executable(host${tgt} ALIAS ${tgt})
  endforeach()
  export(
    TARGETS ${_TOOLS_LIST}
    NAMESPACE host
    FILE host_tools.cmake)
endif()

list(APPEND _TARGETS "${CMAKE_BINARY_DIR}/include/app_json.inc")
add_custom_command(
  OUTPUT "${CMAKE_BINARY_DIR}/include/app_json.inc"
  DEPENDS hoststrliteral
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMAND cmake -E make_directory ${CMAKE_BINARY_DIR}/include
  COMMAND
    $<TARGET_FILE:hoststrliteral> -i "app_json" ${CMAKE_SOURCE_DIR}/.app.json >
    "${CMAKE_BINARY_DIR}/include/app_json.inc")

add_custom_target(generated DEPENDS ${_TARGETS})

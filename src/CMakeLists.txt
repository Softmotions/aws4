if(NOT CMAKE_BUILD_TYPE)
  message(
    FATAL_ERROR
      "Please specify the build type -DCMAKE_BUILD_TYPE=Debug|Release|RelWithDebInfo"
  )
endif()

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} \
  -std=gnu11 \
  -fPIC \
  -Wall \
  -Wextra \
  -Wfatal-errors \
  -Wno-implicit-fallthrough \
  -Wno-missing-braces \
  -Wno-missing-field-initializers \
  -Wno-sign-compare \
  -Wno-unknown-pragmas \
  -Wno-unused-function \
  -Wno-unused-parameter")

set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG
    "-O0 -g -ggdb \
    -Werror \
    -Wno-unused-variable \
    -DDEBUG -D_DEBUG -UNDEBUG")

set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wl,-s")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELEASE} -g")
set(CMAKE_C_FLAGS_RELEASEWITHDEBINFO ${CMAKE_C_FLAGS_RELWITHDEBINFO})

find_package(Threads REQUIRED CMAKE_THREAD_PREFER_PTHREAD)
include(FindCURL)
if(NOT CURL_FOUND)
  message(FATAL_ERROR "Cannot find libcurl library")
endif()

include(AddIOWOW)
include(AddIWNET)

set(LINK_LIBS IWNET::static ${CURL_LIBRARIES})

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_BINARY_DIR}/include
                    ${IOWOW_INCLUDE_DIRS} ${IWNET_INCLUDE_DIRS})
add_definitions(-D_LARGEFILE_SOURCE)

file(GLOB ALL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
               ${CMAKE_BINARY_DIR}/include/config.h)

add_library(aws4_s ${ALL_SRC})
add_dependencies(aws4_s generated)

target_link_libraries(aws4_s PUBLIC ${LINK_LIBS})
set_target_properties(
  aws4_s
  PROPERTIES VERSION ${PROJECT_VERSION}
             PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/aws4.h
             ${CMAKE_CURRENT_SOURCE_DIR}/aws4dd.h
             ${CMAKE_CURRENT_SOURCE_DIR}/aws4dl.h
             OUTPUT_NAME aws4-${PROJECT_VERSION_MAJOR})

if(OWNER_PROJECT_NAME)
  set(AWS4_PUBLIC_HEADER_DESTINATION
      ${CMAKE_INSTALL_INCLUDEDIR}/${OWNER_PROJECT_NAME}/${PROJECT_NAME})
else()
  set(AWS4_PUBLIC_HEADER_DESTINATION
      ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})
endif()

include(InstallRequiredSystemLibraries)
install(
  TARGETS aws4_s
  EXPORT aws4-exports
  FRAMEWORK DESTINATION ${FRAMEWORK_INSTALL_DIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PUBLIC_HEADER DESTINATION ${AWS4_PUBLIC_HEADER_DESTINATION})
install(EXPORT aws4-exports
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/${PROJECT_NAME})

if(BUILD_TESTS)
  add_subdirectory(tests)
endif()

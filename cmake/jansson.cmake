# Minimum CMake required
cmake_minimum_required(VERSION 3.10)

include(${CMAKE_ROOT}/Modules/ExternalProject.cmake)

ExternalProject_Add(
  jansson
  GIT_REPOSITORY "https://github.com/akheron/jansson.git"
  GIT_TAG "v2.12"
  INSTALL_COMMAND ""	# do not install janson
  CMAKE_ARGS -DJANSSON_BUILD_DOCS=OFF -DJANSSON_WITHOUT_TESTS=ON -DJANSSON_EXAMPLES=OFF -DCMAKE_DEBUG_POSTFIX=v -DCMAKE_RELEASE_POSTFIX=v
)

add_library(libjansson STATIC IMPORTED GLOBAL)
add_dependencies(libjansson jansson)

set(LIBJANSSON_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/jansson-prefix/src/jansson-build/include)
file(MAKE_DIRECTORY ${LIBJANSSON_INCLUDE_DIR})
set_target_properties(libjansson PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${LIBJANSSON_INCLUDE_DIR})


if(MSVC)
	set(LIBJANSSON_LIB ${CMAKE_CURRENT_BINARY_DIR}/jansson-prefix/src/jansson-build/lib/${CMAKE_CFG_INTDIR}/janssono.lib)
else(UNIX)
	set(LIBJANSSON_LIB ${CMAKE_CURRENT_BINARY_DIR}/jansson-prefix/src/jansson-build/lib/libjansson.a)
endif()

set_target_properties(libjansson PROPERTIES IMPORTED_LOCATION ${LIBJANSSON_LIB})

# Minimum CMake required
cmake_minimum_required(VERSION 3.10)
set(yara_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/..")

set(yara_YARAC_INC
	${yara_SRC_PATH}/args.h
	${yara_SRC_PATH}/common.h
)

set(yara_YARAC_SRC
	${yara_SRC_PATH}/args.c
	${yara_SRC_PATH}/yarac.c
)

add_executable(yarac ${yara_YARAC_SRC} ${yara_YARAC_INC})
target_link_libraries(yarac libyara)

install(TARGETS yarac RUNTIME DESTINATION bin)

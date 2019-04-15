# Minimum CMake required
cmake_minimum_required(VERSION 3.10)
set(yara_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/..")

set(yara_YARA_INC
	${yara_SRC_PATH}/args.h
	${yara_SRC_PATH}/common.h
)

set(yara_YARA_SRC
	${yara_SRC_PATH}/args.c
	${yara_SRC_PATH}/yarac.c
)

add_executable(yara ${yara_YARA_SRC} ${yara_YARA_INC})
target_link_libraries(yara libyara)

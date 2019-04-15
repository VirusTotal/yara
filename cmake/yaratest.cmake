# Minimum CMake required
cmake_minimum_required(VERSION 3.11)
set(yara_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/..")

set(TEST_COMMON
	${yara_SRC_PATH}/tests/util.c
)

add_executable(alignment ${yara_SRC_PATH}/tests/test-alignment.c)
set_target_properties(alignment PROPERTIES FOLDER Tests)
target_link_libraries(alignment libyara)
add_test(
	NAME test_alignment 
	COMMAND alignment
)

if(NOT WIN32)
	add_executable(version ${yara_SRC_PATH}/tests/test-version.c)
	set_target_properties(version PROPERTIES FOLDER Tests)
	target_link_libraries(version libyara)
	add_test(
		NAME test_version
		COMMAND version
	)
endif()

set(TEST_ATOMS_SRC
	${yara_SRC_PATH}/tests/test-atoms.c 
	${yara_SRC_PATH}/libyara/atoms.c
	${TEST_COMMON}
)
	
add_executable(atoms ${TEST_ATOMS_SRC})
target_link_libraries(atoms libyara)
set_target_properties(atoms PROPERTIES FOLDER Tests)
add_test(
	NAME test_atoms
	COMMAND atoms
)

if(NOT WIN32)
	add_executable(rules ${yara_SRC_PATH}/tests/test-rules.c ${TEST_COMMON})
	target_link_libraries(rules libyara)
	set_target_properties(rules PROPERTIES FOLDER Tests)
	add_test(
		NAME test_rules
		COMMAND rules
	)
endif()

add_executable(pe ${yara_SRC_PATH}/tests/test-pe.c ${TEST_COMMON})
target_link_libraries(pe libyara)
set_target_properties(pe PROPERTIES FOLDER Tests)
add_test(
	NAME test_pe
	COMMAND pe
)

add_executable(elf ${yara_SRC_PATH}/tests/test-elf.c ${TEST_COMMON})
target_link_libraries(elf libyara)
set_target_properties(elf PROPERTIES FOLDER Tests)
add_test(
	NAME test_elf
	COMMAND elf
)

add_executable(api ${yara_SRC_PATH}/tests/test-api.c ${TEST_COMMON})
target_link_libraries(api libyara)
set_target_properties(api PROPERTIES FOLDER Tests)
add_test(
	NAME test_api
	COMMAND api
)

add_executable(bitmask ${yara_SRC_PATH}/tests/test-bitmask.c ${TEST_COMMON})
target_link_libraries(bitmask libyara)
set_target_properties(bitmask PROPERTIES FOLDER Tests)
add_test(
	NAME test_bitmask
	COMMAND bitmask
)

add_executable(math ${yara_SRC_PATH}/tests/test-math.c ${TEST_COMMON})
target_link_libraries(math libyara)
set_target_properties(math PROPERTIES FOLDER Tests)
add_test(
	NAME test_math
	COMMAND math
)

add_executable(stack ${yara_SRC_PATH}/tests/test-stack.c ${TEST_COMMON})
target_link_libraries(stack libyara)
set_target_properties(stack PROPERTIES FOLDER Tests)
add_test(
	NAME test_stack
	COMMAND stack
)

if(yara_MACHO_MODULE)
	add_executable(macho ${yara_SRC_PATH}/tests/test-macho.c ${TEST_COMMON})
	target_link_libraries(macho libyara)
	set_target_properties(macho PROPERTIES FOLDER Tests)
	add_test(
		NAME test_macho
		COMMAND macho
	)
endif()

if(yara_DEX_MODULE)
	add_executable(dex ${yara_SRC_PATH}/tests/test-dex.c ${TEST_COMMON})
	target_link_libraries(dex libyara)
	set_target_properties(dex PROPERTIES FOLDER Tests)
	add_test(
		NAME test_dex
		COMMAND dex
	)
endif()
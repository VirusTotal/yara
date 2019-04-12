# Minimum CMake required
cmake_minimum_required(VERSION 3.11)

# Project
project(yara LANGUAGES C)

# Config
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
SET(ARCHIVE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

# Build options
option(yara_BUILD_YARA "Build yara executable" ON)
option(yara_BUILD_YARAC "Build yarac (compiler) executable" ON)

# Module options
option(yara_CUCKOO_MODULE "Build cuckoo module for libyara" OFF)
option(yara_MAGIC_MODULE "Build magic module for libyara" OFF)
option(yara_HASH_MODULE "Build hash module for libyara" OFF)
option(yara_DOTNET_MODULE "Build dotnet module for libyara" OFF)
option(yara_MACHO_MODULE "Build macho module for libyara" OFF)
option(yara_DEX_MODULE "Build dex module for libyara" OFF)

# Build of yara
include(libyara.cmake)

if(yara_BUILD_YARA)
	include(yara.cmake)
endif()

if(yara_BUILD_YARAC)
	include(yarac.cmake)
endif()

# Summary
message(STATUS "Configuration summary")
message(STATUS "Project name : ${PROJECT_NAME}")
message(STATUS "Project version : ${PROJECT_VERSION}")
message(STATUS "Build yara executable : ${yara_BUILD_YARA}")
message(STATUS "Build yarac (compiler) executable : ${yara_BUILD_YARAC}")
message(STATUS "Build with module Cuckoo : ${yara_CUCKOO_MODULE}")
message(STATUS "Build with module Magic : ${yara_MAGIC_MODULE}")
message(STATUS "Build with module Hash : ${yara_HASH_MODULE}")
message(STATUS "Build with module Dotnet : ${yara_DOTNET_MODULE}")
message(STATUS "Build with module Macho : ${yara_MACHO_MODULE}")
message(STATUS "Build with module Dex : ${yara_DEX_MODULE}")
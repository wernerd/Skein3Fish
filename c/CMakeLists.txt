# Copyright (C) 2010 Werner Dittman
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
cmake_minimum_required(VERSION 2.6)

PROJECT(skein3fish)
set (VERSION 0.6.0)
set (SOVERSION 0.6)

# set true for debug and trace during CMakeLists development
set(CMAKE_VERBOSE_MAKEFILE FALSE)

# find project specific modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

# include most of the fine stuff we need 
include(FindPkgConfig)
include(CheckIncludeFiles)

set (DOXYFILE_SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")
set(DOXYFILE_DOT "YES")
include(UseDoxygen)

if ( "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64" )
  set(LIBDIRNAME "lib64")
else ()
  set(LIBDIRNAME "lib")
endif ()

check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(stddef.h HAVE_STDDEF_H)
check_include_files(string.h HAVE_STRING_H)

include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src/include)

add_definitions(-g -O2)
if(CMAKE_COMPILER_IS_GNUCXX)
  add_definitions(-Wno-long-long -Wno-char-subscripts)
  add_definitions(-Wall -ansi -pedantic)
endif()

add_subdirectory(src)
add_subdirectory(test)

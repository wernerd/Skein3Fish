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

# necessary and required modules checked, ready to generate config.h
# configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# the following set(...) commands are only to have backward
# compatibility with autoconf stuff to generate the pc file
# set(prefix ${CMAKE_INSTALL_PREFIX})
# set(exec_prefix ${prefix}/bin)
# set(libdir ${prefix}/lib)
# set(includedir ${prefix}/include)
# set(PACKAGE pkgconfig)
# configure_file(libzrtpcpp.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libzrtpcpp.pc @ONLY)

# configure_file(libzrtpcpp.spec.cmake ${CMAKE_CURRENT_BINARY_DIR}/libzrtpcpp.spec @ONLY)

include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src/include)

# include(SourceDistribution)
# src_distribution_init()
# add_src_dist_files(AUTHORS COPYING INSTALL NEWS README ChangeLog libzrtpcpp.pc.cmake config.h.cmake libzrtpcpp.spec.cmake)

add_definitions(-g -O2)
if(CMAKE_COMPILER_IS_GNUCXX)
  add_definitions(-Wno-long-long -Wno-char-subscripts)
  add_definitions(-Wall -ansi -pedantic)
endif()

add_subdirectory(src)
add_subdirectory(test)
# add_src_dist_dirs(src)

########### install files ###############
# install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libzrtpcpp.pc DESTINATION ${LIBDIRNAME}/pkgconfig)

########### Add uninstall target ###############
# configure_file(
#   "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
#   "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
#    IMMEDIATE @ONLY)
# add_custom_target(uninstall
#   "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake") 

####### define target to build RPM 
# include(UseRPMTools)
# if(RPMTools_FOUND)
#   RPMTools_ADD_RPM_TARGETS(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/libzrtpcpp.spec.cmake)
# endif()

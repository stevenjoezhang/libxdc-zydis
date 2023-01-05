cmake_minimum_required(VERSION 3.0)

project(libxdc)

include_directories(./include)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast -finline-functions -flto")

aux_source_directory(${CMAKE_SOURCE_DIR}/src src_dir)
ADD_LIBRARY(libxdc STATIC ${src_dir})
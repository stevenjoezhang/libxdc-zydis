cmake_minimum_required(VERSION 3.12)

project(libxdc C)

include_directories(./include)

# Support windows and linux
if (CMAKE_HOST_WIN32)
	set(WINDOWS 1)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWIN32")
elseif (CMAKE_HOST_UNIX)
	set(LINUX 1)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLINUX")
endif()

if (WINDOWS)
	# set(CMAKE_C_FLAGS "-Ofast -finline-functions -flto -v /MD")
	# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast -finline-functions /MD")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -finline-functions /MD")	# for debug
elseif (LINUX)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -finline-functions -flto -fvisibility=hidden -fPIC")
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast")
endif()

# for optimize executable size
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections")
set(CMAKE_LD_FLAGS "${CMAKE_LD_FLAGS} -Wl,--gc-sections")

aux_source_directory(${CMAKE_SOURCE_DIR}/src src_dir)

ADD_LIBRARY(libxdc STATIC ${src_dir})

install(TARGETS libxdc
		ARCHIVE DESTINATION ${CMAKE_SOURCE_DIR}
 		LIBRARY DESTINATION ${CMAKE_SOURCE_DIR})
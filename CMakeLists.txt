cmake_minimum_required(VERSION 3.12)

project(libxdc C)

include_directories(./include)

# Support windows and linux
if (CMAKE_HOST_WIN32)
	# Must build with clang (GNU CLI)
	set(WINDOWS 1)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWIN32 -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE -D_SCL_SECURE_NO_WARNINGS -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS")
elseif (CMAKE_HOST_UNIX)
	set(LINUX 1)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLINUX")
endif()

if (WINDOWS)
	# set(CMAKE_C_FLAGS "-Ofast -finline-functions -flto -v /MD")
	# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast -finline-functions /MD")
	# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -finline-functions /MD")	# for debug
	# check compiler, must be clang
	if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
		message(FATAL_ERROR "Must use clang to compile")
	endif()
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -finline-functions -flto -Ofast")
elseif (LINUX)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -finline-functions -flto -fvisibility=hidden -fPIC")
	# for optimize executable size
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections")
	set(CMAKE_LD_FLAGS "${CMAKE_LD_FLAGS} -Wl,--gc-sections")
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
	elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast")
	endif()
endif()


aux_source_directory(${CMAKE_SOURCE_DIR}/src src_dir)

set (HEADERS ${CMAKE_SOURCE_DIR}/libxdc.h)
ADD_LIBRARY(xdc STATIC ${src_dir} ${HEADERS})

target_include_directories(xdc PUBLIC "C:/Program Files (x86)/capstone/include")

set_target_properties(xdc PROPERTIES PUBLIC_HEADER ${HEADERS})

install(TARGETS xdc
		ARCHIVE DESTINATION ${CMAKE_SOURCE_DIR}
 		LIBRARY DESTINATION ${CMAKE_SOURCE_DIR}
		PUBLIC_HEADER DESTINATION /usr/include)
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
	# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG_TRACES")
elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast")
endif()

# for optimize executable size
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections")
set(CMAKE_LD_FLAGS "${CMAKE_LD_FLAGS} -Wl,--gc-sections")

aux_source_directory(${CMAKE_SOURCE_DIR}/src src_dir)

set (HEADERS ${CMAKE_SOURCE_DIR}/libxdc.h)
ADD_LIBRARY(xdc STATIC ${src_dir} ${HEADERS})
ADD_LIBRARY(xdc_shared SHARED ${src_dir} ${HEADERS})

set_target_properties(xdc PROPERTIES PUBLIC_HEADER ${HEADERS})

set_target_properties(xdc_shared PROPERTIES OUTPUT_NAME "xdc")

install(TARGETS xdc
		ARCHIVE DESTINATION ${CMAKE_SOURCE_DIR}
 		LIBRARY DESTINATION ${CMAKE_SOURCE_DIR}
		PUBLIC_HEADER DESTINATION /usr/include)

install(TARGETS xdc
		ARCHIVE DESTINATION /usr/local/lib
 		LIBRARY DESTINATION /usr/local/lib)

install(TARGETS xdc_shared
		ARCHIVE DESTINATION /usr/local/lib
 		LIBRARY DESTINATION /usr/local/lib)
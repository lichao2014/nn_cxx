cmake_minimum_required(VERSION 2.8)

project(xtest)

set(CMAKE_CXX_STANDARD 17)

option(USE_STATIC_LINK "MT" OFF)

if (${USE_STATIC_LINK})
	set(FLAGS_LIST CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE)

	foreach(FLAGS ${FLAGS_LIST})
		if (${FLAGS} MATCHES "/MD")
			string(REPLACE "/MD" "/MT" ${FLAGS} ${${FLAGS}})
		endif()
	endforeach()
endif()

include_directories(
	D:/third_party/nanomsg-1.1.4/src)

link_directories(
	D:/third_party/nanomsg-1.1.4/build)

add_executable(xtest xtest.cc nn_cxx.h)
target_link_libraries(xtest nanomsg)
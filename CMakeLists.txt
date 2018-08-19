cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_STANDARD 17)

option(USE_STATIC_LINK "MT option" ON)
option(USE_TEST "test option" ON)

project(xtest)

if (${USE_STATIC_LINK})
	set(FLAGS_LIST CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE)

	foreach(FLAGS ${FLAGS_LIST})
		if (${FLAGS} MATCHES "/MD")
			string(REPLACE "/MD" "/MT" ${FLAGS} ${${FLAGS}})
		endif()
	endforeach()

	message(STATUS "use MT option")
endif()

include_directories(
	D:/third_party/nanomsg-1.1.4/src)

link_directories(
	D:/third_party/nanomsg-1.1.4/build
	D:/third_party/googletest-release-1.8.0/googletest/build)

add_executable(xtest xtest.cc nn_cxx.h)
target_link_libraries(xtest nanomsg)

if (${USE_TEST})
	add_executable(nn_cxx_test nn_cxx_test.cc nn_cxx.h)
	target_include_directories(nn_cxx_test PRIVATE "D:/third_party/googletest-release-1.8.0/googletest/include")
	target_link_libraries(nn_cxx_test nanomsg gtest)
endif()
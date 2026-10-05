cmake_minimum_required(VERSION 3.16)
project(ProtocolFlowEngine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PF_BUILD_TESTS "Build tests" ON)

add_library(pf_core INTERFACE)
target_include_directories(pf_core INTERFACE core/include)

file(GLOB PF_CORE_SRCS CONFIGURE_DEPENDS core/src/*.cpp)

if(PF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

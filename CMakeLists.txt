cmake_minimum_required(VERSION 3.3)
project(DNS)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp base/dns.cpp base/util.cpp)
INCLUDE_DIRECTORIES(include)
add_executable(DNS ${SOURCE_FILES})
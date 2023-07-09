cmake_minimum_required(VERSION 3.6)
project(rsa)

set(CMAKE_CXX_STANDARD 11)

include_directories(lib)

add_executable(main
    src/main.cpp
)


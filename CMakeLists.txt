cmake_minimum_required(VERSION 3.17)
project(MD5)

set(CMAKE_CXX_STANDARD 14)

add_executable(MD5 main.cpp md5.cpp md5.h md5_loc.h)
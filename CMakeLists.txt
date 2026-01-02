cmake_minimum_required(VERSION 4.1)
project(Cat_and_mouse C)

set(CMAKE_C_STANDARD 23)

add_library(Cat_and_mouse SHARED library.c)

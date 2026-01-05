cmake_minimum_required(VERSION 4.1)
project(Cat_and_mouse C)

set(CMAKE_C_STANDARD 23)
add_library(Troj SHARED library.c Darkest_Troj.c Darkest_Troj.h updater.h)
add_library(Loader SHARED library.c Darkest_load.c Darkest_load.h)
add_library(Payload SHARED library.c Darkest_pay.c Darkest_pay.h
        Darkest_pay.h)
add_executable(Main main.c)

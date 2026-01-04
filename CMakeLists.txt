cmake_minimum_required(VERSION 4.1)
project(Cat_and_mouse C)

set(CMAKE_C_STANDARD 23)

add_library(Cat_and_mouse SHARED library.c Darkest_loader.c Darkest_loader.h)
add_library(Cat_and_mouse_updater SHARED library.c Darkest_updater.c Darkest_updater.h)

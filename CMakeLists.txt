cmake_minimum_required(VERSION 4.1)
project(Cat_and_mouse C)

set(CMAKE_C_STANDARD 23)
add_library(Troj SHARED ntlib.c library.c Darkest_Troj.c Darkest_Troj.h)
add_library(Loader SHARED ntlib.c library.c Darkest_load.c Darkest_load.h)
add_library(Payload SHARED ntlib.c library.c Darkest_pay.c Darkest_pay.h Darkest_pay.h)
add_executable(Main main.c ntlib.c)

target_compile_options(Payload PRIVATE $<$<CONFIG:Release>:/GS- /Os /GL /Gy /Oi>)
target_link_options(Payload PRIVATE $<$<CONFIG:Release>:/NODEFAULTLIB /ENTRY:DllMain /OPT:REF /OPT:ICF /ALIGN:512 /MERGE:.rdata=.text>)
target_link_libraries(Payload PRIVATE kernel32.lib ntdll.lib advapi32.lib)

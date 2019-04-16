cmake_minimum_required(VERSION 3.13)
project(stubborn)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static -lpthread")

#set(CMAKE_RC_COMPILER_INIT windres)
#ENABLE_LANGUAGE(RC)
#set(CMAKE_RC_COMPILE_OBJECT "windres HelloWorld.rc HelloWorld.o")

add_executable(stubborn main.cpp HelloWorld.rc WinInternals.h resource.h)
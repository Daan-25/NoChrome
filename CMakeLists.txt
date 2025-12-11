cmake_minimum_required(VERSION 3.21)
project(NoChrome LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(HOMEBREW_PREFIX "/opt/homebrew")

# OpenSSL (Homebrew)
set(OPENSSL_ROOT_DIR "${HOMEBREW_PREFIX}/opt/openssl@3")
find_package(OpenSSL REQUIRED)


# SDL2 include
find_path(SDL2_INCLUDE_DIR
    NAMES SDL.h
    PATHS "${HOMEBREW_PREFIX}/include"
    PATH_SUFFIXES SDL2
    REQUIRED
)

# SDL2 lib
find_library(SDL2_LIBRARY
    NAMES SDL2
    PATHS "${HOMEBREW_PREFIX}/lib"
    REQUIRED
)

# SDL2_ttf include
find_path(SDL2TTF_INCLUDE_DIR
    NAMES SDL_ttf.h
    PATHS "${HOMEBREW_PREFIX}/include"
    PATH_SUFFIXES SDL2
    REQUIRED
)

# SDL2_ttf lib
find_library(SDL2TTF_LIBRARY
    NAMES SDL2_ttf
    PATHS "${HOMEBREW_PREFIX}/lib"
    REQUIRED
)

add_executable(NoChrome main.cpp)

target_include_directories(NoChrome PRIVATE
    ${SDL2_INCLUDE_DIR}
    ${SDL2TTF_INCLUDE_DIR}
)

target_link_libraries(NoChrome PRIVATE
    ${SDL2_LIBRARY}
    ${SDL2TTF_LIBRARY}
    OpenSSL::SSL
    OpenSSL::Crypto
)
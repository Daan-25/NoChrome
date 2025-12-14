cmake_minimum_required(VERSION 3.20)
project(NoChrome LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)

pkg_check_modules(SDL2 REQUIRED sdl2)
pkg_check_modules(SDL2_TTF REQUIRED SDL2_ttf)
pkg_check_modules(SDL2_IMAGE REQUIRED SDL2_image)

find_package(OpenSSL REQUIRED)

add_executable(NoChrome main.cpp)

target_include_directories(NoChrome PRIVATE
  ${SDL2_INCLUDE_DIRS}
  ${SDL2_TTF_INCLUDE_DIRS}
  ${SDL2_IMAGE_INCLUDE_DIRS}
)

target_link_directories(NoChrome PRIVATE
  ${SDL2_LIBRARY_DIRS}
  ${SDL2_TTF_LIBRARY_DIRS}
  ${SDL2_IMAGE_LIBRARY_DIRS}
)

target_compile_options(NoChrome PRIVATE
  ${SDL2_CFLAGS_OTHER}
  ${SDL2_TTF_CFLAGS_OTHER}
  ${SDL2_IMAGE_CFLAGS_OTHER}
)

target_link_libraries(NoChrome PRIVATE
  ${SDL2_LIBRARIES}
  ${SDL2_TTF_LIBRARIES}
  ${SDL2_IMAGE_LIBRARIES}
  OpenSSL::SSL
  OpenSSL::Crypto
)
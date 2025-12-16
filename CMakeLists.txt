cmake_minimum_required(VERSION 3.20)
project(NoChrome LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Homebrew default prefix on Apple Silicon
if(APPLE AND EXISTS "/opt/homebrew")
  list(PREPEND CMAKE_PREFIX_PATH "/opt/homebrew")
endif()

find_package(PkgConfig REQUIRED)

# SDL dependencies via pkg-config
pkg_check_modules(SDL2 REQUIRED sdl2)
pkg_check_modules(SDL2_TTF REQUIRED SDL2_ttf)
pkg_check_modules(SDL2_IMAGE REQUIRED SDL2_image)

find_package(OpenSSL REQUIRED)

option(NOCHROME_ENABLE_JS "Enable JavaScript support" ON)

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

if(NOCHROME_ENABLE_JS)
  target_compile_definitions(NoChrome PRIVATE NOCHROME_ENABLE_JS=1)

  if(APPLE)
    # Use Apple's built-in JavaScript engine (JavaScriptCore framework)
    find_library(JAVASCRIPTCORE_FRAMEWORK JavaScriptCore REQUIRED)
    target_link_libraries(NoChrome PRIVATE ${JAVASCRIPTCORE_FRAMEWORK})
  else()
    # Non-macOS: embed QuickJS (requires headers + libquickjs).
    # If your distro doesn't ship libquickjs, build QuickJS from source and point CMake to it:
    #   -DQUICKJS_INCLUDE_DIR=/path/include -DQUICKJS_LIBRARY=/path/libquickjs.a
    find_path(QUICKJS_INCLUDE_DIR quickjs.h)
    find_library(QUICKJS_LIBRARY NAMES quickjs libquickjs)

    if(NOT (QUICKJS_INCLUDE_DIR AND QUICKJS_LIBRARY))
      message(FATAL_ERROR
        "QuickJS not found on this platform. Provide -DQUICKJS_INCLUDE_DIR and -DQUICKJS_LIBRARY.")
    endif()

    target_include_directories(NoChrome PRIVATE ${QUICKJS_INCLUDE_DIR})
    target_link_libraries(NoChrome PRIVATE ${QUICKJS_LIBRARY})

    if(UNIX AND NOT APPLE)
      target_link_libraries(NoChrome PRIVATE m dl pthread)
    endif()
  endif()
endif()

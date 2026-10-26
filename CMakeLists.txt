cmake_minimum_required(VERSION 3.16)
project(mc5_offline CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wno-unused-parameter)

find_package(Threads REQUIRED)

# The Federation server: one source tree used by the desktop host now and the
# embedded .so later.
add_library(mc5server STATIC
  server/core/http.cpp
  server/core/server.cpp
  server/services/services.cpp
  server/services/eve.cpp
  server/services/pandora.cpp
  server/services/auth.cpp
  server/services/misc.cpp
)
target_include_directories(mc5server PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(mc5server PUBLIC Threads::Threads)

# Desktop standalone host (dev loop, LAN/VPS host later).
add_executable(mc5-offline-standalone hosts/standalone/main.cpp)
target_link_libraries(mc5-offline-standalone PRIVATE mc5server)

enable_testing()
add_executable(test_json tests/test_json.cpp)
add_executable(test_router tests/test_router.cpp)
target_link_libraries(test_router PRIVATE mc5server)
add_test(NAME json COMMAND test_json)
add_test(NAME router COMMAND test_router)

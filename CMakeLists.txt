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

# GOT/PLT hook engine (generic Linux; unit-tested on the host, used by the .so).
add_library(mc5hook STATIC hosts/embedded/gothook.cpp)
target_include_directories(mc5hook PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(mc5hook PUBLIC ${CMAKE_DL_LIBS})

if(ANDROID)
  # TLS for the loopback listener: mbedTLS, vendored under third_party/mbedtls
  # (fetched + sha256-verified by scripts/build-android.sh if absent).
  if(NOT EXISTS ${CMAKE_SOURCE_DIR}/third_party/mbedtls/CMakeLists.txt)
    message(FATAL_ERROR "third_party/mbedtls missing — run scripts/build-android.sh (it fetches it) or see docs/DEV-LOOP.md")
  endif()
  if(NOT EXISTS ${CMAKE_SOURCE_DIR}/hosts/embedded/tls_cert.hpp)
    message(FATAL_ERROR "hosts/embedded/tls_cert.hpp missing — run scripts/build-android.sh (it generates the loopback TLS cert)")
  endif()
  set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
  set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
  add_subdirectory(third_party/mbedtls EXCLUDE_FROM_ALL)

  # Embedded build: libmc5offline.so, loaded inside the game process. Same server
  # tree, plus the JNI/C bootstrap, diagnostics and TLS. Links liblog + libandroid.
  add_library(mc5offline SHARED hosts/embedded/bootstrap.cpp hosts/embedded/redirect.cpp hosts/embedded/patch.cpp hosts/embedded/diag.cpp hosts/embedded/tls.cpp)
  target_link_libraries(mc5offline PRIVATE mc5server mc5hook mbedtls mbedx509 mbedcrypto log android)
  # Keep the C/JNI entry points; strip the rest (incl. mbedTLS) for a small library.
  target_link_options(mc5offline PRIVATE -Wl,--exclude-libs,ALL)
else()
  # Desktop standalone host (dev loop, LAN/VPS host later).
  add_executable(mc5-offline-standalone hosts/standalone/main.cpp)
  target_link_libraries(mc5-offline-standalone PRIVATE mc5server)
endif()

if(NOT ANDROID)
  enable_testing()
  add_executable(test_json tests/test_json.cpp)
  add_executable(test_router tests/test_router.cpp)
  target_link_libraries(test_router PRIVATE mc5server)

  # Victim library + GOT-hook test.
  add_library(victim MODULE tests/victim.cpp)
  set_target_properties(victim PROPERTIES PREFIX "lib")
  target_link_options(victim PRIVATE -Wl,-z,now)
  add_executable(test_gothook tests/test_gothook.cpp)
  target_link_libraries(test_gothook PRIVATE mc5hook ${CMAKE_DL_LIBS})
  target_compile_definitions(test_gothook PRIVATE VICTIM_PATH="$<TARGET_FILE:victim>")
  add_dependencies(test_gothook victim)

  # Diagnostics crash reporter (diag.cpp is portable Linux; tested on the host).
  add_executable(test_diag tests/test_diag.cpp hosts/embedded/diag.cpp)
  target_include_directories(test_diag PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(test_diag PRIVATE Threads::Threads)

  add_test(NAME json COMMAND test_json)
  add_test(NAME router COMMAND test_router)
  add_test(NAME gothook COMMAND test_gothook)
  add_test(NAME diag COMMAND test_diag)
endif()

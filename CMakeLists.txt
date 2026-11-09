cmake_minimum_required(VERSION 3.18)
project(CLIPasswordManager CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(PWM_STATIC "Link the program statically" OFF)
option(PWM_SANITIZE "Build with address and undefined behaviour sanitizers" OFF)

if(PWM_STATIC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
endif()
find_path(CRYPTOPP_INCLUDE_DIR cryptopp/aes.h REQUIRED)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp crypto++ REQUIRED)

add_compile_options(-Wall -Wextra -Wpedantic)
if(PWM_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

add_library(vault STATIC src/Vault.cpp)
target_include_directories(vault PUBLIC src)
target_include_directories(vault SYSTEM PUBLIC ${CRYPTOPP_INCLUDE_DIR})
target_link_libraries(vault PUBLIC ${CRYPTOPP_LIBRARY})

add_library(ui STATIC src/Ui.cpp src/Strength.cpp)
target_include_directories(ui PUBLIC src)

add_executable(password-manager src/main.cpp src/Terminal.cpp)
target_link_libraries(password-manager PRIVATE vault ui)
if(PWM_STATIC)
    target_link_options(password-manager PRIVATE -static)
endif()

enable_testing()
add_executable(vault-tests tests/VaultTest.cpp)
target_link_libraries(vault-tests PRIVATE vault ui)
add_test(NAME vault-tests COMMAND vault-tests)

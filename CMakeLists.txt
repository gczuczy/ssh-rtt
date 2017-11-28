cmake_minimum_required(VERSION 2.6)
project(ssh-rtt)
add_executable(ssh-rtt main.cc)

# libraries
find_library(LIB_SSH2 ssh2)
find_file(INC_SSH2 libssh2.h PATHS /usr/local/include )
if(NOT LIB_SSH2)
message(FATAL_ERROR "libssh2 not found")
endif()
if(NOT INC_SSH2)
message(FATAL_ERROR "libssh2.h not found ")
endif()
message(STATUS "ssh2 found: " ${LIB_SSH2} ", " ${INC_SSH2})
include_directories(${INC_SSH2})

target_link_libraries(ssh-rtt ${LIB_SSH2})

install (TARGETS ssh-rtt DESTINATION bin)

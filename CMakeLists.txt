cmake_minimum_required(VERSION 3.5)
project(ssh-rtt)
add_executable(ssh-rtt main.cc)

# we need to set c++11
if(CMAKE_COMPILER_IS_GNUCXX)
  list(APPEND CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS} -Wall")
endif()

target_link_libraries(ssh-rtt ${LIB_SSH2})

install (TARGETS ssh-rtt DESTINATION bin)

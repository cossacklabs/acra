cmake_minimum_required(VERSION 3.12)
project(cpp)

set(CMAKE_CXX_STANDARD 14)

add_executable(cpp main.cpp)


#file(GLOB THEMISPP_SOURCE themispp/*.hpp)
#add_library(themispp ${THEMISPP_SOURCE})
target_link_libraries(cpp themis crypto)
#set_target_properties(themispp PROPERTIES LINKER_LANGUAGE CXX)
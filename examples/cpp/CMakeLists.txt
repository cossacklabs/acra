cmake_minimum_required(VERSION 3.12)
project(acrawriter_cpp)
set(CMAKE_CXX_STANDARD 14)

set(ACRAWRITER ../../wrappers/cpp)

include_directories(${ACRAWRITER})

set(
    SOURCE_FILES
    ${ACRAWRITER}/acrawriter.hpp
    main.cpp
    )

add_executable(acrawriter_cpp ${SOURCE_FILES})
target_link_libraries(acrawriter_cpp themis crypto)

cmake_minimum_required(VERSION 3.12)
project(acrawriter_cpp_tests)
set(CMAKE_CXX_STANDARD 14)

set(ACRAWRITER ../../wrappers/cpp)
include_directories(${ACRAWRITER})

set(
        SOURCE_FILES
        ${ACRAWRITER}/acrawriter.hpp
        main_tests.cpp
)

add_executable(acrawriter_cpp_tests ${SOURCE_FILES})
target_link_libraries(acrawriter_cpp_tests themis crypto)
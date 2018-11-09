cmake_minimum_required(VERSION 3.12)
project(acrawriter_cpp)
set(CMAKE_CXX_STANDARD 14)

set(ACRAWRITER ../../wrappers/cpp)
include_directories(${ACRAWRITER})

set(LIBS libs)
include_directories(${LIBS})

set(
    SOURCE_FILES
    ${ACRAWRITER}/acrawriter.hpp
    ${LIBS}
    main.cpp
    )

add_executable(acrawriter_cpp ${SOURCE_FILES})
target_link_libraries(acrawriter_cpp themis crypto)

cmake_minimum_required(VERSION 3.12)
project(acrawriter_cpp_tests)
set(CMAKE_CXX_STANDARD 14)

set(ACRAWRITER ../../wrappers/cpp)
include_directories(${ACRAWRITER})

set(LIBS libs)
include_directories(${LIBS})

set(
        SOURCE_FILES
        ${ACRAWRITER}/acrawriter.hpp
        ${LIBS}
        main_tests.cpp
)

add_executable(acrawriter_cpp_tests ${SOURCE_FILES})
target_link_libraries(acrawriter_cpp_tests themis crypto)
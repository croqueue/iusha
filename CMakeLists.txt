cmake_minimum_required(VERSION 3.16)
project(libiusha VERSION 1.0.0 LANGUAGES C)

file(GLOB SRC_CODE ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

add_library(iusha SHARED ${SRC_CODE})

target_include_directories(iusha
    PUBLIC 
        $<INSTALL_INTERFACE:include>    
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/include
)

target_compile_options(iusha PRIVATE -Werror)
target_compile_features(iusha PRIVATE c_std_11)

include(CTest)

if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    add_subdirectory(tests)
endif()

enable_testing()

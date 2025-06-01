project(sharptwoth_tests LANGUAGES C)

file(GLOB TEST_SRC ${CMAKE_CURRENT_SOURCE_DIR}/test_*.c)

foreach(TEST_FILE ${TEST_SRC})
    get_filename_component(TEST_TARGET ${TEST_FILE} NAME_WLE)
    add_executable(${TEST_TARGET} ${TEST_FILE} ${CMAKE_CURRENT_SOURCE_DIR}/helpers.c)
    target_link_libraries(${TEST_TARGET} PRIVATE sharptwoth)

    target_include_directories(${TEST_TARGET}
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )
    target_include_directories(${TEST_TARGET}
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    add_test(NAME ${TEST_TARGET} COMMAND ${TEST_TARGET} WORKING_DIRECTORY ${UNIT_TEST_BIN_OUTPUT_DIR})

endforeach()

add_custom_command(TARGET test_sha1 PRE_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy_directory
                       ${CMAKE_CURRENT_SOURCE_DIR}/data/ $<TARGET_FILE_DIR:test_sha1>/data)


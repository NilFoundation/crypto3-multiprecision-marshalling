#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework filesystem log log_setup program_options thread system)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       ${Boost_LIBRARIES}

                       crypto3::multiprecision
                       ${CMAKE_WORKSPACE_NAME}::core)

macro(define_marshalling_test name)
    get_filename_component(name ${name} NAME)

    set(test_name "marshalling_${name}_test")

    set(additional_args "")
    if(ENABLE_JUNIT_TEST_OUTPUT)
        set(TEST_RESULTS_DIR "${CMAKE_CURRENT_BINARY_DIR}/junit_results")
        set(TEST_LOGS_DIR "${TEST_RESULTS_DIR}/logs")
        file(MAKE_DIRECTORY ${TEST_LOGS_DIR} ${TEST_REPORTS_DIR})

        set(additional_args "--log_format=JUNIT"
                            "--log_sink=${TEST_LOGS_DIR}/${test_name}.xml")
    endif()

    cm_test(NAME ${test_name} SOURCES ${name}.cpp ARGS ${additional_args})

    target_include_directories(marshalling_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(marshalling_${name}_test PROPERTIES
                          CXX_STANDARD 17
                          CXX_STANDARD_REQUIRED TRUE)

    if(TARGET Boost::unit_test_framework)
        get_target_property(target_type Boost::unit_test_framework TYPE)
        if(target_type STREQUAL "SHARED_LIB")
            target_compile_definitions(marshalling_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
        elseif(target_type STREQUAL "STATIC_LIB")

        endif()
    endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(marshalling_${name}_test PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(marshalling_${name}_test PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

endmacro()

set(TESTS_NAMES
    "integral"
    "integral_fixed_size_container"
    "integral_non_fixed_size_container"
    )

foreach(TEST_NAME ${TESTS_NAMES})
    define_marshalling_test(${TEST_NAME})
endforeach()

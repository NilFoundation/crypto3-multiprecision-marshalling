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

option(ENABLE_JUNIT_TESTS_OUTPUT "Enable JUnit output for tests" FALSE)
set(TEST_RESULTS_DIR "${CMAKE_BINARY_DIR}/junit_results" CACHE STRING "Directory to save test results in JUnit format")

macro(define_marshalling_test test)

    get_filename_component(name ${test} NAME)

    set(test_name "marshalling_${name}_test")

    set(additional_args "")
    if(ENABLE_JUNIT_TESTS_OUTPUT)
        set(LOGS_DIR "${TEST_RESULTS_DIR}/logs")
        set(REPORTS_DIR "${TEST_RESULTS_DIR}/reports")
        file(MAKE_DIRECTORY ${LOGS_DIR} ${REPORTS_DIR})

        set(additional_args "--log_format=JUNIT --log_sink=${LOGS_DIR}/${test_name}.xml --report_sink=${REPORTS_DIR}/${test_name}.xml")
    endif()

    cm_test(NAME marshalling_${name}_test SOURCES ${test}.cpp ARGS ${additional_args})


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
endmacro()

set(TESTS_NAMES
    "integral"
    "integral_fixed_size_container"
    "integral_non_fixed_size_container"
    )

foreach(TEST_NAME ${TESTS_NAMES})
    define_marshalling_test(${TEST_NAME})
endforeach()

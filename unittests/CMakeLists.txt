#file(GLOB COMMON_SOURCES "common/*.cpp")

find_package( Gperftools QUIET )
if( GPERFTOOLS_FOUND )
    message( STATUS "Found gperftools; compiling tests with TCMalloc")
    list( APPEND PLATFORM_SPECIFIC_LIBS tcmalloc )
endif()

add_subdirectory(contracts)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/contracts.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/include/contracts.hpp ESCAPE_QUOTES)

add_subdirectory(snapshots)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/snapshots.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/include/snapshots.hpp ESCAPE_QUOTES)

file(GLOB UNIT_TESTS "*.cpp")

add_executable( unit_test ${UNIT_TESTS} ${WASM_UNIT_TESTS} )
target_link_libraries( unit_test eosio_chain chainbase eosio_testing fc ${PLATFORM_SPECIFIC_LIBS} )

target_compile_options(unit_test PUBLIC -DDISABLE_EOSLIB_SERIALIZE)
target_include_directories( unit_test PUBLIC
                            ${CMAKE_SOURCE_DIR}/libraries/testing/include
                            ${CMAKE_SOURCE_DIR}/contracts
                            ${CMAKE_BINARY_DIR}/contracts
                            ${CMAKE_CURRENT_SOURCE_DIR}/contracts
                            ${CMAKE_CURRENT_BINARY_DIR}/contracts
                            ${CMAKE_CURRENT_BINARY_DIR}/include )

### MARK TEST SUITES FOR EXECUTION ###
foreach(TEST_SUITE ${UNIT_TESTS}) # create an independent target for each test suite
  execute_process(COMMAND bash -c "grep -E 'BOOST_AUTO_TEST_SUITE\\s*[(]' ${TEST_SUITE} | grep -vE '//.*BOOST_AUTO_TEST_SUITE\\s*[(]' | cut -d ')' -f 1 | cut -d '(' -f 2" OUTPUT_VARIABLE SUITE_NAME OUTPUT_STRIP_TRAILING_WHITESPACE) # get the test suite name from the *.cpp file
  if (NOT "" STREQUAL "${SUITE_NAME}") # ignore empty lines
    execute_process(COMMAND bash -c "echo ${SUITE_NAME} | sed -e 's/s$//' | sed -e 's/_test$//'" OUTPUT_VARIABLE TRIMMED_SUITE_NAME OUTPUT_STRIP_TRAILING_WHITESPACE) # trim "_test" or "_tests" from the end of ${SUITE_NAME}
    # to run unit_test with all log from blockchain displayed, put "--verbose" after "--", i.e. "unit_test -- --verbose"
    foreach(RUNTIME ${EOSIO_WASM_RUNTIMES})
      add_test(NAME ${TRIMMED_SUITE_NAME}_unit_test_${RUNTIME} COMMAND unit_test --run_test=${SUITE_NAME} --report_level=detailed --color_output --catch_system_errors=no -- --${RUNTIME})
      # build list of tests to run during coverage testing
      if(ctest_tests)
         string(APPEND ctest_tests "|")
      endif()
      string(APPEND ctest_tests ${TRIMMED_SUITE_NAME}_unit_test_$RUNTIME)
    endforeach()
  endif()
endforeach(TEST_SUITE)
set(ctest_tests "'${ctest_tests}' -j8") # surround test list string in apostrophies

# The following tests are known to take the longest, bump up their cost (priority) so that they'll run first
# even on fresh first time test runs before ctest auto-detects costs
foreach(RUNTIME ${EOSIO_WASM_RUNTIMES})
   set_tests_properties(api_unit_test_${RUNTIME} PROPERTIES COST 5000)
   set_tests_properties(wasm_unit_test_${RUNTIME} PROPERTIES COST 4000)
   set_tests_properties(delay_unit_test_${RUNTIME} PROPERTIES COST 3000)
endforeach()

### COVERAGE TESTING ###
if(ENABLE_COVERAGE_TESTING)

  set(Coverage_NAME ${PROJECT_NAME}_ut_coverage)

  if(NOT LCOV_PATH)
    message(FATAL_ERROR "lcov not found! Aborting...")
  endif() # NOT LCOV_PATH

  if(NOT LLVMCOV_PATH)
    message(FATAL_ERROR "llvm-cov not found! Aborting...")
  endif() # NOT LCOV_PATH

  if(NOT GENHTML_PATH)
    message(FATAL_ERROR "genhtml not found! Aborting...")
  endif() # NOT GENHTML_PATH

  # no spaces allowed within tests list
  set(ctest_tests 'unit_test_wabt|unit_test_wavm')
  set(ctest_exclude_tests '')

  # Setup target
  add_custom_target(${Coverage_NAME}

    # Cleanup lcov
    COMMAND ${LCOV_PATH} --directory . --zerocounters

    # Run tests
    COMMAND ./tools/ctestwrapper.sh -R ${ctest_tests} -E ${ctest_exclude_tests}

    COMMAND ${LCOV_PATH} --directory . --capture --gcov-tool ${CMAKE_SOURCE_DIR}/tools/llvm-gcov.sh --output-file ${Coverage_NAME}.info

    COMMAND ${LCOV_PATH} -remove ${Coverage_NAME}.info '*/boost/*' '/usr/lib/*' '/usr/include/*' '*/externals/*' '*/fc/*' '*/wasm-jit/*' --output-file ${Coverage_NAME}_filtered.info

    COMMAND ${GENHTML_PATH} -o ${Coverage_NAME} ${PROJECT_BINARY_DIR}/${Coverage_NAME}_filtered.info

    COMMAND if [ "$CI" != "true" ]\; then ${CMAKE_COMMAND} -E remove ${Coverage_NAME}.base ${Coverage_NAME}.info ${Coverage_NAME}_filtered.info ${Coverage_NAME}.total ${PROJECT_BINARY_DIR}/${Coverage_NAME}.info.cleaned ${PROJECT_BINARY_DIR}/${Coverage_NAME}_filtered.info.cleaned\; fi

    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    COMMENT "Resetting code coverage counters to zero. Processing code coverage counters and generating report. Report published in ./${Coverage_NAME}"
    )

  # Show info where to find the report
  add_custom_command(TARGET ${Coverage_NAME} POST_BUILD
    COMMAND ;
    COMMENT "Open ./${Coverage_NAME}/index.html in your browser to view the coverage report."
    )
endif()

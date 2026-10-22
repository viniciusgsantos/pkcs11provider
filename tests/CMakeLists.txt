add_executable(
    all_tests
    main.cpp
)

target_link_libraries(all_tests
    PRIVATE
        ${PROJECT_NAME}
        OpenSSL::Crypto
        GTest::gtest_main
)

set_target_properties(all_tests PROPERTIES 
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

include(GoogleTest)
gtest_discover_tests(all_tests)

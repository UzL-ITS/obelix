set(TEST_ARCH ${OBELIX_SUPPORTED_ARCH})

set(OBELIX_LIT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(OBELIX_LIT_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})

set(OBELIX_TEST_DEPS ${SANITIZER_COMMON_LIT_TEST_DEPS})

foreach(arch ${OBELIX_SUPPORTED_ARCH})
    set(SANITIZER_COMMON_TEST_TARGET_ARCH ${arch})
    get_test_cc_for_arch(${arch}
            SHADOWSTACK_TEST_TARGET_CC SHADOWSTACK_TEST_TARGET_CFLAGS)
    configure_lit_site_cfg(
            ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.py.in
            ${CMAKE_CURRENT_BINARY_DIR}/${arch}/lit.site.cfg.py)
    list(APPEND OBELIX_TESTSUITES ${CMAKE_CURRENT_BINARY_DIR}/${arch})
endforeach()

add_lit_testsuite(check-obelix "Running the Obelix tests"
        ${OBELIX_TESTSUITES}
        DEPENDS ${SANITIZER_COMMON_LIT_TEST_DEPS})
set_target_properties(check-obelix PROPERTIES FOLDER "Compiler-RT Misc")

configure_lit_site_cfg(
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.py.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg.py
  MAIN_CONFIG
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.cfg.py
  )

set(GOLLVM_TEST_DEPS llvm-goc)
list(APPEND GOLLVM_TEST_DEPS
  llvm-config
  llvm-readelf
  llvm-objcopy
  llvm-objdump
  llvm-dis
  llvm-mc
  FileCheck
  count
  not
)

add_lit_testsuite(check-gollvm-int "Running gollvm test suite"
  ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${GOLLVM_TEST_DEPS}
  )

add_custom_target(gollvm-test-depends DEPENDS ${GOLLVM_TEST_DEPS})
set_target_properties(gollvm-test-depends PROPERTIES FOLDER "gollvm tests")

add_lit_testsuites(LLD ${CMAKE_CURRENT_SOURCE_DIR}
  DEPENDS ${GOLLVM_TEST_DEPS}
  )

set_target_properties(check-gollvm-int PROPERTIES FOLDER "gollvm tests")


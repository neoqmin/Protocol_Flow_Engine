# Test layout (see tests/README.md):
#   unit/        per-Block unit tests          (label: unit)
#   flow/        Flow-level tests              (label: flow)
#   protocol/    interop with real OpenVPN     (label: protocol)
#   regression/  golden-vector replay          (label: regression)
#   performance/ benchmarks                    (label: performance)

add_library(pf_test_main STATIC support/test_main.cpp)
target_include_directories(pf_test_main PUBLIC support)
target_link_libraries(pf_test_main PUBLIC pf_core)

# Tests named *_openssl.cpp need the OpenSSL-backed provider; skipped when it is unavailable.
macro(pf_filter_openssl_tests var)
  if(NOT PF_HAVE_OPENSSL)
    list(FILTER ${var} EXCLUDE REGEX "_openssl\\.cpp$")
  endif()
endmacro()

# pf_add_test(<label> <name> <sources...>)
function(pf_add_test label name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE pf_test_main)
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES LABELS ${label})
endfunction()

file(GLOB UNIT_SRCS CONFIGURE_DEPENDS unit/test_*.cpp)
pf_filter_openssl_tests(UNIT_SRCS)
if(UNIT_SRCS)
  pf_add_test(unit pf_unit_tests ${UNIT_SRCS})
endif()

file(GLOB FLOW_SRCS CONFIGURE_DEPENDS flow/test_*.cpp)
pf_filter_openssl_tests(FLOW_SRCS)
if(FLOW_SRCS)
  pf_add_test(flow pf_flow_tests ${FLOW_SRCS})
  target_compile_definitions(pf_flow_tests PRIVATE
    GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/regression/golden")
endif()

file(GLOB REG_SRCS CONFIGURE_DEPENDS regression/test_*.cpp)
pf_filter_openssl_tests(REG_SRCS)
if(REG_SRCS)
  pf_add_test(regression pf_regression_tests ${REG_SRCS})
  target_compile_definitions(pf_regression_tests PRIVATE
    GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/regression/golden")
endif()

# Protocol tests need external OpenVPN binaries; opt-in only.
option(PF_PROTOCOL_TESTS "Enable OpenVPN interop tests" OFF)
if(PF_PROTOCOL_TESTS)
  file(GLOB PROTO_SRCS CONFIGURE_DEPENDS protocol/test_*.cpp)
  if(PROTO_SRCS)
    pf_add_test(protocol pf_protocol_tests ${PROTO_SRCS})
  endif()
endif()

# libFuzzer targets (Clang only): cmake -DPF_BUILD_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++
if(PF_BUILD_FUZZ)
  file(GLOB FUZZ_SRCS CONFIGURE_DEPENDS fuzz/fuzz_*.cpp)
  foreach(src ${FUZZ_SRCS})
    get_filename_component(name ${src} NAME_WE)
    add_executable(${name} ${src})
    target_link_libraries(${name} PRIVATE pf_core)
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()
endif()

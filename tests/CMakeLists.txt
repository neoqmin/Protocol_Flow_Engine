# Test layout (see tests/README.md):
#   unit/        per-Block unit tests          (label: unit)
#   flow/        Flow-level tests              (label: flow)
#   protocol/    interop with real OpenVPN     (label: protocol)
#   regression/  golden-vector replay          (label: regression)
#   performance/ benchmarks                    (label: performance)

add_library(pf_test_main STATIC support/test_main.cpp)
target_include_directories(pf_test_main PUBLIC support)
if(PF_HAVE_OPENSSL)
  target_sources(pf_test_main PRIVATE support/test_pki.cpp)   # run-time test PKI (no keys on disk)
endif()
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
  target_compile_definitions(pf_unit_tests PRIVATE GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/regression/golden")
endif()

# Platform (PAL) tests: real sockets on loopback, no root needed (Linux only; label: unit).
if(TARGET pf_platform_linux)
  file(GLOB PLATFORM_SRCS CONFIGURE_DEPENDS platform/test_*.cpp)
  if(PLATFORM_SRCS)
    pf_add_test(unit pf_platform_tests ${PLATFORM_SRCS})
    target_link_libraries(pf_platform_tests PRIVATE pf_platform_linux)
  endif()
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
if(PF_PROTOCOL_TESTS AND TARGET pf_connect)
  # pf_connect vs an unmodified OpenVPN 2.6 server in a network namespace. Needs root; exits 77 (skipped) otherwise.
  add_test(NAME pf_interop_openvpn
           COMMAND ${CMAKE_COMMAND} -E env PF_CONNECT=$<TARGET_FILE:pf_connect>
                   bash ${CMAKE_SOURCE_DIR}/tests/protocol/run_interop.sh)
  set_tests_properties(pf_interop_openvpn PROPERTIES LABELS protocol TIMEOUT 300 SKIP_RETURN_CODE 77 RESOURCE_LOCK pf_lab)
endif()
if(PF_PROTOCOL_TESTS AND TARGET pf_client)
  # A4: pf_client (UDP + real TUN device) pings through the tunnel to an unmodified OpenVPN 2.6 server. Needs root.
  # Shares the lab's fixed namespace/interface names with pf_interop_openvpn, hence the lock. The 1 hour soak is
  # opt-in: PF_ONLY=soak PF_SOAK_SECONDS=3700 (see the script header).
  add_test(NAME pf_tunnel_openvpn
           COMMAND ${CMAKE_COMMAND} -E env PF_CLIENT=$<TARGET_FILE:pf_client>
                   bash ${CMAKE_SOURCE_DIR}/tests/protocol/run_tunnel.sh)
  set_tests_properties(pf_tunnel_openvpn PROPERTIES LABELS protocol TIMEOUT 300 SKIP_RETURN_CODE 77 RESOURCE_LOCK pf_lab)
endif()
if(PF_PROTOCOL_TESTS AND TARGET pf_client)
  # Transports: UDP, TCP (renegotiation) and UDP silently blocked -> automatic TCP fallback.
  add_test(NAME pf_transport_tunnel_openvpn
           COMMAND ${CMAKE_COMMAND} -E env PF_CLIENT=$<TARGET_FILE:pf_client>
                   bash ${CMAKE_SOURCE_DIR}/tests/protocol/run_transport_tunnel.sh)
  set_tests_properties(pf_transport_tunnel_openvpn PROPERTIES LABELS protocol TIMEOUT 300 SKIP_RETURN_CODE 77 RESOURCE_LOCK pf_lab)
endif()
if(PF_PROTOCOL_TESTS)
  file(GLOB PROTO_SRCS CONFIGURE_DEPENDS protocol/test_*.cpp)
  if(PROTO_SRCS)
    pf_add_test(protocol pf_protocol_tests ${PROTO_SRCS})
  endif()
endif()

# Data-path micro benchmark (label: performance; informational, not pass/fail).
if(PF_HAVE_OPENSSL)
  add_executable(pf_bench_data_path performance/bench_data_path.cpp)
  target_link_libraries(pf_bench_data_path PRIVATE pf_core)
  add_test(NAME pf_bench_data_path COMMAND pf_bench_data_path)
  set_tests_properties(pf_bench_data_path PROPERTIES LABELS performance)
endif()
# Flow runner overhead with tracing off/on (label: performance; informational).
add_executable(pf_bench_flow_trace performance/bench_flow_trace.cpp)
target_link_libraries(pf_bench_flow_trace PRIVATE pf_core)
add_test(NAME pf_bench_flow_trace COMMAND pf_bench_flow_trace)
set_tests_properties(pf_bench_flow_trace PROPERTIES LABELS performance)

# libFuzzer targets (Clang only): cmake -DPF_BUILD_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++
if(PF_BUILD_FUZZ)
  file(GLOB FUZZ_SRCS CONFIGURE_DEPENDS fuzz/fuzz_*.cpp)
  foreach(src ${FUZZ_SRCS})
    get_filename_component(name ${src} NAME_WE)
    if(name STREQUAL "fuzz_tls_crypt" AND NOT PF_HAVE_OPENSSL)
      continue()
    endif()
    add_executable(${name} ${src})
    target_link_libraries(${name} PRIVATE pf_core)
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()
endif()

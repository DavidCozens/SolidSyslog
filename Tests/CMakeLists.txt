if(SOLIDSYSLOG_POSIX OR SOLIDSYSLOG_WINSOCK)
    add_subdirectory(Support)
endif()

if(SOLIDSYSLOG_POSIX OR (SOLIDSYSLOG_WINSOCK AND HAVE_WINDOWS_PLATFORM))
    add_subdirectory(Bdd/Targets)
endif()

# Each platform's unit tests follow that platform's own switch, so a lane which
# turns one off stops building its tests too. Unlike the platforms themselves,
# these DO need the upstream tree — they compile against the real lwip/*.h,
# FreeRTOS.h and ff.h — which is why the top-level CMakeLists demands a path for
# every selected platform when SOLIDSYSLOG_BUILD_TESTING is on.
#
# A devcontainer build sets no platform list, so both FreeRTOS networking stacks
# are selected from the environment and both stacks' tests build together — you
# can work on lwIP and Plus-TCP in one tree without reconfiguring. That has
# always been true by accident of the gating; say it out loud so a future change
# to platform selection cannot quietly halve the suite.
if(SOLIDSYSLOG_LWIPRAW AND SOLIDSYSLOG_PLUSTCP)
    message(STATUS "SolidSyslog tests: both FreeRTOS networking stacks selected — lwIP and Plus-TCP suites build together.")
endif()
if(SOLIDSYSLOG_FREERTOS)
    add_subdirectory(Support/FreeRtosFakes)
    add_subdirectory(FreeRtos)
endif()

if(SOLIDSYSLOG_FATFS)
    add_subdirectory(Support/FatFsFakes)
    add_subdirectory(FatFs)
endif()

if(SOLIDSYSLOG_PLUSFAT)
    add_subdirectory(Support/PlusFatFakes)
    add_subdirectory(PlusFat)
endif()

if(SOLIDSYSLOG_LWIPRAW)
    add_subdirectory(Lwip)
endif()

if(SOLIDSYSLOG_MBEDTLS)
    add_subdirectory(MbedTls)
    add_subdirectory(MbedTlsIntegration)
endif()

set(TEST_SOURCES
    SolidSyslogTest.cpp
    SolidSyslogPoolTest.cpp
    SolidSyslogTunablesTest.cpp
    SolidSyslogSwitchingSenderTest.cpp
    SolidSyslogMetaSdTest.cpp
    SolidSyslogTimeQualitySdTest.cpp
    SolidSyslogOriginSdTest.cpp
    SolidSyslogPassthroughBufferTest.cpp
    SolidSyslogCircularBufferTest.cpp
    SolidSyslogPoolAllocatorTest.cpp
    SolidSyslogNullBlockDeviceTest.cpp
    SolidSyslogNullBufferTest.cpp
    SolidSyslogNullDatagramTest.cpp
    SolidSyslogNullFileTest.cpp
    SolidSyslogNullResolverTest.cpp
    SolidSyslogNullStreamTest.cpp
    SolidSyslogNullMutexTest.cpp
    SolidSyslogNullSdTest.cpp
    SolidSyslogSdValueTest.cpp
    SolidSyslogSdElementTest.cpp
    SolidSyslogHeaderFieldTest.cpp
    SolidSyslogEndpointHostTest.cpp
    SolidSyslogNullSenderTest.cpp
    SolidSyslogNullStoreTest.cpp
    SolidSyslogNullSecurityPolicyTest.cpp
    SolidSyslogCrc16Test.cpp
    SolidSyslogTlsFingerprintTest.cpp
    SolidSyslogCrc16PolicyTest.cpp
    SolidSyslogPrivalTest.cpp
    SolidSyslogErrorTest.cpp
    SolidSyslogConfigLockTest.cpp
    SolidSyslogFormatterTest.cpp
    SolidSyslogTimestampFormatterTest.cpp
    SolidSyslogMessageFormatterTest.cpp
    SolidSyslogUdpPayloadTest.cpp
    Support/SyslogFieldParser.cpp
    BufferFakeTest.cpp
    AddressFake.c
    BufferFake.c
    MutexFake.c
    StoreFakeTest.cpp
    StoreFake.c
    SenderFakeTest.cpp
    SenderFake.c
    DatagramFake.c
    DatagramFakeTest.cpp
    StringFakeTest.cpp
    StringFake.c
    FileFakeTest.cpp
    FileFake.c
    StreamFakeTest.cpp
    StreamFake.c
    TestAssert.cpp
    SolidSyslogBlockStoreTest.cpp
    SolidSyslogBlockStoreDrainOrderingTest.cpp
    SolidSyslogBlockDeviceTest.cpp
    SolidSyslogFileBlockDeviceTest.cpp
    SolidSyslogBlockSequenceTest.cpp
    SolidSyslogBlockSequencePoolTest.cpp
    SolidSyslogRecordStorePoolTest.cpp
    main.cpp
)

if(MSVC)
    list(APPEND TEST_SOURCES Support/SafeStringWindows.c)
else()
    list(APPEND TEST_SOURCES Support/SafeStringStandard.c)
endif()

if(HAVE_ATOMIC_COUNTER)
    list(APPEND TEST_SOURCES
        SolidSyslogAtomicCounterContractTest.cpp
        SolidSyslogNullAtomicCounterTest.cpp
    )
endif()

# Pick exactly one AtomicCounter platform helper to whitebox-include the
# matching impl's .c. Prefer stdatomic when available; fall back to
# Windows Interlocked. Both flags can be true on MSVC 2022+; the elseif
# ensures only one helper is compiled, so there are no duplicate symbols.
if(SOLIDSYSLOG_STDATOMIC)
    list(APPEND TEST_SOURCES
        SolidSyslogStdAtomicCounterTestHelper.c
        SolidSyslogStdAtomicCounterPoolTest.cpp
    )
elseif(SOLIDSYSLOG_WINDOWS AND HAVE_WINDOWS_INTERLOCKED)
    list(APPEND TEST_SOURCES
        SolidSyslogWindowsAtomicCounterTestHelper.c
        SolidSyslogWindowsAtomicCounterPoolTest.cpp
    )
endif()

if(SOLIDSYSLOG_POSIX)
    list(APPEND TEST_SOURCES
        SolidSyslogPosixClockTest.cpp
        SolidSyslogPosixMessageQueueBufferTest.cpp
        SolidSyslogPosixMutexTest.cpp
        SolidSyslogPosixSleepTest.cpp
        SolidSyslogPosixSysUpTimeTest.cpp
        ClockFakeTest.cpp
        SolidSyslogUdpSenderTest.cpp
        SolidSyslogStreamSenderTest.cpp
        SolidSyslogPosixFileTest.cpp
        SolidSyslogBlockStorePosixTest.cpp
        SolidSyslogPosixAddressTest.cpp
        SolidSyslogPosixResolverTest.cpp
        SolidSyslogPosixDatagramTest.cpp
        SolidSyslogPosixTcpStreamTest.cpp
        MqFakeTest.cpp
        SocketFakeTest.cpp
    )
endif()

if(SOLIDSYSLOG_OPENSSL)
    list(APPEND TEST_SOURCES
        SolidSyslogOpenSslStreamTest.cpp
        SolidSyslogOpenSslStreamPoolTest.cpp
        SolidSyslogOpenSslHmacSha256PolicyTest.cpp
        SolidSyslogOpenSslAesGcmPolicyTest.cpp
        OpenSslFakeTest.cpp
        OpenSslCredentialsFake.c
        SolidSyslogOpenSslNullCredentialsTest.cpp
        SolidSyslogOpenSslPemFileCredentialsTest.cpp
    )
endif()

if(HAVE_WINDOWS_PLATFORM)
    list(APPEND TEST_SOURCES
        SolidSyslogWindowsClockTest.cpp
        SolidSyslogWindowsFileTest.cpp
        SolidSyslogWindowsHostnameTest.cpp
        SolidSyslogWindowsMutexTest.cpp
        SolidSyslogWindowsProcessIdTest.cpp
        SolidSyslogWindowsSleepTest.cpp
        SolidSyslogWindowsSysUpTimeTest.cpp
    )
endif()

if(SOLIDSYSLOG_WINSOCK)
    list(APPEND TEST_SOURCES
        WinsockFakeTest.cpp
        SolidSyslogWinsockAddressTest.cpp
        SolidSyslogWinsockResolverTest.cpp
        SolidSyslogWinsockDatagramTest.cpp
        SolidSyslogWinsockTcpStreamTest.cpp
    )
endif()

add_executable(${PROJECT_NAME}Tests ${TEST_SOURCES})

target_link_libraries(${PROJECT_NAME}Tests PRIVATE ${PROJECT_NAME} ErrorHandlerFake ConfigLockFake CppUTest CppUTestExt Threads::Threads)
target_include_directories(${PROJECT_NAME}Tests PRIVATE ${CMAKE_SOURCE_DIR}/Core/Source ${CMAKE_CURRENT_SOURCE_DIR}/Support)

if(SOLIDSYSLOG_STDATOMIC)
    target_include_directories(${PROJECT_NAME}Tests PRIVATE ${CMAKE_SOURCE_DIR}/Platform/StdAtomic/Source)
elseif(SOLIDSYSLOG_WINDOWS AND HAVE_WINDOWS_INTERLOCKED)
    target_include_directories(${PROJECT_NAME}Tests PRIVATE ${CMAKE_SOURCE_DIR}/Platform/Windows/Source)
endif()

# Drives the static_assert in SolidSyslogTunablesTest.cpp when a tunable-override
# preset is active. Default builds leave it undefined; the assertion compiles out.
if(DEFINED SOLIDSYSLOG_TEST_EXPECTED_MAX_MESSAGE_SIZE)
    target_compile_definitions(${PROJECT_NAME}Tests PRIVATE
        SOLIDSYSLOG_TEST_EXPECTED_MAX_MESSAGE_SIZE=${SOLIDSYSLOG_TEST_EXPECTED_MAX_MESSAGE_SIZE})
endif()

if(SOLIDSYSLOG_POSIX)
    target_link_libraries(${PROJECT_NAME}Tests PRIVATE PosixFakes)
    target_include_directories(${PROJECT_NAME}Tests PRIVATE ${CMAKE_SOURCE_DIR}/Platform/Posix/Source)
endif()

if(SOLIDSYSLOG_OPENSSL)
    target_link_libraries(${PROJECT_NAME}Tests PRIVATE OpenSslFakes)
endif()

if(HAVE_WINDOWS_PLATFORM OR SOLIDSYSLOG_WINSOCK)
    target_include_directories(${PROJECT_NAME}Tests PRIVATE ${CMAKE_SOURCE_DIR}/Platform/Windows/Source)
endif()

if(SOLIDSYSLOG_WINSOCK)
    target_link_libraries(${PROJECT_NAME}Tests PRIVATE WinsockFakes)
endif()


if(SOLIDSYSLOG_OPENSSL)
    add_subdirectory(OpenSslIntegration)
endif()

# Standard CppUTest console output via ctest -V
add_test(NAME ${PROJECT_NAME}Tests COMMAND ${PROJECT_NAME}Tests)

# JUnit XML output for CI and the VS Code test explorer.
# Uses a cmake script so test failures (non-zero exit) don't abort the target.
add_custom_target(junit
    COMMAND ${CMAKE_COMMAND}
        -DEXECUTABLE=$<TARGET_FILE:${PROJECT_NAME}Tests>
        -DDIR=${CMAKE_BINARY_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_junit.cmake
    DEPENDS ${PROJECT_NAME}Tests
    COMMENT "Running tests with JUnit XML output"
)

# Each registered executable runs through run_junit.cmake as a POST_BUILD step
# on the `junit` custom target, so its cpputest_<group>.xml lands in the build
# dir alongside SolidSyslogTests' output. CI's junit-* upload-artifact then
# picks them all up for the Quality Summary panel. The `if(TARGET ...)` guard
# keeps the list authoritative without duplicating the FREERTOS_KERNEL_PATH /
# FREERTOS_PLUS_TCP_PATH env-var guards that already gate the test
# executables' definition in Tests/FreeRtos/CMakeLists.txt — a missing target
# is silently skipped, so jobs running outside a FreeRTOS-aware container
# just run SolidSyslogTests as before.
function(register_junit_test test_target)
    add_custom_command(TARGET junit POST_BUILD
        COMMAND ${CMAKE_COMMAND}
            -DEXECUTABLE=$<TARGET_FILE:${test_target}>
            -DDIR=${CMAKE_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run_junit.cmake
        COMMENT "Running ${test_target} with JUnit XML output"
        VERBATIM
    )
    add_dependencies(junit ${test_target})
endfunction()

foreach(freertos_test_target IN ITEMS
    SolidSyslogFreeRtosMutexTest
    SolidSyslogFreeRtosSysUpTimeTest
    CmsdkUartTest
    SolidSyslogPlusTcpAddressTest
    SolidSyslogPlusTcpDatagramTest
    SolidSyslogPlusTcpTcpStreamTest
    SolidSyslogPlusTcpResolverTest
)
    if(TARGET ${freertos_test_target})
        register_junit_test(${freertos_test_target})
    endif()
endforeach()

foreach(fatfs_test_target IN ITEMS
    SolidSyslogFatFsFileTest
)
    if(TARGET ${fatfs_test_target})
        register_junit_test(${fatfs_test_target})
    endif()
endforeach()

foreach(plusfat_test_target IN ITEMS
    SolidSyslogPlusFatFileTest
)
    if(TARGET ${plusfat_test_target})
        register_junit_test(${plusfat_test_target})
    endif()
endforeach()

foreach(mbedtls_test_target IN ITEMS
    SolidSyslogMbedTlsStreamPoolTest
    SolidSyslogMbedTlsStreamTest
    MbedTlsIntegrationTests
)
    if(TARGET ${mbedtls_test_target})
        register_junit_test(${mbedtls_test_target})
    endif()
endforeach()

foreach(lwip_test_target IN ITEMS
    SolidSyslogLwipRawAddressTest
    SolidSyslogLwipRawResolverTest
    SolidSyslogLwipRawDatagramTest
)
    if(TARGET ${lwip_test_target})
        register_junit_test(${lwip_test_target})
    endif()
endforeach()

# Code coverage report using lcov/genhtml.
# Requires the coverage preset: cmake --preset coverage && cmake --build --preset coverage --target coverage
# lcov and genhtml must be installed (available in both container images).
if(COVERAGE)
    find_program(LCOV_EXECUTABLE lcov)
    find_program(GENHTML_EXECUTABLE genhtml)

    if(LCOV_EXECUTABLE AND GENHTML_EXECUTABLE)
        add_custom_target(coverage
            COMMAND ${LCOV_EXECUTABLE} --zerocounters --directory ${CMAKE_BINARY_DIR}
            COMMAND ${CMAKE_COMMAND}
                -DEXECUTABLE=$<TARGET_FILE:${PROJECT_NAME}Tests>
                -DDIR=${CMAKE_BINARY_DIR}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/run_junit.cmake
            COMMAND ${LCOV_EXECUTABLE} --capture --directory ${CMAKE_BINARY_DIR}
                --output-file ${CMAKE_BINARY_DIR}/coverage.info
                --rc branch_coverage=1
            COMMAND ${LCOV_EXECUTABLE} --extract ${CMAKE_BINARY_DIR}/coverage.info
                "${CMAKE_SOURCE_DIR}/Core/Source/*"
                "${CMAKE_SOURCE_DIR}/Platform/*/Source/*"
                --output-file ${CMAKE_BINARY_DIR}/coverage.filtered.info
                --rc branch_coverage=1
            COMMAND ${GENHTML_EXECUTABLE} ${CMAKE_BINARY_DIR}/coverage.filtered.info
                --output-directory ${CMAKE_BINARY_DIR}/coverage_report
                --branch-coverage
            DEPENDS ${PROJECT_NAME}Tests
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating coverage report in build/coverage/coverage_report/"
        )
    else()
        message(STATUS "lcov/genhtml not found — 'coverage' target unavailable (requires updated base image)")
    endif()
endif()

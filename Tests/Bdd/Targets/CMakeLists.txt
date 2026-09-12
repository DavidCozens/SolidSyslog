# Platform-agnostic tests always included.
set(BDD_TARGET_TEST_SOURCES
    BddTargetAppNameTest.cpp
    BddTargetCustomSdTest.cpp
    BddTargetErrorTextTest.cpp
    BddTargetIpsTest.cpp
    BddTargetLanguageTest.cpp
    BddTargetTlsConfigTest.cpp
    main.cpp
)

set(BDD_TARGET_PRODUCTION_SOURCES
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetAppName.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetCustomSd.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetErrorText.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetIps.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetLanguage.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetTlsConfig.c
)

set(BDD_TARGET_TEST_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common
    ${CMAKE_SOURCE_DIR}/Core/Source
)

if(SOLIDSYSLOG_POSIX)
    list(APPEND BDD_TARGET_TEST_SOURCES
        BddTargetCommandLineTest.cpp
        BddTargetInteractiveTest.cpp
        BddTargetServiceThreadTest.cpp
        BddTargetStderrErrorHandlerTest.cpp
        BddTargetSwitchConfigTest.cpp
    )
    list(APPEND BDD_TARGET_PRODUCTION_SOURCES
        ${CMAKE_SOURCE_DIR}/Bdd/Targets/Linux/BddTargetCommandLine.c
        ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetServiceThread.c
        ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetStderrErrorHandler.c
        ${CMAKE_SOURCE_DIR}/Bdd/Targets/Linux/BddTargetTcpConfig.c
        ${CMAKE_SOURCE_DIR}/Bdd/Targets/Linux/BddTargetUdpConfig.c
        ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetInteractive.c
        ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetSwitchConfig.c
    )
    list(APPEND BDD_TARGET_TEST_INCLUDE_DIRS
        ${CMAKE_SOURCE_DIR}/Bdd/Targets/Linux
    )
endif()

if(SOLIDSYSLOG_WINSOCK AND HAVE_WINDOWS_PLATFORM)
    list(APPEND BDD_TARGET_TEST_SOURCES
        BddTargetWindowsCommandLineTest.cpp
    )
    list(APPEND BDD_TARGET_PRODUCTION_SOURCES
        ${CMAKE_SOURCE_DIR}/Bdd/Targets/Windows/BddTargetWindowsCommandLine.c
    )
    list(APPEND BDD_TARGET_TEST_INCLUDE_DIRS
        ${CMAKE_SOURCE_DIR}/Bdd/Targets/Windows
    )
endif()

add_executable(BddTargetTests ${BDD_TARGET_TEST_SOURCES})

target_link_libraries(BddTargetTests PRIVATE ${PROJECT_NAME} CppUTest CppUTestExt Threads::Threads)

if(SOLIDSYSLOG_POSIX)
    target_link_libraries(BddTargetTests PRIVATE PosixFakes)
endif()

target_include_directories(BddTargetTests PRIVATE ${BDD_TARGET_TEST_INCLUDE_DIRS})

target_sources(BddTargetTests PRIVATE ${BDD_TARGET_PRODUCTION_SOURCES})

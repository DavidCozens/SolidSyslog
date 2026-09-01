set(SOURCES
    SolidSyslog.c
    SolidSyslogStatic.c
    SolidSyslogError.c
    SolidSyslogConfigLock.c
    SolidSyslogSwitchingSender.c
    SolidSyslogSwitchingSenderStatic.c
    SolidSyslogBuffer.c
    SolidSyslogFormatter.c
    SolidSyslogTimestampFormatter.c
    SolidSyslogMessageFormatter.c
    SolidSyslogMetaSd.c
    SolidSyslogMetaSdStatic.c
    SolidSyslogPassthroughBuffer.c
    SolidSyslogPassthroughBufferStatic.c
    SolidSyslogCircularBuffer.c
    SolidSyslogCircularBufferStatic.c
    SolidSyslogPoolAllocator.c
    SolidSyslogMutex.c
    SolidSyslogNullMutex.c
    SolidSyslogSender.c
    SolidSyslogSenderHealth.c
    SolidSyslogNullSender.c
    SolidSyslogStore.c
    SolidSyslogNullSd.c
    SolidSyslogNullStore.c
    SolidSyslogNullBuffer.c
    SolidSyslogNullBlockDevice.c
    SolidSyslogNullSecurityPolicy.c
    SolidSyslogCrc16.c
    SolidSyslogTlsFingerprint.c
    SolidSyslogCrc16Policy.c
    SolidSyslogStream.c
    SolidSyslogNullStream.c
    SolidSyslogStructuredData.c
    SolidSyslogSdValue.c
    SolidSyslogSdElement.c
    SolidSyslogHeaderField.c
    SolidSyslogEndpointHost.c
    SolidSyslogTimeQualitySd.c
    SolidSyslogTimeQualitySdStatic.c
    SolidSyslogOriginSd.c
    SolidSyslogOriginSdStatic.c
    SolidSyslogFile.c
    SolidSyslogNullFile.c
    SolidSyslogBlockStore.c
    SolidSyslogBlockStoreStatic.c
    SolidSyslogRecordStore.c
    SolidSyslogRecordStoreStatic.c
    SolidSyslogBlockSequence.c
    SolidSyslogBlockSequenceStatic.c
    SolidSyslogBlockDevice.c
    SolidSyslogFileBlockDevice.c
    SolidSyslogFileBlockDeviceStatic.c
    SolidSyslogUdpPayload.c
    SolidSyslogResolver.c
    SolidSyslogNullResolver.c
    SolidSyslogDatagram.c
    SolidSyslogNullDatagram.c
    SolidSyslogUdpSender.c
    SolidSyslogUdpSenderStatic.c
    SolidSyslogStreamSender.c
    SolidSyslogStreamSenderStatic.c
    SolidSyslogAtomicCounter.c
    SolidSyslogNullAtomicCounter.c
)
# Every source above includes Core headers and nothing else. They stay
# unconditional because an integrator reaching a role through its extension point
# — their own Stream, Sender or AtomicCounter — needs the dispatchers and Null
# objects whether or not they also took one of our platform implementations.

add_library(${PROJECT_NAME} STATIC ${SOURCES})

target_include_directories(${PROJECT_NAME}
    PUBLIC  ${SolidSyslog_SOURCE_DIR}/Core/Interface
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME} PUBLIC SolidSyslogTunables)

if(SOLIDSYSLOG_POSIX)
    target_link_libraries(${PROJECT_NAME} PUBLIC rt)
endif()

# Top-level only — see solidsyslog_install_public_headers() in the root
# CMakeLists for why a nested build installs nothing.
if(SOLIDSYSLOG_IS_TOP_LEVEL)
    include(GNUInstallDirs)

    install(TARGETS ${PROJECT_NAME}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )

    install(DIRECTORY ${SolidSyslog_SOURCE_DIR}/Core/Interface/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h"
    )
endif()

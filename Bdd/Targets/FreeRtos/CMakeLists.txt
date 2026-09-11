# FreeRTOS-Plus-TCP BDD target ELF for QEMU mps2-an385 (Cortex-M3).
#
# Compiled cross-only — gated by the top-level CMakeLists.txt on
# CMAKE_CROSSCOMPILING + CMAKE_SYSTEM_PROCESSOR == "arm".
#
# Wires SolidSyslogUdpSender behind the SolidSyslogPlusTcpDatagram adapter
# and the static resolver, with Bdd/Targets/Common/BddTargetInteractive
# driving `send N` / `quit` over the QEMU -serial stdio UART (CmsdkUart RX
# path).
#
# Source layout: upstream FreeRTOS-Kernel + Plus-TCP sources are compiled
# into a separate OBJECT library (`solid_syslog_freertos_upstream`) that
# accepts the relaxed warning set those headers / sources require. Local
# project code (main.c, Startup.c, Common/CmsdkUart.c, Common/Syscalls.c,
# the Platform/FreeRtos/Source adapters, and Bdd/Targets/Common/
# BddTargetInteractive.c) stays in the executable target under the strict
# project warning bar so regressions in our own code can't slip through.

set(FREERTOS_KERNEL_PATH "${SOLIDSYSLOG_FREERTOS_KERNEL_PATH}")
if(NOT FREERTOS_KERNEL_PATH)
    message(FATAL_ERROR
        "SOLIDSYSLOG_FREERTOS_KERNEL_PATH is empty (falls back to $FREERTOS_KERNEL_PATH). Use the cpputest-freertos-cross "
        "container, which sets this to /opt/freertos/kernel.")
endif()

set(FREERTOS_PLUS_TCP_PATH "${SOLIDSYSLOG_FREERTOS_PLUS_TCP_PATH}")
if(NOT FREERTOS_PLUS_TCP_PATH)
    message(FATAL_ERROR
        "SOLIDSYSLOG_FREERTOS_PLUS_TCP_PATH is empty (falls back to $FREERTOS_PLUS_TCP_PATH). Use the cpputest-freertos-cross "
        "container, which sets this to /opt/freertos/plus-tcp.")
endif()

set(FREERTOS_PLUS_FAT_PATH "${SOLIDSYSLOG_FREERTOS_PLUS_FAT_PATH}")
if(NOT FREERTOS_PLUS_FAT_PATH)
    message(FATAL_ERROR
        "SOLIDSYSLOG_FREERTOS_PLUS_FAT_PATH is empty (falls back to $FREERTOS_PLUS_FAT_PATH). Use the cpputest-freertos-cross "
        "container, which sets this to /opt/freertos/plus-fat.")
endif()

set(MBEDTLS_SOURCE_DIR "${SOLIDSYSLOG_MBEDTLS_DIR}")
if(NOT EXISTS "${MBEDTLS_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "SOLIDSYSLOG_MBEDTLS_DIR is empty or invalid (falls back to $MBEDTLS_DIR). Use the cpputest-freertos-cross "
        "container, which sets this to /opt/mbedtls.")
endif()

# No source staging for FreeRTOS-Plus-FAT (unlike ChaN-FatFs). ff_headers.h's
# `#include "FreeRTOSFATConfig.h"` finds no copy beside itself in
# ${FREERTOS_PLUS_FAT_PATH}/include, so GCC's `""` lookup falls through to the
# -I path, where our integrator FreeRTOSFATConfig.h (this directory) wins.

set(PLUS_FAT_SRC_DIR "${FREERTOS_PLUS_FAT_PATH}")

set(FREERTOS_PORT_DIR "${FREERTOS_KERNEL_PATH}/portable/GCC/ARM_CM3")

set(PLUS_TCP_SRC_DIR "${FREERTOS_PLUS_TCP_PATH}/source")
set(PLUS_TCP_PORT_GCC_DIR "${PLUS_TCP_SRC_DIR}/portable/Compiler/GCC")
set(PLUS_TCP_BUF_DIR "${PLUS_TCP_SRC_DIR}/portable/BufferManagement")
set(PLUS_TCP_NIF_DIR "${PLUS_TCP_SRC_DIR}/portable/NetworkInterface/MPS2_AN385")

# --- Upstream OBJECT library --------------------------------------------------
#
# Compiles all kernel + Plus-TCP + LAN9118 driver sources with the relaxed
# warning set. Marked PRIVATE on this library; the executable consumes the
# objects via $<TARGET_OBJECTS:...> so the relaxations don't leak.

add_library(solid_syslog_freertos_upstream OBJECT
    ${FREERTOS_KERNEL_PATH}/tasks.c
    ${FREERTOS_KERNEL_PATH}/queue.c
    ${FREERTOS_KERNEL_PATH}/list.c
    ${FREERTOS_KERNEL_PATH}/timers.c
    ${FREERTOS_KERNEL_PATH}/event_groups.c
    ${FREERTOS_PORT_DIR}/port.c
    ${FREERTOS_KERNEL_PATH}/portable/MemMang/heap_4.c
    # Plus-TCP core (UDP-only — see FreeRTOSIPConfig.h).
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_ARP.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_BitConfig.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_DHCP.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_DHCPv6.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_DNS.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_DNS_Cache.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_DNS_Callback.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_DNS_Networking.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_DNS_Parser.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_ICMP.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_IP.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_IP_Timers.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_IP_Utils.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_IPv4.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_IPv4_Sockets.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_IPv4_Utils.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_IPv6.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_IPv6_Sockets.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_IPv6_Utils.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_ND.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_RA.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_Routing.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_Sockets.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_Stream_Buffer.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_IP.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_IP_IPv4.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_IP_IPv6.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_Reception.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_State_Handling.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_State_Handling_IPv4.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_State_Handling_IPv6.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_Transmission.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_Transmission_IPv4.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_Transmission_IPv6.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_Utils.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_Utils_IPv4.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_Utils_IPv6.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_TCP_WIN.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_Tiny_TCP.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_UDP_IP.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_UDP_IPv4.c
    ${PLUS_TCP_SRC_DIR}/FreeRTOS_UDP_IPv6.c
    ${PLUS_TCP_BUF_DIR}/BufferAllocation_2.c
    # MPS2_AN385 LAN9118 NetworkInterface + driver.
    ${PLUS_TCP_NIF_DIR}/NetworkInterface.c
    ${PLUS_TCP_NIF_DIR}/ether_lan9118/smsc9220_eth_drv.c
    # FreeRTOS-Plus-FAT upstream core (SHA 8d38036). Like the FreeRTOS kernel
    # and Plus-TCP sources, these trip the relaxed warnings (sign-conversion,
    # shadow, type narrowing), so they live in this OBJECT lib. The integrator
    # FreeRTOSFATConfig.h is found off the -I path (CMAKE_CURRENT_SOURCE_DIR
    # below) — no source staging, see note above. The FF_Disk_t media driver
    # (FFSemihostingDisk.c) is OUR code and stays in the strict executable
    # target alongside the SolidSyslogPlusFatFile adapter.
    ${PLUS_FAT_SRC_DIR}/ff_crc.c
    ${PLUS_FAT_SRC_DIR}/ff_dir.c
    ${PLUS_FAT_SRC_DIR}/ff_error.c
    ${PLUS_FAT_SRC_DIR}/ff_fat.c
    ${PLUS_FAT_SRC_DIR}/ff_file.c
    ${PLUS_FAT_SRC_DIR}/ff_format.c
    ${PLUS_FAT_SRC_DIR}/ff_ioman.c
    ${PLUS_FAT_SRC_DIR}/ff_locking.c
    ${PLUS_FAT_SRC_DIR}/ff_memory.c
    ${PLUS_FAT_SRC_DIR}/ff_stdio.c
    ${PLUS_FAT_SRC_DIR}/ff_string.c
    ${PLUS_FAT_SRC_DIR}/ff_sys.c
    ${PLUS_FAT_SRC_DIR}/ff_time.c
)

target_compile_options(solid_syslog_freertos_upstream PRIVATE
    -mcpu=cortex-m3
    -mthumb
    -ffunction-sections
    -fdata-sections
    -fno-common
    # FreeRTOS-Kernel + Plus-TCP V11.1.0/V4.2.2 + Plus-FAT use non-prototype
    # function declarations, type-narrowing constructs, sign-conversion patterns,
    # and shadowed locals that trip our strict host warnings. Scoped to this
    # OBJECT library so the relaxations never reach project code.
    -Wno-unused-parameter
    -Wno-unused-but-set-variable
    -Wno-implicit-fallthrough
    -Wno-array-bounds
    -Wno-conversion
    -Wno-sign-conversion
    -Wno-shadow
    -Wno-pedantic
    # Plus-FAT's ff_fat.c emits `#warning Only maintaining one FAT table` when
    # built with a single FAT (our config: n_fat = 1, the intended layout). The
    # informational #warning would otherwise be promoted by -Werror.
    -Wno-cpp
)

target_include_directories(solid_syslog_freertos_upstream PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}                       # FreeRTOSConfig.h, FreeRTOSIPConfig.h
    ${FREERTOS_KERNEL_PATH}/include
    ${FREERTOS_PORT_DIR}                              # portmacro.h
    ${PLUS_TCP_SRC_DIR}/include
    ${PLUS_TCP_PORT_GCC_DIR}                          # pack_struct_*.h
    ${PLUS_TCP_NIF_DIR}                               # NetworkInterface.h consumed locally
    ${PLUS_TCP_NIF_DIR}/ether_lan9118                 # SMM_MPS2.h, smsc9220_*.h
    ${FREERTOS_PLUS_FAT_PATH}/include                 # ff_headers.h, ff_stdio.h, ff_ioman.h, …
)

# --- mbedTLS upstream as a subproject ----------------------------------------
#
# Same pattern as Tests/MbedTlsIntegration/CMakeLists.txt: bring mbedTLS in via
# add_subdirectory(EXCLUDE_FROM_ALL), force-disable its programs/tests, and
# strip our strict warning surface from the upstream targets so a future
# mbedTLS bump doesn't break our build for diagnostic reasons. clang-tidy /
# cppcheck are also disabled per-target — they would otherwise apply our
# .clang-tidy ruleset to upstream code.
set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable mbedTLS demo programs in our build" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "Disable mbedTLS upstream tests in our build" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "Upstream mbedTLS warnings are not errors in our build" FORCE)
add_subdirectory(${MBEDTLS_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/_mbedtls EXCLUDE_FROM_ALL)

# MBEDTLS_USER_CONFIG_FILE is consumed by mbedTLS's headers via `#include`,
# so the macro value must be a quoted C string literal. CMake-quote with
# `\"` to survive the shell -> compiler hop.
set(MBEDTLS_USER_CONFIG_HEADER
    "\"${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_user_config.h\""
)

foreach(_mbedtls_upstream_target IN ITEMS mbedtls mbedx509 mbedcrypto everest p256m)
    if(TARGET ${_mbedtls_upstream_target})
        target_compile_options(${_mbedtls_upstream_target} PRIVATE -w)
        target_compile_definitions(${_mbedtls_upstream_target} PRIVATE
            MBEDTLS_USER_CONFIG_FILE=${MBEDTLS_USER_CONFIG_HEADER}
        )
        set_target_properties(${_mbedtls_upstream_target} PROPERTIES
            C_CLANG_TIDY ""
            CXX_CLANG_TIDY ""
            C_CPPCHECK ""
            CXX_CPPCHECK ""
        )
    endif()
endforeach()

# --- Bake demo PEMs into the ELF -------------------------------------------
#
# QEMU has no path to the host filesystem, and the integrator config disables
# MBEDTLS_FS_IO, so the demo CA + client identity travel as `static const`
# arrays in rodata. xxd -i emits the array shape we want; mbedTLS's PEM parser
# additionally requires a NUL-terminated input, which the wrapper TU adds at
# parse time by copying into a +1-sized buffer (cheaper than a shell pipeline
# to append the NUL at bake time, and keeps this CMake step simple).

set(BAKED_PEMS_DIR "${CMAKE_CURRENT_BINARY_DIR}/baked_pems")
file(MAKE_DIRECTORY ${BAKED_PEMS_DIR})

function(bake_pem_into_header input_pem output_header symbol)
    add_custom_command(
        OUTPUT ${output_header}
        COMMAND bash -c "xxd -i -n '${symbol}' '${input_pem}' > '${output_header}'"
        DEPENDS ${input_pem}
        COMMENT "Baking ${input_pem} -> ${output_header}"
        VERBATIM
    )
endfunction()

bake_pem_into_header(
    ${CMAKE_SOURCE_DIR}/Bdd/syslog-ng/tls/ca.pem
    ${BAKED_PEMS_DIR}/BddBakedCaPem.h
    bdd_baked_ca_pem
)
# The authority a scenario rotates to, and the one that signs the certificates a
# peer-refusal cell expects to be refused. Baked like the rest: this target has
# no filesystem to read one from.
bake_pem_into_header(
    ${CMAKE_SOURCE_DIR}/Bdd/syslog-ng/tls/ca-b.pem
    ${BAKED_PEMS_DIR}/BddBakedCaBPem.h
    bdd_baked_ca_b_pem
)
bake_pem_into_header(
    ${CMAKE_SOURCE_DIR}/Bdd/syslog-ng/tls/client.pem
    ${BAKED_PEMS_DIR}/BddBakedClientCertPem.h
    bdd_baked_client_cert_pem
)
bake_pem_into_header(
    ${CMAKE_SOURCE_DIR}/Bdd/syslog-ng/tls/client.key
    ${BAKED_PEMS_DIR}/BddBakedClientKeyPem.h
    bdd_baked_client_key_pem
)

set(BAKED_PEM_HEADERS
    ${BAKED_PEMS_DIR}/BddBakedCaPem.h
    ${BAKED_PEMS_DIR}/BddBakedCaBPem.h
    ${BAKED_PEMS_DIR}/BddBakedClientCertPem.h
    ${BAKED_PEMS_DIR}/BddBakedClientKeyPem.h
)

# --- Executable ---------------------------------------------------------------
#
# Project code only. Inherits the full project warning set
# (-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Werror)
# from the top-level CMakeLists.txt — no -Wno-* relaxations here.

add_executable(SolidSyslogBddTarget
    main.c
    Startup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/CmsdkUart.c
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Syscalls.c
    # SolidSyslog platform adapters arrive via the SolidSyslog::{PlusTcp,FreeRtos,
    # MbedTls,PlusFat} pack umbrellas linked below (S30.02 dogfood) — their
    # target_sources(INTERFACE) compile here against this target's config.
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetErrorText.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetFreeRtosPipeline.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetCustomSd.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetInteractive.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetIps.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetLanguage.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetMtlsConfig.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetPlusFatMount.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetSwitchConfig.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetMbedTlsCredentials.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetTlsConfig.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetTlsSender_MbedTls_PlusTcpTcp.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/FFSemihostingDisk.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/SemihostingDisk.c
    ${BAKED_PEM_HEADERS}
    $<TARGET_OBJECTS:solid_syslog_freertos_upstream>
)

set_target_properties(SolidSyslogBddTarget PROPERTIES SUFFIX ".elf")

target_compile_options(SolidSyslogBddTarget PRIVATE
    -mcpu=cortex-m3
    -mthumb
    -ffunction-sections
    -fdata-sections
    -fno-common
)

target_include_directories(SolidSyslogBddTarget PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}                       # FreeRTOSConfig.h, FreeRTOSIPConfig.h
    ${CMAKE_CURRENT_SOURCE_DIR}/Common                # CmsdkUart.h
    ${CMAKE_SOURCE_DIR}/Core/Interface                # SolidSyslog*.h
    ${CMAKE_SOURCE_DIR}/Core/Source                   # internal headers consumed by adapters
    # Platform/{PlusFat,FreeRtos,PlusTcp,MbedTls}/{Interface,Source} include dirs
    # now arrive transitively from the SolidSyslog::* pack umbrellas linked below.
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common            # BddTargetInteractive.h
    ${BAKED_PEMS_DIR}                                 # BddBaked*.h (xxd -i output)
    ${FREERTOS_KERNEL_PATH}/include
    ${FREERTOS_PORT_DIR}                              # portmacro.h
    ${PLUS_TCP_SRC_DIR}/include
    ${PLUS_TCP_PORT_GCC_DIR}                          # pack_struct_*.h
    ${FREERTOS_PLUS_FAT_PATH}/include                 # ff_stdio.h (adapter) + ff_headers.h / ff_ioman.h /
                                                      # ff_format.h / ff_sys.h (FFSemihostingDisk.c). The
                                                      # integrator FreeRTOSFATConfig.h resolves to
                                                      # CMAKE_CURRENT_SOURCE_DIR above — same as the OBJECT lib,
                                                      # so the Plus-FAT core and our adapter/driver share one
                                                      # config across all translation units.
)

# FFSemihostingDisk.c drives the mount/format lifecycle via Plus-FAT's FF_isERR /
# FF_ERR_* macros, whose error codes carry the 0x80000000 FF_ERRFLAG bit and so
# are unsigned-with-high-bit — they cannot be made -Wsign-conversion clean at the
# call site. Relax only that one diagnostic for only this file; every other
# strict warning (and the rest of our code) is unaffected. The SolidSyslogPlusFatFile
# adapter needs no such relaxation — it uses the ff_stdio handle API, not the
# error-code macros.
set_source_files_properties(
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/FFSemihostingDisk.c
    PROPERTIES COMPILE_OPTIONS "-Wno-sign-conversion"
)

target_link_libraries(SolidSyslogBddTarget PRIVATE
    ${PROJECT_NAME}                                   # libSolidSyslog.a (cross-compiled)
    SolidSyslog::PlusTcp                              # Address/Datagram/Resolver/TcpStream adapters (sources)
    SolidSyslog::FreeRtos                             # Mutex + SysUpTime adapters (sources)
    SolidSyslog::MbedTls                              # TLS Stream + HMAC/AES-GCM policy adapters (sources)
    SolidSyslog::PlusFat                              # Plus-FAT file adapter (sources)
    mbedtls mbedx509 mbedcrypto                       # mbedTLS upstream (subproject, cross-compiled)
)

# Platform/MbedTls/Source/*.c include <mbedtls/ssl.h>; they MUST see the same
# user config as the mbedTLS library itself, otherwise struct sizes and the
# enabled-feature bitset diverge between the consumer and the library.
target_compile_definitions(SolidSyslogBddTarget PRIVATE
    MBEDTLS_USER_CONFIG_FILE=${MBEDTLS_USER_CONFIG_HEADER}
)

target_link_options(SolidSyslogBddTarget PRIVATE
    -mcpu=cortex-m3
    -mthumb
    -T${CMAKE_CURRENT_SOURCE_DIR}/Common/mps2-an385.ld
    --specs=nano.specs
    --specs=nosys.specs
    -Wl,--gc-sections
    -Wl,-Map=$<TARGET_FILE:SolidSyslogBddTarget>.map
)

set_target_properties(SolidSyslogBddTarget PROPERTIES
    LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Common/mps2-an385.ld)

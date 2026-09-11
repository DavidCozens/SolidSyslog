# FreeRTOS + lwIP (Raw API, NO_SYS=0) BDD target ELF for QEMU mps2-an385
# (Cortex-M3).
#
# S28.09: grew the S28.07 link-probe into a runnable BDD target — a real
# LAN9118 lwIP netif (netif/EthernetIf.c over the vendored Arm smsc9220
# driver), tcpip_init + a static IP, and the SolidSyslog UDP pipeline reaching
# the syslog-ng oracle on QEMU. Selected via SOLIDSYSLOG_BDD_FREERTOS_NET=LWIP,
# with zero dependency on Platform/PlusTcp / FreeRTOS-Plus-TCP.
#
# Source layout mirrors Bdd/Targets/FreeRtos/CMakeLists.txt: upstream
# FreeRTOS-Kernel + lwIP-core + lwIP-api + the contrib FreeRTOS sys_arch + the
# vendored LAN9118 driver compile into a separate OBJECT library
# (`solid_syslog_freertos_lwip_upstream`) under a relaxed warning set; our own
# code (main.c, the reused Cortex-M3 startup, netif/EthernetIf.c, the
# Platform/LwipRaw + Platform/FreeRtos adapters, and the shared BddTarget
# sources) stays in the executable under the strict project warning bar.

set(FREERTOS_KERNEL_PATH "${SOLIDSYSLOG_FREERTOS_KERNEL_PATH}")
if(NOT FREERTOS_KERNEL_PATH)
    message(FATAL_ERROR
        "SOLIDSYSLOG_FREERTOS_KERNEL_PATH is empty (falls back to $FREERTOS_KERNEL_PATH). Use the cpputest-freertos-cross "
        "container, which sets this to /opt/freertos/kernel.")
endif()

set(LWIP_DIR "${SOLIDSYSLOG_LWIP_PATH}")
if(NOT LWIP_DIR)
    message(FATAL_ERROR
        "SOLIDSYSLOG_LWIP_PATH is empty (falls back to $LWIP_PATH). Use the cpputest-freertos-cross container, "
        "which sets this to /opt/lwip.")
endif()

set(MBEDTLS_SOURCE_DIR "${SOLIDSYSLOG_MBEDTLS_DIR}")
if(NOT EXISTS "${MBEDTLS_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "SOLIDSYSLOG_MBEDTLS_DIR is empty or invalid (falls back to $MBEDTLS_DIR). Use the cpputest-freertos-cross "
        "container, which sets this to /opt/mbedtls.")
endif()

set(FATFS_PATH "${SOLIDSYSLOG_FATFS_PATH}")
if(NOT FATFS_PATH)
    message(FATAL_ERROR
        "SOLIDSYSLOG_FATFS_PATH is empty (falls back to $FATFS_PATH). Use the cpputest-freertos-cross container, "
        "which sets this to /opt/fatfs.")
endif()

# Stage the upstream FatFs source pack alongside our integrator ffconf.h
# (shared with the Plus-TCP target — Bdd/Targets/Common/ffconf.h) in the
# build dir. FatFs's ff.h does `#include "ffconf.h"` and GCC's `""` lookup
# checks the source file's own directory first, so colocating them is the
# only way our integrator config wins over upstream's sample. Same pattern
# as Bdd/Targets/FreeRtos/CMakeLists.txt.
set(FATFS_STAGE_DIR "${CMAKE_CURRENT_BINARY_DIR}/fatfs")
configure_file(${FATFS_PATH}/source/ff.c     ${FATFS_STAGE_DIR}/ff.c     COPYONLY)
configure_file(${FATFS_PATH}/source/ff.h     ${FATFS_STAGE_DIR}/ff.h     COPYONLY)
configure_file(${FATFS_PATH}/source/diskio.h ${FATFS_STAGE_DIR}/diskio.h COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/ffconf.h ${FATFS_STAGE_DIR}/ffconf.h COPYONLY)

# lwIP ships its source lists as *_SRCS variables via Filelists.cmake. For
# NO_SYS=0 we consume the IPv4 core set plus the api/ set (tcpip.c, api_lib,
# api_msg, …) — the tcpip thread, timeouts, and tcpip_callback marshal hop
# live there. No ipv6.
include(${LWIP_DIR}/src/Filelists.cmake)

set(LWIP_CONTRIB_FREERTOS_DIR "${LWIP_DIR}/contrib/ports/freertos")

set(FREERTOS_PORT_DIR "${FREERTOS_KERNEL_PATH}/portable/GCC/ARM_CM3")
set(FREERTOS_TCP_TARGET_DIR "${CMAKE_SOURCE_DIR}/Bdd/Targets/FreeRtos")
set(FREERTOS_COMMON_DIR "${FREERTOS_TCP_TARGET_DIR}/Common")

# --- Upstream OBJECT library --------------------------------------------------
#
# FreeRTOS kernel + lwIP IPv4 core + lwIP api (tcpip thread) + the contrib
# FreeRTOS sys_arch + the vendored Arm LAN9118 driver, compiled with the
# relaxed warning set those upstream / third-party sources require. The
# executable consumes the objects via $<TARGET_OBJECTS:...> so the relaxations
# don't leak into project code.

add_library(solid_syslog_freertos_lwip_upstream OBJECT
    ${FREERTOS_KERNEL_PATH}/tasks.c
    ${FREERTOS_KERNEL_PATH}/queue.c
    ${FREERTOS_KERNEL_PATH}/list.c
    ${FREERTOS_KERNEL_PATH}/timers.c
    ${FREERTOS_KERNEL_PATH}/event_groups.c
    ${FREERTOS_PORT_DIR}/port.c
    ${FREERTOS_KERNEL_PATH}/portable/MemMang/heap_4.c
    ${lwipcore_SRCS}
    ${lwipcore4_SRCS}
    ${lwipapi_SRCS}
    # etharp (in core4) emits ARP frames via ethernet_output/ethbroadcast/
    # ethzero from netif/ethernet.c — pull that one netif source in (but not
    # bridgeif/slipif from lwipnetif_SRCS, which this target has no use for).
    ${LWIP_DIR}/src/netif/ethernet.c
    # lwIP FreeRTOS OS-abstraction port (sys_mutex/sem/mbox/thread) — required
    # for NO_SYS=0.
    ${LWIP_CONTRIB_FREERTOS_DIR}/sys_arch.c
    # Vendored Arm LAN9118 (SMSC9220) low-level driver (Apache-2.0). The lwIP
    # netif wrapper over it (netif/EthernetIf.c) stays in the executable under
    # the strict bar; this third-party source sits under the relaxations.
    ${CMAKE_CURRENT_SOURCE_DIR}/netif/smsc9220/smsc9220_eth_drv.c
    # FatFs upstream (R0.16) + our shared integrator ffsystem.c — same
    # relaxed-warnings treatment as the Plus-TCP target (ff.c inherits FatFs's
    # sign-conversion / typedef-via-BYTE patterns). ff.c is staged so its
    # `#include "ff.h"` / "ffconf.h" resolve to our integrator config.
    ${FATFS_STAGE_DIR}/ff.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/ffsystem.c
)

target_compile_options(solid_syslog_freertos_lwip_upstream PRIVATE
    -mcpu=cortex-m3
    -mthumb
    -ffunction-sections
    -fdata-sections
    -fno-common
    # FreeRTOS-Kernel + lwIP + the Arm driver use non-prototype declarations,
    # type-narrowing constructs, sign-conversion patterns, and shadowed locals
    # that trip our strict host warnings. Scoped to this OBJECT library so the
    # relaxations never reach project code.
    -Wno-unused-parameter
    -Wno-unused-but-set-variable
    -Wno-implicit-fallthrough
    -Wno-array-bounds
    -Wno-conversion
    -Wno-sign-conversion
    -Wno-shadow
    -Wno-pedantic
)

target_include_directories(solid_syslog_freertos_lwip_upstream PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}                       # FreeRTOSConfig.h, lwipopts.h, arch/cc.h
    ${CMAKE_CURRENT_SOURCE_DIR}/netif/smsc9220        # smsc9220_eth_drv.h, smsc9220_emac_config.h
    ${FREERTOS_KERNEL_PATH}/include
    ${FREERTOS_PORT_DIR}                              # portmacro.h
    ${LWIP_DIR}/src/include
    ${LWIP_CONTRIB_FREERTOS_DIR}/include              # arch/sys_arch.h
    ${FATFS_STAGE_DIR}                                # ff.h, diskio.h + integrator ffconf.h colocated
)

# --- mbedTLS upstream as a subproject ----------------------------------------
#
# Same pattern as Bdd/Targets/FreeRtos/CMakeLists.txt: bring mbedTLS in via
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
# Project code only. Inherits the full project warning set from the top-level
# CMakeLists.txt — no -Wno-* relaxations here.

add_executable(SolidSyslogBddTargetLwip
    main.c
    ${FREERTOS_TCP_TARGET_DIR}/Startup.c              # Ethernet variant: IRQ 13 -> EthernetISR
    ${FREERTOS_COMMON_DIR}/CmsdkUart.c
    ${FREERTOS_COMMON_DIR}/Syscalls.c
    netif/EthernetIf.c
    # SolidSyslog platform adapters arrive via the SolidSyslog::* pack umbrellas
    # linked below (S30.02 dogfood): LwipRaw (Address/Datagram/TcpStream/
    # Resolver/DnsResolver/Marshal; the unused numeric resolver dead-strips),
    # FreeRtos (Mutex +
    # SysUpTime), MbedTls (TLS Stream + HMAC/AES-GCM policies), FatFs (file
    # adapter). diskio.c is the shared semihosting media driver (8 MiB FAT16).
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/diskio.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/SemihostingDisk.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetErrorText.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetFatFsMount.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetFreeRtosPipeline.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetCustomSd.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetInteractive.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetIps.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetLanguage.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetMtlsConfig.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetSwitchConfig.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetMbedTlsCredentials.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetTlsConfig.c
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common/BddTargetTlsSender_MbedTls_LwipRawTcp.c
    ${BAKED_PEM_HEADERS}
    $<TARGET_OBJECTS:solid_syslog_freertos_lwip_upstream>
)

set_target_properties(SolidSyslogBddTargetLwip PROPERTIES SUFFIX ".elf")

target_compile_options(SolidSyslogBddTargetLwip PRIVATE
    -mcpu=cortex-m3
    -mthumb
    -ffunction-sections
    -fdata-sections
    -fno-common
)

target_include_directories(SolidSyslogBddTargetLwip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}                       # FreeRTOSConfig.h, lwipopts.h, arch/cc.h
    ${CMAKE_CURRENT_SOURCE_DIR}/netif                 # EthernetIf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/netif/smsc9220        # smsc9220_eth_drv.h, smsc9220_emac_config.h
    ${FREERTOS_COMMON_DIR}                            # CmsdkUart.h
    ${CMAKE_SOURCE_DIR}/Core/Interface                # SolidSyslog*.h
    ${CMAKE_SOURCE_DIR}/Core/Source                   # internal headers consumed by adapters
    # Platform/{LwipRaw,FreeRtos,MbedTls,FatFs}/{Interface,Source} include dirs
    # now arrive transitively from the SolidSyslog::* pack umbrellas linked below.
    ${FATFS_STAGE_DIR}                                # ff.h, diskio.h + integrator ffconf.h colocated
    ${BAKED_PEMS_DIR}                                 # BddBaked*.h (xxd -i output)
    ${CMAKE_SOURCE_DIR}/Bdd/Targets/Common            # BddTargetInteractive.h, BddTargetSwitchConfig.h, …
    ${FREERTOS_KERNEL_PATH}/include
    ${FREERTOS_PORT_DIR}                              # portmacro.h
    ${LWIP_DIR}/src/include
    ${LWIP_CONTRIB_FREERTOS_DIR}/include              # arch/sys_arch.h (via lwip/sys.h)
)

target_link_libraries(SolidSyslogBddTargetLwip PRIVATE
    ${PROJECT_NAME}                                   # libSolidSyslog.a (cross-compiled)
    SolidSyslog::LwipRaw                              # lwIP Raw adapters (DNS resolver needs LWIP_DNS=1)
    SolidSyslog::FreeRtos                             # Mutex + SysUpTime adapters (sources)
    SolidSyslog::MbedTls                              # TLS Stream + HMAC/AES-GCM policy adapters (sources)
    SolidSyslog::FatFs                                # FatFs file adapter (sources)
    mbedtls mbedx509 mbedcrypto                       # mbedTLS upstream (subproject, cross-compiled)
)

# Platform/MbedTls/Source/*.c include <mbedtls/ssl.h>; they MUST see the same
# user config as the mbedTLS library itself, otherwise struct sizes and the
# enabled-feature bitset diverge between the consumer and the library.
target_compile_definitions(SolidSyslogBddTargetLwip PRIVATE
    MBEDTLS_USER_CONFIG_FILE=${MBEDTLS_USER_CONFIG_HEADER}
)

target_link_options(SolidSyslogBddTargetLwip PRIVATE
    -mcpu=cortex-m3
    -mthumb
    -T${FREERTOS_COMMON_DIR}/mps2-an385.ld
    --specs=nano.specs
    --specs=nosys.specs
    -Wl,--gc-sections
    -Wl,-Map=$<TARGET_FILE:SolidSyslogBddTargetLwip>.map
)

set_target_properties(SolidSyslogBddTargetLwip PROPERTIES
    LINK_DEPENDS ${FREERTOS_COMMON_DIR}/mps2-an385.ld)

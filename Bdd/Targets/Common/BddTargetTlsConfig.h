#ifndef BDDTARGETTLSCONFIG_H
#define BDDTARGETTLSCONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SolidSyslogExternC.h"

struct SolidSyslogEndpoint;

SOLIDSYSLOG_EXTERN_C_BEGIN

    enum
    {
        /* Four pins is enough for every cell in the matrix: one matching, one
           not, and a stale-plus-current pair for a renewal crossing. */
        BDD_TARGET_TLS_MAX_FINGERPRINTS = 4
    };

    const char* BddTargetTlsConfig_GetHost(void);
    uint16_t BddTargetTlsConfig_GetPort(void);
    /* Which trust anchors a connection is made with, as a logical name rather
       than a path: "ca", "ca-b", or "none" for a configuration with no anchors
       at all. A path would be meaningless on a target with no filesystem, where
       the anchors are baked into the image, so each pack's credentials backend
       resolves the name its own way and one feature file drives every target. */
    const char* BddTargetTlsConfig_GetTrustAnchorName(void);
    /* The client credential to present: "client", "cert-only" for the
       half-supplied case the contract reports and continues through, or "none". */
    const char* BddTargetTlsConfig_GetClientCredentialName(void);
    /* NULL asks for no name check and no opt-out, "" is the explicit opt-out,
       and anything else is verified against the peer certificate. The three
       are distinct to the library, so the harness has to be able to say all
       three. */
    const char* BddTargetTlsConfig_GetServerName(void);
    const char* const * BddTargetTlsConfig_GetPeerFingerprints(void);
    size_t BddTargetTlsConfig_GetPeerFingerprintCount(void);
    void BddTargetTlsConfig_GetEndpoint(struct SolidSyslogEndpoint * endpoint, void* context);
    uint32_t BddTargetTlsConfig_GetEndpointVersion(void* context);
    /* What the TLS stream reads to decide whether to reconnect. Shares one
       counter with the endpoint version: moving both when only one changed
       costs a reconnect that was going to happen anyway. */
    uint32_t BddTargetTlsConfig_GetStreamVersion(void* context);

    /* Override the default TLS host ("syslog-ng" - Linux compose service
       name). Caller owns the string lifetime. Used by the per-platform
       main.c to inject SOLIDSYSLOG_BDD_TLS_HOST when set, so the same
       example targets the Linux compose oracle or the Windows OTel oracle
       on 127.0.0.1. NULL leaves the current host alone. */
    void BddTargetTlsConfig_SetHost(const char* host);

    /* Override the TLS server name used for SNI and cert hostname
       verification, independently of the connection host. By default
       BddTargetTlsConfig_GetServerName aliases BddTargetTlsConfig_GetHost
       (the Linux / Windows BDD setup
       uses the cert subject as the connection host), but the FreeRTOS
       BDD target's QEMU networking needs the connection IP separate
       from the cert subject - slirp NAT goes through 10.0.2.2, while
       the syslog-ng oracle's cert is for "syslog-ng". Caller owns the
       string lifetime. NULL leaves the current name alone. */
    void BddTargetTlsConfig_SetServerName(const char* serverName);

    /* Apply one `set <name> <value>` from the prompt, returning false for a
       name this module does not own so the caller can try another handler.
       Names, and the values that mean something other than themselves:

         tls-host  <host>
         tls-port  <number>
         tls-ca     ca | ca-b | none          - none asks for no trust anchors
         tls-client client | cert-only | none - what to present for mutual TLS
         tls-name   <name> | none | ""        - none asks for no name at all
         tls-pin    <fingerprint> | none      - none clears the list, else appends

       Every accepted set moves the version, so the next record reconnects and
       the change is in force from the one after it. */
    bool BddTargetTlsConfig_SetByName(const char* name, const char* value);

    /* Back to the defaults a target starts with, version included. For tests;
       a target has no reason to call it. */
    void BddTargetTlsConfig_Reset(void);

SOLIDSYSLOG_EXTERN_C_END

#endif /* BDDTARGETTLSCONFIG_H */

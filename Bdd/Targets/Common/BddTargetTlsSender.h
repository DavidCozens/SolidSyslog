#ifndef BDDTARGETTLSSENDER_H
#define BDDTARGETTLSSENDER_H

#include "SolidSyslogExternC.h"

#include <stdbool.h>

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogErrorSource;
    struct SolidSyslogResolver;
    struct SolidSyslogSender;
    struct mbedtls_ctr_drbg_context;

    struct SolidSyslogSender* BddTargetTlsSender_Create(struct SolidSyslogResolver * resolver, bool mtls);
    void BddTargetTlsSender_Destroy(void);

    /* The seeded CTR-DRBG this module owns, so the at-rest AES-256-GCM policy can
     * reuse it as its nonce source rather than standing up a second entropy /
     * DRBG pair on this resource-constrained demo target. Valid once Create has
     * run (InteractiveTask seeds it during Setup, before any `store file`
     * rebuild). Returns the address of the file-scope context even if seeding
     * failed - the policy's nonce draw then fails closed, which is the correct
     * degraded behaviour. */
    struct mbedtls_ctr_drbg_context* BddTargetTlsSender_GetRng(void);

    /* The error source the linked TLS stream reports through, or NULL where this
     * target has no TLS. Only this file knows which pack is linked, so asking it
     * lets the error handler mark a TLS-stream report without the handler, or a
     * step definition, naming a backend - which is the one thing the equivalence
     * matrix must not do. */
    const struct SolidSyslogErrorSource* BddTargetTlsSender_ErrorSource(void);

SOLIDSYSLOG_EXTERN_C_END

#endif /* BDDTARGETTLSSENDER_H */

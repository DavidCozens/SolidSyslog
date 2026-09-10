/* MbedTLS-over-PlusTcpTcpStream BDD TLS sender (slice 6b).
 *
 * Composes:
 *   - SolidSyslogPlusTcpTcpStream  inner TCP transport
 *   - SolidSyslogMbedTlsStream      TLS over the injected Stream
 *   - SolidSyslogStreamSender       RFC 6587 octet-counting framing
 *
 * Mirrors BddTargetTlsSender_OpenSsl_PosixTcp.c on the POSIX target. The
 * mbedTLS adapter takes pre-built handles (mbedtls_ctr_drbg, mbedtls_x509_crt,
 * mbedtls_pk_context) rather than file paths, because MBEDTLS_FS_IO is
 * disabled in the integrator config - there is no host path reachable from
 * QEMU. The demo CA / client cert / client key PEMs travel as `static const`
 * arrays in rodata, baked at CMake-time by xxd -i from
 * Bdd/syslog-ng/tls/ ca.pem / client.pem / client.key. The arrays are
 * parsed once on first BddTargetTlsSender_Create call.
 *
 * Entropy + CTR_DRBG also live in this TU rather than in main.c so all
 * mbedTLS-specific state is one file's responsibility. The entropy source
 * is deliberately weak - see DemoEntropySource - and an audit-trail
 * WARNING is emitted via SolidSyslog_Error on first init.
 */

#include "BddTargetTlsSender.h"

#include "BddTargetMtlsConfig.h"
#include "BddTargetSwitchConfig.h"
#include "BddTargetTlsConfig.h"
#include "SolidSyslogPlusTcpAddress.h"
#include "SolidSyslogPlusTcpTcpStream.h"
#include "SolidSyslogMbedTlsHandleCredentials.h"
#include "SolidSyslogMbedTlsStream.h"
#include "SolidSyslogNullSender.h"
#include "SolidSyslogStream.h"
#include "SolidSyslogStreamSender.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <FreeRTOS.h>
#include <task.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "BddBakedCaPem.h"
#include "BddBakedClientCertPem.h"
#include "BddBakedClientKeyPem.h"

struct SolidSyslogResolver;

static struct SolidSyslogStream* underlyingStream;
static struct SolidSyslogMbedTlsCredentials* credentials;
static struct SolidSyslogStream* tlsStream;
static struct SolidSyslogAddress* address;
static struct SolidSyslogSender* sender;

/* Entropy + CTR_DRBG live for the lifetime of the BDD target; one-shot init
 * gated on `mbedTlsInitialised`. mbedTLS structs are zero-initialised by
 * static storage; mbedtls_*_init is still called explicitly because the
 * library treats post-init / post-free as the same state. */
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context drbg;
static bool mbedTlsInitialised;

/* mbedtls_x509_crt_parse / mbedtls_pk_parse_key require NUL-terminated PEM
 * input. xxd -i doesn't append a NUL, so we hold a +1-sized copy here and
 * NUL-terminate at parse time. The cost is one extra byte per PEM in BSS;
 * cheaper than the shell pipeline that would be needed to bake the NUL at
 * CMake time. */
static unsigned char caPemBuf[sizeof(bdd_baked_ca_pem) + 1U];
static unsigned char clientCertPemBuf[sizeof(bdd_baked_client_cert_pem) + 1U];
static unsigned char clientKeyPemBuf[sizeof(bdd_baked_client_key_pem) + 1U];

static mbedtls_x509_crt caChain;
static mbedtls_x509_crt clientCertChain;
static mbedtls_pk_context clientKey;

/* mbedTLS allocates its per-SSL-context IN/OUT buffers (~6 KiB combined) and
 * handshake state (~10 KiB) via libc calloc - on this FreeRTOS target that
 * funnels through newlib's tiny syscall heap (~4 KiB, see Common/Syscalls.c),
 * which can't satisfy a single TLS context. Redirect to pvPortMalloc so
 * mbedTLS allocates from the 96 KiB FreeRTOS heap_4 region instead - the
 * standard FreeRTOS+mbedTLS integration. Gated on MBEDTLS_PLATFORM_MEMORY in
 * mbedtls_user_config.h. The zero-fill mirrors libc calloc's contract. */
static void* FreeRtosMbedTlsCalloc(size_t nmemb, size_t size)
{
    void* result = NULL;
    /* Guard the multiplication against wrap BEFORE multiplying: a maliciously
     * huge request must not underestimate the allocation size, or pvPortMalloc
     * would hand back a too-small buffer the caller then writes past. With size
     * already known non-zero, nmemb <= SIZE_MAX / size proves nmemb * size fits. */
    if ((nmemb != 0U) && (size != 0U) && (nmemb <= (SIZE_MAX / size)))
    {
        size_t bytes = nmemb * size;
        result = pvPortMalloc(bytes);
        if (result != NULL)
        {
            memset(result, 0, bytes);
        }
    }
    return result;
}

static void FreeRtosMbedTlsFree(void* ptr)
{
    if (ptr != NULL)
    {
        vPortFree(ptr);
    }
}

/* PSA crypto's randomness hook (gated on MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG in
 * the user config). mbedTLS 3.6's TLS 1.3 path drives PSA crypto, and PSA's
 * built-in entropy collector returns PSA_ERROR_INSUFFICIENT_ENTROPY on
 * MBEDTLS_NO_PLATFORM_ENTROPY targets - bypass it by feeding PSA from the
 * same CTR_DRBG the classic mbedTLS API already uses. The DRBG must be
 * seeded before psa_crypto_init() so the first PSA crypto operation can
 * draw bytes - EnsureMbedTlsInitialised below enforces that ordering. */
psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t* context,
    uint8_t* output,
    size_t outputSize,
    size_t* outputLength
)
{
    (void) context;
    if (mbedtls_ctr_drbg_random(&drbg, output, outputSize) != 0)
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
    *outputLength = outputSize;
    return PSA_SUCCESS;
}

/* Demo-only entropy: XOR the FreeRTOS tick count, a per-call counter, and
 * the destination address (which varies per call) into each output byte.
 * Quality is intentionally terrible - QEMU has no real source - and the
 * "demo-only entropy" printf emit at the end of EnsureMbedTlsInitialised
 * makes that explicit. Real integrators on bare-metal would replace this
 * with TRNG / HSM bytes. */
static int DemoEntropySource(void* data, unsigned char* output, size_t len, size_t* olen)
{
    (void) data;
    static uint32_t counter = 0U;
    for (size_t i = 0; i < len; i++)
    {
        counter++;
        uint32_t mix = (uint32_t) xTaskGetTickCount() ^ counter ^ (uint32_t) (uintptr_t) &output[i];
        output[i] = (unsigned char) ((mix >> ((i % 4U) * 8U)) & 0xFFU);
    }
    *olen = len;
    return 0;
}

static void RtosSleep(int milliseconds)
{
    /* Same rounding rule as the CmsdkUart sleep in main.c - sub-tick requests
     * must still block the task, otherwise vTaskDelay(0) just yields. */
    TickType_t ticks = pdMS_TO_TICKS((TickType_t) milliseconds);
    if ((milliseconds > 0) && (ticks == 0U))
    {
        ticks = 1U;
    }
    vTaskDelay(ticks);
}

/* Idempotent: safe to call from BddTargetTlsSender_Create on every invocation
 * even though the first call is the only one that does real work. mbedTLS
 * state for entropy/DRBG/cert/key lives at file scope and survives across
 * connect/disconnect cycles.
 *
 * Each major step emits a SolidSyslog_Error INFO message and yields one
 * tick to the FreeRTOS scheduler. Under QEMU mps2-an385 the DRBG seed +
 * cert/key parses can each take several seconds (mbedTLS does serious
 * crypto work - RSA key parse, ECDHE primes, ASN.1 walks); without the
 * yields, lower-priority tasks would starve until init finishes, and
 * without the diagnostic prints the boot would appear to hang. */
static void EnsureMbedTlsInitialised(void)
{
    if (mbedTlsInitialised)
    {
        return;
    }

    /* Boot diagnostics via printf rather than SolidSyslog_Error because main's
     * error handler installation happens AFTER BddTargetTlsSender_Create -
     * the default no-op handler would otherwise swallow these. */
    (void) printf("[mbedtls] init entropy + DRBG seed (slow under QEMU)\r\n");
    vTaskDelay(1U);

    /* Redirect mbedTLS allocations to the FreeRTOS heap before any
     * mbedtls_*_init runs. Must come first - once an ssl_setup runs against
     * the default libc calloc and fails, the failure mode is heap exhaustion
     * inside newlib's 4 KiB syscall heap, not a recoverable error. */
    mbedtls_platform_set_calloc_free(FreeRtosMbedTlsCalloc, FreeRtosMbedTlsFree);

    mbedtls_entropy_init(&entropy);
    /* Registered as MBEDTLS_ENTROPY_SOURCE_STRONG even though the demo
     * randomness is intentionally terrible. The STRONG/WEAK label is
     * checked structurally by `mbedtls_entropy_func`, which requires at
     * least MBEDTLS_ENTROPY_BLOCK_SIZE bytes of strong contribution per
     * call - without any strong source registered, every
     * `mbedtls_ctr_drbg_seed` returns ENTROPY_SOURCE_FAILED (-0x0034)
     * after looping 256 times trying to satisfy the threshold. The
     * "demo-only entropy" notice printed at the end of this function is
     * the real quality assertion; real integrators replace this with a
     * TRNG / HSM source. */
    mbedtls_entropy_add_source(
        &entropy,
        DemoEntropySource,
        NULL,
        MBEDTLS_ENTROPY_BLOCK_SIZE,
        MBEDTLS_ENTROPY_SOURCE_STRONG
    );

    mbedtls_ctr_drbg_init(&drbg);
    static const unsigned char personalization[] = "solidsyslog-freertos-bdd";
    int drbgSeedRc =
        mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, personalization, sizeof(personalization) - 1U);
    if (drbgSeedRc != 0)
    {
        (void
        ) printf("[mbedtls] ctr_drbg_seed FAILED rc=-0x%04x; TLS slot will be unusable\r\n", (unsigned) -drbgSeedRc);
        return;
    }
    vTaskDelay(1U);

    /* mbedTLS 3.6 routes TLS 1.3 cryptography through PSA, so psa_crypto_init()
     * must succeed before the first handshake or mbedtls_ssl_handshake returns
     * MBEDTLS_ERR_ERROR_GENERIC_ERROR (-0x0001) at the first state transition.
     * MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG in the user config disables PSA's
     * built-in entropy collector (which would otherwise return
     * PSA_ERROR_INSUFFICIENT_ENTROPY on this no-platform-entropy target), so
     * the init only succeeds once the DRBG is seeded above - that's why this
     * sits after the seed step. Idempotent across subsequent calls. */
    psa_status_t psaRc = psa_crypto_init();
    if (psaRc != PSA_SUCCESS)
    {
        (void) printf("[mbedtls] psa_crypto_init FAILED rc=%d; TLS slot will be unusable\r\n", (int) psaRc);
        return;
    }

    (void) printf("[mbedtls] parsing CA chain\r\n");

    memcpy(caPemBuf, bdd_baked_ca_pem, sizeof(bdd_baked_ca_pem));
    caPemBuf[sizeof(bdd_baked_ca_pem)] = '\0';
    mbedtls_x509_crt_init(&caChain);
    int caParseRc = mbedtls_x509_crt_parse(&caChain, caPemBuf, sizeof(caPemBuf));
    if (caParseRc != 0)
    {
        (void
        ) printf("[mbedtls] CA chain parse FAILED rc=-0x%04x; TLS slot will be unusable\r\n", (unsigned) -caParseRc);
        return;
    }
    vTaskDelay(1U);

    (void) printf("[mbedtls] parsing client cert chain\r\n");

    memcpy(clientCertPemBuf, bdd_baked_client_cert_pem, sizeof(bdd_baked_client_cert_pem));
    clientCertPemBuf[sizeof(bdd_baked_client_cert_pem)] = '\0';
    mbedtls_x509_crt_init(&clientCertChain);
    int clientCertParseRc = mbedtls_x509_crt_parse(&clientCertChain, clientCertPemBuf, sizeof(clientCertPemBuf));
    if (clientCertParseRc != 0)
    {
        (void) printf(
            "[mbedtls] client cert parse FAILED rc=-0x%04x; mTLS will be unusable\r\n",
            (unsigned) -clientCertParseRc
        );
        return;
    }
    vTaskDelay(1U);

    (void) printf("[mbedtls] parsing client key (RSA — slowest step)\r\n");

    memcpy(clientKeyPemBuf, bdd_baked_client_key_pem, sizeof(bdd_baked_client_key_pem));
    clientKeyPemBuf[sizeof(bdd_baked_client_key_pem)] = '\0';
    mbedtls_pk_init(&clientKey);
    int clientKeyParseRc = mbedtls_pk_parse_key(
        &clientKey,
        clientKeyPemBuf,
        sizeof(clientKeyPemBuf),
        NULL,
        0U,
        mbedtls_ctr_drbg_random,
        &drbg
    );
    if (clientKeyParseRc != 0)
    {
        (void) printf(
            "[mbedtls] client key parse FAILED rc=-0x%04x; mTLS will be unusable\r\n",
            (unsigned) -clientKeyParseRc
        );
        return;
    }
    vTaskDelay(1U);

    /* Audit trail: every cold boot of this target announces the demo-only
     * entropy explicitly. Integrators porting this off the BDD target should
     * see this and replace DemoEntropySource with TRNG before shipping. The
     * `mbedTlsInitialised = true` latch happens only after every fail-able
     * step above has succeeded - partial-init state would silently degrade
     * later handshakes into confusing "internal" errors. */
    (void) printf("[mbedtls] init complete. WARNING: demo-only entropy "
                  "(xTaskGetTickCount + per-call counter). Not for production.\r\n");

    mbedTlsInitialised = true;
}

/* Dispatch the StreamSender's endpoint+version callbacks based on whether
 * the harness most recently selected `tls` or `mtls` over the UART. tls
 * and mtls share BDD_TARGET_SWITCH_TLS (and therefore one TLS stream / one
 * TCP socket / one mbedTLS context); only the destination port (6514 vs
 * 6515) differs at Connect time. The mTLS port's syslog-ng listener
 * peer-verifies the client cert that the wrapper wires unconditionally
 * below, and the plain-TLS port's listener accepts it as optional-untrusted
 * - so the same client identity works on both ports. */
static void DispatchEndpoint(struct SolidSyslogEndpoint* endpoint, void* context)
{
    if (BddTargetSwitchConfig_IsMtlsMode())
    {
        BddTargetMtlsConfig_GetEndpoint(endpoint, context);
    }
    else
    {
        BddTargetTlsConfig_GetEndpoint(endpoint, context);
    }
}

static uint32_t DispatchEndpointVersion(void* context)
{
    return BddTargetSwitchConfig_IsMtlsMode() ? BddTargetMtlsConfig_GetEndpointVersion(context)
                                              : BddTargetTlsConfig_GetEndpointVersion(context);
}

struct SolidSyslogSender* BddTargetTlsSender_Create(struct SolidSyslogResolver* resolver, bool mtls)
{
    /* `mtls` is honoured for cross-platform contract uniformity but does not
     * gate cert wiring on FreeRTOS - both TLS and mTLS BDD scenarios share
     * one Switching slot here, and `set transport mtls` arrives over the UART
     * AFTER this Create call has run. Wiring the client identity
     * unconditionally lets the dispatcher above flip ports at runtime without
     * needing a sender re-create. */
    (void) mtls;

    EnsureMbedTlsInitialised();
    if (!mbedTlsInitialised)
    {
        /* EnsureMbedTlsInitialised already printed a [mbedtls] ... FAILED
         * diagnostic explaining which step tripped. Returning the shared
         * NullSender here keeps the bad-setup contract intact - the
         * SwitchingSender's tls slot drops messages cleanly rather than
         * failing opaquely later inside MbedTlsStream_Open, and the
         * statics below stay NULL so BddTargetTlsSender_Destroy can
         * detect the short-circuit. */
        return SolidSyslogNullSender_Get();
    }
    /* Plain-TLS and mTLS share one SNI on this oracle (CN/SAN = "syslog-ng"), so
 * BddTargetTlsConfig_GetServerName and BddTargetMtlsConfig_GetServerName return
 * the same string. Use the TLS one to make the equivalence explicit. */
    static void BddTargetTlsSender_Profile(struct SolidSyslogMbedTlsProfile * profile, void* context)
    {
        (void) context;
        profile->ServerName = BddTargetTlsConfig_GetServerName();
    }

    underlyingStream = SolidSyslogPlusTcpTcpStream_Create(NULL);

    static struct SolidSyslogMbedTlsStreamConfig tlsStreamConfig;
    tlsStreamConfig = (struct SolidSyslogMbedTlsStreamConfig) {0};
    tlsStreamConfig.Transport = underlyingStream;
    tlsStreamConfig.Sleep = RtosSleep;
    tlsStreamConfig.Rng = &drbg;
    tlsStreamConfig.Profile = BddTargetTlsSender_Profile;
    static struct SolidSyslogMbedTlsHandleCredentialsConfig credentialsConfig;
    credentialsConfig = (struct SolidSyslogMbedTlsHandleCredentialsConfig) {0};
    credentialsConfig.Rng = &drbg;
    credentialsConfig.CaChain = &caChain;
    credentialsConfig.ClientCertChain = &clientCertChain;
    credentialsConfig.ClientKey = &clientKey;
    credentials = SolidSyslogMbedTlsHandleCredentials_Create(&credentialsConfig);
    tlsStreamConfig.Credentials = credentials;
    tlsStream = SolidSyslogMbedTlsStream_Create(&tlsStreamConfig);

    address = SolidSyslogPlusTcpAddress_Create();

    static struct SolidSyslogStreamSenderConfig senderConfig;
    senderConfig = (struct SolidSyslogStreamSenderConfig) {0};
    senderConfig.Resolver = resolver;
    senderConfig.Stream = tlsStream;
    senderConfig.Address = address;
    senderConfig.Endpoint = DispatchEndpoint;
    senderConfig.EndpointVersion = DispatchEndpointVersion;
    sender = SolidSyslogStreamSender_Create(&senderConfig);

    return sender;
}

void BddTargetTlsSender_Destroy(void)
{
    /* If EnsureMbedTlsInitialised failed, Create short-circuited to the
     * shared NullSender and never assigned the file-scope statics - there
     * is nothing to release. The pool-backed Destroy helpers tolerate
     * a NULL handle but skipping makes the no-op explicit. */
    if (sender == NULL)
    {
        return;
    }
    SolidSyslogStreamSender_Destroy(sender);
    SolidSyslogPlusTcpAddress_Destroy(address);
    SolidSyslogMbedTlsStream_Destroy(tlsStream);
    SolidSyslogMbedTlsHandleCredentials_Destroy(credentials);
    SolidSyslogPlusTcpTcpStream_Destroy(underlyingStream);

    /* Entropy / DRBG / parsed certs survive across Destroy -> Create cycles to
     * avoid re-seeding on every reconnect. Real teardown only happens at
     * process exit, which the FreeRTOS target never reaches. */
}

struct mbedtls_ctr_drbg_context* BddTargetTlsSender_GetRng(void)
{
    return &drbg;
}

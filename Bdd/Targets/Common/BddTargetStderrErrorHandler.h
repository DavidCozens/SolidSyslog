#ifndef BDDTARGETSTDERRERRORHANDLER_H
#define BDDTARGETSTDERRERRORHANDLER_H

#include <stdbool.h>

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    struct SolidSyslogErrorSource;

    void BddTargetStderrErrorHandler_Install(void);

    /* Which source counts as the TLS-stream role, so its reports can be marked
       `role=tls`. Injected rather than looked up: the handler links into targets
       and test binaries that have no TLS pack at all. NULL marks nothing. */
    void BddTargetStderrErrorHandler_SetTlsSource(const struct SolidSyslogErrorSource* source);

    /* Whether an ERROR or worse ends the process. On by default, because most
       scenarios treat one as a failed run. The matrix turns it off: a refused
       handshake is reported at ERROR, so a fatal handler would kill the target
       before the scenario could see what happened next. */
    void BddTargetStderrErrorHandler_SetFatal(bool fatal);

SOLIDSYSLOG_EXTERN_C_END

#endif /* BDDTARGETSTDERRERRORHANDLER_H */

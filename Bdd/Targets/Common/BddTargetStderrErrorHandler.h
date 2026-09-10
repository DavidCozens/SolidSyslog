#ifndef BDDTARGETSTDERRERRORHANDLER_H
#define BDDTARGETSTDERRERRORHANDLER_H

#include <stdbool.h>

#include "SolidSyslogExternC.h"

SOLIDSYSLOG_EXTERN_C_BEGIN

    void BddTargetStderrErrorHandler_Install(void);

    /* Whether an ERROR or worse ends the process. On by default, because most
       scenarios treat one as a failed run. The matrix turns it off: a refused
       handshake is reported at ERROR, so a fatal handler would kill the target
       before the scenario could see what happened next. */
    void BddTargetStderrErrorHandler_SetFatal(bool fatal);

SOLIDSYSLOG_EXTERN_C_END

#endif /* BDDTARGETSTDERRERRORHANDLER_H */

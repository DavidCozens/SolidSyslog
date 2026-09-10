#include "BddTargetStderrErrorHandler.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "BddTargetErrorText.h"
#include "SolidSyslogError.h"
#include "SolidSyslogPrival.h"

static bool fatalOnError = true;

void BddTargetStderrErrorHandler_SetFatal(bool fatal)
{
    fatalOnError = fatal;
}

static void StderrErrorHandlerEx(void* context, const struct SolidSyslogErrorEvent* event)
{
    (void) context;
    const char* sourceName = "<unknown>";
    const struct SolidSyslogErrorSource* source = event->Source;
    if (source != NULL)
    {
        sourceName = source->Name;
    }
    const char* message = BddTargetErrorText_Category(event->Category);
    if (fatalOnError && (event->Severity <= SOLIDSYSLOG_SEVERITY_ERROR))
    {
        (void) fprintf(
            stderr,
            "BDD-TARGET: FATAL: [%s cat=%u detail=%ld] %s\n",
            sourceName,
            (unsigned) event->Category,
            (long) event->Detail,
            message
        );
        (void) fflush(stderr);
        _Exit(3);
    }
    else
    {
        (void) fprintf(
            stderr,
            "[solidsyslog] severity=%d [%s cat=%u detail=%ld] %s\n",
            (int) event->Severity,
            sourceName,
            (unsigned) event->Category,
            (long) event->Detail,
            message
        );
    }
}

void BddTargetStderrErrorHandler_Install(void)
{
    SolidSyslog_SetErrorHandler(StderrErrorHandlerEx, NULL);
}

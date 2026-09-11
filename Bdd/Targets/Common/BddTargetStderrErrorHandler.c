#include "BddTargetStderrErrorHandler.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "BddTargetErrorText.h"
#include "SolidSyslogError.h"
#include "SolidSyslogPrival.h"

static bool fatalOnError = true;
static const struct SolidSyslogErrorSource* tlsStreamSource;

void BddTargetStderrErrorHandler_SetTlsSource(const struct SolidSyslogErrorSource* source)
{
    tlsStreamSource = source;
}

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
    /* Detail codes are per-class, so a number is only meaningful once the class
       is known. Marking the TLS-stream role lets a step assert a portable detail
       without matching the backend's name. */
    const char* role = ((tlsStreamSource != NULL) && (source == tlsStreamSource)) ? "role=tls " : "";
    if (fatalOnError && (event->Severity <= SOLIDSYSLOG_SEVERITY_ERROR))
    {
        (void) fprintf(
            stderr,
            "BDD-TARGET: FATAL: [%s %scat=%u detail=%ld] %s\n",
            sourceName,
            role,
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
            "[solidsyslog] severity=%d [%s %scat=%u detail=%ld] %s\n",
            (int) event->Severity,
            sourceName,
            role,
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

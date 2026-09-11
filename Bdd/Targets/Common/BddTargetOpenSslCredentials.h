#ifndef BDDTARGETOPENSSLCREDENTIALS_H
#define BDDTARGETOPENSSLCREDENTIALS_H

#include "SolidSyslogExternC.h"

struct SolidSyslogOpenSslCredentials;

SOLIDSYSLOG_EXTERN_C_BEGIN

    /* The BDD target fills the credentials role itself rather than wiring the
       shipped PEM-file backend, because a matrix cell configures its trust
       anchors and pins at the prompt, after the sender has been built. A
       shipped backend copies its configuration at Create, so it could only ever
       carry what the target knew at startup.
    
       Filling the role is also what makes the rotation cells prove anything: the
       material changes, the stream's version moves, and the library re-asks on
       the next connection. Rebuilding the target's own objects instead would
       prove only that the harness can rebuild them. */
    struct SolidSyslogOpenSslCredentials* BddTargetOpenSslCredentials_Get(void);

SOLIDSYSLOG_EXTERN_C_END

#endif /* BDDTARGETOPENSSLCREDENTIALS_H */

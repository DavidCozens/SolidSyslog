# BDD TLS test material

**TEST ONLY.** These keys and certificates exist solely to drive the BDD TLS
scenarios against the collector running in a BDD compose container. They must
never be used for any purpose that touches real data.

Two authorities are here. A BDD target is given **CA A** as its trust anchor
unless a scenario says otherwise, so anything **CA B** signs is a peer the
target cannot chain. Each server certificate carries exactly one fault, so a
scenario that refuses a connection has only one thing it can be refusing for.

| File | Issuer | Name it claims | Used for |
|---|---|---|---|
| `ca.pem` / `ca.key` | self | CA A | the trust anchor a target is given, and the issuer syslog-ng checks a client against |
| `ca-b.pem` / `ca-b.key` | self | CA B | never handed over as an anchor, so its leaves do not chain; also what a target rotates *to* |
| `intermediate.pem` / `.key` | CA A | intermediate | issues a leaf that has to be presented with its issuer |
| `server.pem` / `.key` | CA A | `syslog-ng` | the collector on the happy path |
| `server-untrusted.pem` / `.key` | CA B | `syslog-ng` | right name, unchainable issuer |
| `server-wrongname.pem` / `.key` | CA A | `other-collector` | right issuer, wrong identity |
| `server-selfsigned.pem` / `.key` | self | `syslog-ng` | no chain at all, authorised by fingerprint alone |
| `server-chained.pem` / `.key` | intermediate | `syslog-ng` | a chain checked above depth zero |
| `server-chained-fullchain.pem` | - | - | the leaf and its issuer, which is what the listener presents |
| `server-b.pem` / `.key` | CA B | `collector-b` | the second collector a target is redirected to |
| `client.pem` / `.key` | CA A | `solidsyslog-bdd-client` | the mutual-TLS identity SolidSyslog presents |

Validity is 10 years from generation. Nothing here is expired or not yet valid
on purpose: certificate validity is proved against both TLS libraries in the
integration tier, where a real clock exists.

## Regenerating

Run `./generate.sh` from this directory or from the repo root, and commit the
result. No fingerprint is written down anywhere - the BDD steps compute each one
from the committed certificate at test time - so regenerating breaks nothing.

# Naming conventions

This document defines the identifier naming rules for SolidSyslog. The rules
reconcile three constraints:

1. **MISRA C:2012 uniqueness rules** (5.1 through 5.9) — non-negotiable
   within the strict scope (see Scope below).
2. **Clean Code principles** — identifier length proportional to scope; no
   lazy abbreviations.
3. **Readability at the call site** — a reader should be able to tell, from
   the name alone, roughly where an identifier comes from.

Naming is one slice of the project's coding standard. Rules unrelated to
identifier shape (single-exit-point, parenthesisation, `0U` literal suffixes,
etc.) live in the MISRA standard and `docs/misra-deviations.md`, which are
the authoritative references.

The scheme is enforced by review and by static analysis, with a clean
split between the two tools so they cannot disagree on the same name:

- **clang-tidy** is the sole authority on naming *shape*. The
  `readability-identifier-naming` check understands linkage, scope, and
  the distinction between macros, typedefs, tags and ordinary identifiers.
  Per-directory `.clang-tidy` files implement the tier model below.
  Note: `readability-identifier-naming` enforces case style + prefix +
  suffix per identifier kind, but does not support a positive
  must-match regex. The `SolidSyslogClass_Function` shape past the
  `SolidSyslog` prefix is therefore enforced by review and by
  cppcheck-misra rule 5.1 distinctness, not by clang-tidy directly.
- **cppcheck-misra** is the sole authority on naming *uniqueness*. The
  MISRA addon surfaces rules 5.1, 5.2, 5.4, 5.6, 5.7, 5.8 and 5.9
  violations, which pattern matching alone cannot detect.
- **`scripts/check_platform_docs.py`** is the sole authority on the one
  rule neither tool can see — that a platform class carries its pack's
  registry token, described under *Platform classes carry their pack's
  registry token* below. The token is declared in CMake rather than in
  the code, so no check reading only the translation unit can know it.

cppcheck's `naming` addon is deliberately not used: it does less than
clang-tidy on every axis we care about, and a second tool checking the
same conditions creates the risk of contradictory verdicts.

---

## Scope

The rules apply with different strictness across the tree:

| Tier | Naming | MISRA | Directories |
|------|--------|-------|-------------|
| **Strict** | Full Tier 1–4 | Full chosen subset | `Core/Interface/`, `Core/Source/`, `Platform/*/Interface/` |
| **Pragmatic** | Tier 1–4 applied; local names that mirror third-party APIs (e.g. `mqd_t mq`, `FIL file`, `SOCKET sock`) and parameters in adapter wrappers are exempt; 5.3 shadowing relaxed when the shadowed name is a third-party identifier | Full chosen subset; per-file deviations documented when third-party APIs force them | `Platform/*/Source/` |
| **Consistency-only** | New code follows conventions; CppUTest macro outputs used as-is; test fakes drop the `SolidSyslog` prefix; no rename sweep of existing test code | Excluded | `Tests/` |
| **Out of scope** | Not enforced | Not enforced | `Bdd/`, `ci/`, `docs/`, `.github/`, `.devcontainer/` |

Enforcement gates (clang-tidy + cppcheck-misra) run per tier with different
rule sets.

---

## MISRA C:2012 rules in play

| Rule | Applies to | Constraint |
|------|------------|------------|
| 5.1  | External identifiers | Distinct in the first **63** characters (project deviation — C99 mandates only 31; see `docs/misra-deviations.md`) |
| 5.2  | Identifiers in the same scope and name space | Distinct in the first 63 characters |
| 5.3  | Inner-scope identifiers | Shall not hide an outer-scope identifier |
| 5.4  | Macro identifiers | Unique within the first 63 characters |
| 5.5  | Macros vs other identifiers | No reuse of the same name |
| 5.6  | Typedef names | Unique across the program |
| 5.7  | Tag names | Unique across the program |
| 5.8  | Identifiers with external linkage | Unique |
| 5.9 (advisory) | Identifiers with internal linkage | Should be unique |

The scheme below satisfies all of these by construction. Rule 5.9 is advisory
in MISRA but treated as required here.

---

## Tier 1 — External linkage (public API)

**Form:** `SolidSyslog<Class>_<Function>` for class-scoped operations,
or `SolidSyslog_<Function>` for whole-library operations where the
library itself is the class. `SolidSyslog<Class>` for exported types
and tag names.

```c
/* Class-scoped functions — operate on a specific module.
 * Parameter naming follows the this-pointer rule (Tier 3): `base` when
 * the declared type is the abstract base struct, `self` otherwise. */
bool SolidSyslogBuffer_Read(struct SolidSyslogBuffer* base, void* data, size_t maxSize, size_t* bytesRead);
int  SolidSyslogTransport_Send(struct SolidSyslogTransport* base, ...);

/* Whole-library functions — operate on the library instance, or on
   library-global state. The library is the class; there's nothing more
   specific to insert. Earned by having no narrower class to sit on, not
   by being important: a function that acts on one component takes that
   component's name however central it is. */
struct SolidSyslog* SolidSyslog_Create(const struct SolidSyslogConfig* config);
void                SolidSyslog_Destroy(struct SolidSyslog* self);
void                SolidSyslog_Log(struct SolidSyslog* self, const struct SolidSyslogMessage* message);
void                SolidSyslog_Service(struct SolidSyslog* self);
void                SolidSyslog_SetErrorHandler(SolidSyslogErrorHandler handler, void* context);

/* Tag names — note: tag, not typedef. See "No struct typedefs" below. */
struct SolidSyslogBuffer
{
    /* ... */
};

struct SolidSyslogSecurityPolicy
{
    /* ... */
};

/* Public enum constants — SCREAMING_SNAKE with the project prefix.
 * Single rule for tagged and anonymous enums tree-wide. */
enum SolidSyslogSeverity
{
    SOLIDSYSLOG_SEVERITY_EMERGENCY = 0,
    SOLIDSYSLOG_SEVERITY_ALERT     = 1,
    /* ... */
};

/* Exported objects — the class name runs straight into the object's own
 * name. No underscore: that separator introduces a function name, and an
 * object has none. */
extern const struct SolidSyslogErrorSource SolidSyslogUdpSenderErrorSource;
```

The `SolidSyslog` prefix is the library's namespace. The `<Class>_`
portion (when present) identifies the module. The function name
follows in PascalCase. The "whole-library" form is not an
exception: both shapes are first-class Tier 1; the difference is
whether the operation lives on a specific class or on the library
itself.

An exported object takes `SolidSyslog<Class><Name>`, the same shape as an
exported type. `SolidSyslogUdpSenderErrorSource` is the form;
`SolidSyslogUdpSender_ErrorSource` is not, because the underscore would
announce a function.

**Applies to:** any identifier declared in a header under `Core/Interface/`
or `Platform/*/Interface/`, plus any identifier with external linkage
declared in a `.c` file.

Tier 1 is decided by linkage, not by whether an integrator is meant to call
the identifier. A class that is internal to the library but spans more than one
translation unit — declared in a `Core/Source/` `*Private.h`, defined in one
`.c`, used from another — has external linkage and takes the prefix. Its
struct tags follow, since the tag is no longer local to a file. `SolidSyslogRecordStore`
and `SolidSyslogBlockSequence` are the two: `SolidSyslogBlockStore` composes them,
and no public header names either. Path B is what makes this load-bearing rather
than tidy — an integrator compiling from a manifest gets `Core/Source` on the
include path and every object in one directory, so an unprefixed
`RecordStore_Append` is a symbol collision waiting to happen.

### Spelling a class name inside a SCREAMING_SNAKE identifier

A public macro or enum constant that names a class writes the class in
`SCREAMING_SNAKE`, one word per PascalCase word — **except** that a platform
registry token stays whole, spelled exactly as its CMake option spells it.

```c
SOLIDSYSLOG_CIRCULAR_BUFFER_ERROR_POOL_EXHAUSTED     /* Core class, every word split */
SOLIDSYSLOG_FATFS_FILE_ERROR_POOL_EXHAUSTED          /* FatFs token whole, File split */
SOLIDSYSLOG_WINSOCK_TCP_STREAM_ERROR_UNKNOWN_DESTROY /* Winsock whole, TcpStream split */
```

Splitting the token would misspell the upstream it names — `OPEN_SSL` and
`FAT_FS` are not products — and would disagree with `SOLIDSYSLOG_OPENSSL` and
`SOLIDSYSLOG_FATFS`, the options that select those packs. The tokens are the
ones listed in `SOLIDSYSLOG_PLATFORM_REGISTRY`; see *Platform classes carry
their pack's registry token* below.

The library instance is the degenerate case: its class name is the project name,
so prefix and class collapse and the constants read `SOLIDSYSLOG_ERROR_*` rather
than `SOLIDSYSLOG_SOLIDSYSLOG_ERROR_*`.

**On length.** C99 guarantees 63 significant characters in an internal
identifier, and enum constants have no linkage, so that is the limit that
applies. What has to hold is therefore not a maximum length but a distinctness
rule: **no two public identifiers may share their first 63 characters.** A few
run past 63 in total - the longest are the client-credential codes on the
TLS-credentials role - and that is safe precisely because each is already
distinct well inside the limit. Stating the rule rather than the current longest
name is deliberate: a maximum goes stale every time a constant is added, and
this paragraph has carried a stale one before.

The 31-character figure is C89's, and applies to a standard the library does not
claim: the `build-linux-c89-headers` lane proves the public headers are
*includable* from C89 code, not that the library is C89. Weigh all of this before
coining a class name as long as `MbedTlsHmacSha256Policy`.

### Platform classes carry their pack's registry token

`SOLIDSYSLOG_PLATFORM_REGISTRY` in the top-level `CMakeLists.txt` is the single
declaration of what a platform is. Its token already names the directory, the
CMake option and the docs page; it names the pack's classes too.

**Form:** `SolidSyslog<RegistryToken><Thing>` for every public class declared in
`Platform/<RegistryToken>/Interface/`.

```c
SolidSyslogPosixResolver_Create();     /* Platform/Posix   — not SolidSyslogGetAddrInfoResolver */
SolidSyslogOpenSslStream_Create(...);  /* Platform/OpenSsl — not SolidSyslogTlsStream */
```

Naming a class after the upstream function it happens to call costs the reader
the one thing the token buys: predicting where a class lives from its name, and
what it is from where it lives. Naming it after the **role** it fills is worse,
because two packs can fill one role — whichever claims the role name first makes
its sibling read as a special case of it, which is how `SolidSyslogMbedTlsStream`
came to look like a variant of `SolidSyslogTlsStream`.

A pack that wraps a genuinely distinct second upstream prefixes those classes
with that upstream instead: `Platform/Windows/` ships `SolidSyslogWinsock*`
beside `SolidSyslogWindows*`. That is an alias for the pack, agreed when the
second upstream is taken on, and not a licence to coin a prefix per class.

Note the deliberate opposite pull on pool-size tunables below: those are named
for the role, because the integrator sizes "how many TLS streams" without caring
which vendor fills them, while wiring the vendor's class by name.

### A platform's callbacks take the platform as their class

A pack also ships plain functions that fill a `SolidSyslogConfig` callback rather
than a class: the clock, the host name, the process id, the uptime and the sleep.
These have no instance, no `Create` and no vtable, so there is no class for the
`<Class>_` portion to name — and inventing one produces a function name with no
content left to carry.

**Form:** `SolidSyslog<RegistryToken>_<WhatItSupplies>`, matching the config field
it is assigned to.

```c
config.Clock        = SolidSyslogPosix_GetTimestamp;   /* not SolidSyslogPosixClock_GetTimestamp */
config.GetHostname  = SolidSyslogPosix_GetHostname;    /* not SolidSyslogPosixHostname_Get */
config.GetProcessId = SolidSyslogPosix_GetProcessId;
```

`_Get` as a whole function name is the shape this rule exists to stop: it passes
the `SolidSyslog<Class>_<Function>` regex while saying nothing, because the verb
is the only word left once the noun has been spent on the class.

The header **file** keeps the name of the thing it supplies —
`SolidSyslogPosixHostname.h` — so the platform-token rule above still holds over
every filename, and a reader looking for the host name callback still finds the
file by guessing it. This is the one place where the file name and the class name
in it differ, and it is deliberate: one file per thing supplied, one class per
platform.

---

## Tier 2 — Internal linkage (file-scope `static`)

**Form:** `Class_Function` for static functions, `Class_Variable` for
file-scope static variables and constants, **bare `PascalCase` for
file-scope struct tags that are never exported**. PascalCase
throughout. No `SolidSyslog` prefix at any Tier 2 site — the file
itself is the namespace.

```c
/* Inside Buffer.c */
static int  Buffer_AppendRecord(struct SolidSyslogBuffer* base, ...);
static void Buffer_ResetCursor(struct SolidSyslogBuffer* base);

static const struct SolidSyslogSecurityPolicy Buffer_DefaultPolicy = { /* ... */ };
static size_t                                 Buffer_ActiveInstanceCount;

/* File-scope helper structs that exist only to give a small group of
   fields a name within this .c file. Not visible to other TUs; not
   declared in any header. The tag is local to the file, so it does
   not carry the SolidSyslog namespace prefix. */
struct EscapedContext
{
    struct SolidSyslogFormatter* Formatter;
    const char*                  Source;
    size_t                       SourcePos;
    /* ... */
};

struct OpenHandle
{
    struct SolidSyslogFile* File;
    size_t                  BlockIndex;
    bool                    Open;
};
```

Rationale:

- Uniqueness across the library is achieved by the `Class_` prefix on
  Tier 2 functions and variables — `Buffer_AppendRecord` cannot
  collide with `Transport_AppendRecord` — which satisfies advisory
  rule 5.9. File-scope struct tags rely on internal-linkage scoping
  to the file (`static` storage classes for any objects of the type),
  which gives them the same uniqueness guarantee without needing a
  prefix.
- The visible difference from Tier 1 is the missing `SolidSyslog`
  prefix, which signals "internal" at the call site without comment.
  Both tiers use PascalCase on both sides of the underscore (or, for
  Tier 2 tags, bare PascalCase), so static helpers and public
  functions read consistently.
- One class per translation unit is the norm; if a `.c` file contains
  helpers for two classes, use both prefixes accordingly.

### Picking the `Class_` prefix from the filename

For source files matching `SolidSyslog<X>.c`, the Tier 2 class prefix
is `<X>_` — the filename with the `SolidSyslog` library namespace
stripped. So `SolidSyslogOpenSslStream.c` → `OpenSslStream_*`,
`SolidSyslogPlusTcpTcpStream.c` → `PlusTcpTcpStream_*`,
`SolidSyslogWinsockTcpStream.c` → `WinsockTcpStream_*`,
`SolidSyslogBlockSequence.c` → `BlockSequence_*`. Every file under `Core/` and
`Platform/` carries the prefix, so the rule has no second case.

The strip-only rule is mechanical and predictable; short-shorthand
prefixes (e.g. `Tls_`, `FrTcp_`, `WinTcp_`) were considered and
rejected — every file would need a hand-picked prefix, the choice
would be hard to predict at a call site, and the convention would
be harder to enforce going forward.

#### The `SolidSyslog.c` exception

`Core/Source/SolidSyslog.c` is the one file where the strip rule
yields an empty prefix (the file is the library namespace).
Statics in this file use **`SolidSyslog_<Function>`** — the same
shape as Tier 1 whole-library API entry points (`SolidSyslog_Log`,
`SolidSyslog_Service`, etc.). Linkage (`static`) distinguishes them
at definition; collision risk is zero because only one file can
ever be named `SolidSyslog.c`.

### When a Tier 2 tag DOES carry the `SolidSyslog` prefix

The implementation struct that corresponds to a Tier 1 opaque type
shares the public tag name verbatim. For example, `struct SolidSyslog`
is declared opaquely in `SolidSyslog.h` (Tier 1) and defined
concretely in `SolidSyslog.c`. The .c-side definition is technically
Tier 2 by linkage (it's where the struct's layout lives), but the
tag name is fixed by the Tier 1 public declaration. This is the
opaque-impl pattern; the .c-side use of the tag is not free to
choose its own name.

---

## Tier 3 — Function parameters and block-scope locals

**Form:** lowerCamelCase, no prefix, descriptive but compact. Domain
abbreviations (TLS, UDP, TCP, CRC, RFC, MQ, FAT) are permitted as words.

```c
int Buffer_AppendRecord(struct SolidSyslogBuffer* base,
                        const uint8_t*            record,
                        size_t                    recordLength)
{
    size_t bytesWritten   = 0U;
    size_t bytesRemaining = recordLength;
    /* ... */
}
```

Constraints:

- **Rule 5.3 (no shadowing).** Locals must not share a name with any
  file-scope static, any function parameter, or any enclosing block local.
  In practice this means avoiding generic names like `buffer`, `policy`,
  `state`, `count` inside a file whose statics use those words. Prefer
  `targetBuffer`, `activePolicy`, `currentState`, `recordCount`.
- **No single-letter identifiers.** Use short domain words instead:
  `index`, `count`, `cursor`, `byte`, `next`, `prev`. A loop over records
  is `for (size_t index = 0U; index < recordCount; ++index)`, not
  `for (i = ...)`.
- **No lazy abbreviations.** `buffer` not `buf`, `message` not `msg`,
  `configuration` not `cfg`, `pointer` not `ptr`. Distinguish lazy
  abbreviations from domain terms — the latter are the real names of
  things and should be used unmodified. Domain terms include:
  - RFC field names from specs the library implements (RFC 5424
      `MSG` / `MSGID` / `PRIVAL` / `BOM` / `SD` / `PROCID`).
  - Protocol and technology shorthands (`mq`, `crc`, `tls`, `tcp`,
      `udp`, `ip`, `dns`).
  - POSIX / Win32 idioms that mirror third-party signatures (`fd`,
      `errno`, `pid`, `sock`) — see also the Pragmatic-tier exemption
      in the Scope table for parameter locals in adapter wrappers
      (`buf` / `len` in `send` / `recv` wrappers, `attr` for
      `struct mq_attr`, etc.).
- **No pointer Hungarian.** Never prefix pointer variables with `p`/`P`
  or suffix with `Ptr`. Pointer-ness is visible from the declaration.
- **Booleans.** A boolean that names a *condition* takes an `isX`, `hasX`
  or `canX` shape - a predicate function (`BlockSequence_IsAboveThreshold`),
  or a variable whose name has to carry its meaning where it is read
  (`isValid`, `hasUnsent`, `canSend`). A short-lived local holding the
  outcome of the work the function has just done does not: `ok`, `parsed`,
  `released` are read next to the call that produced them, and a prefix adds
  length without adding meaning. The test is whether the name travels - a
  condition passed around or tested far from where it was set earns the
  prefix; a result returned three lines later does not.

### This-pointer parameters

The first parameter of a method-shaped function — the "this-pointer" — uses
one of two names, chosen by **the declared parameter type**, not by the
function's purpose:

- **`self`** — the declared parameter type is the function's own class
  (the concrete derived type, or for non-vtable classes simply the class).
  Applies to: every helper (`static`/`static inline`); every local
  introduced by a downcast; every public function whose first parameter is
  declared as the concrete class.

- **`base`** — the declared parameter type is the abstract base struct
  (one that exposes vtable function-pointer members — `SolidSyslogBuffer`,
  `SolidSyslogStore`, `SolidSyslogFile`, etc.). Applies to: every vtable
  entry-point implementation; every concrete-class `<Class>_Destroy` whose
  declared first parameter is the abstract base; every base-class
  helper or free utility operating polymorphically on the base.

The rule is mechanical: if the declared type is the abstract base, the
name is `base`; otherwise it is `self`. The function's role does not
enter the decision.

#### The downcast: `<Class>_SelfFromBase`

When a vtable entry point or a concrete-class `<Class>_Destroy` receives a
`base` and needs to operate on its concrete type, the downcast is named
and centralised, one `static inline` helper per derived class:

```c
static inline struct SolidSyslogCircularBuffer*
CircularBuffer_SelfFromBase(struct SolidSyslogBuffer* base)
{
    return (struct SolidSyslogCircularBuffer*) base;
}
```

Every entry point then reads:

```c
static bool CircularBuffer_Read(struct SolidSyslogBuffer* base,
                                void* data, size_t maxSize, size_t* bytesRead)
{
    struct SolidSyslogCircularBuffer* self = CircularBuffer_SelfFromBase(base);
    ...
}
```

#### The callback cast: `<Class>_SelfFromArg`

A third-party callback that hands back a `void*` context needs the same
treatment, for the same reason: the cast lives in one named place, so
MISRA 11.5 has a single suppression site rather than one per callback.
`SolidSyslogLwipRawTcpStream` registers itself with `tcp_arg(pcb, self)`
and recovers it in every lwIP callback:

```c
static inline struct SolidSyslogLwipRawTcpStream*
LwipRawTcpStream_SelfFromArg(void* arg)
{
    return (struct SolidSyslogLwipRawTcpStream*) arg;
}
```

There is no cast from caller-supplied *instance* storage. Every stateful
class is pool-allocated (E11), so `<Class>_Create` returns a slot pointer
from the class's static pool. Where a caller still supplies memory it
backs the payload rather than the instance — the ring handed to
`SolidSyslogCircularBuffer_Create` is the one public example, and the
buffer's own instance struct is still a pool slot pointing at it.

Helpers are named per Tier 2 (`Class_Function`, `static inline`, no
`SolidSyslog` prefix). Placement follows the function-ordering rule:
forward-declared with the other helpers at the top of the file,
defined immediately beneath the first caller.

#### Headers

Function-pointer member parameter names inside the public
`SolidSyslog<X>Definition.h` structs follow the same `base` rule —
because the declared type at those member declarations is the abstract
base. C ignores function-pointer parameter names at struct-member
declarations (only the type matters for ABI and callers), so this is a
documentation choice: matching the implementations reduces the
cognitive load on a reader who flips between header and implementation.

#### Shadowing

`self` and `base` are reserved at Tier 3 for the this-pointer role.
Files must not use either name for any other parameter or block-scope
local (avoids MISRA 5.3 shadowing the moment a nested helper is added).
They are also reserved at Tier 2 — no file-scope static should be named
`self` or `base`.

---

## Tier 4 — Struct members

**Form:** PascalCase, no prefix, no class qualifier. No member-kind
exceptions — data members and function-pointer (vtable) members both use
the same shape. The boolean and no-Hungarian conventions from Tier 3
do not apply at this tier — PascalCase carries the visual signal that
"this is a named, persistent piece of state" without needing an `is`/`has`
prefix to convey "this is a boolean."

The domain-term exemption from Tier 3 applies equally at Tier 4 —
`struct SolidSyslogMessage`'s members `MessageId` (the full English
word) and `Msg` (RFC 5424's spec label for the body field) are an
example of how the two forms legitimately co-exist when one is an
RFC abbreviation and the other is not.

```c
struct SolidSyslogSecurityPolicy
{
    SolidSyslogIntegrityCheck IntegrityCheck;
    SolidSyslogEncryption     Encryption;
    uint32_t                  MaximumRecordLength;
    bool                      Enabled;
};

/* Vtable function-pointer members follow the same rule — and have done
   so already in practice. The Tier 4 PascalCase convention is the
   project-wide policy that consolidates them. Parameter naming for the
   function-pointer members follows the Tier 3 this-pointer rule: the
   declared type is the abstract base struct, so the parameter is `base`. */
struct SolidSyslogStore
{
    bool (*Write)(struct SolidSyslogStore* base, const void* data, size_t size);
    bool (*ReadNextUnsent)(struct SolidSyslogStore* base, ...);
    void (*MarkSent)(struct SolidSyslogStore* base);
    bool (*HasUnsent)(struct SolidSyslogStore* base);
};
```

### Why PascalCase, and why not member-kind-dependent

PascalCase at the member access site gives a strong visual signal that
something named-and-persistent is being touched, distinct from the
lowerCamelCase of parameters and locals. `buffer->Position += count` reads
clearly as "field write"; `position += count` is a transient local. The
case shape encodes lifetime, not the member's kind.

The previous scheme used lowerCamelCase for data members and tolerated
PascalCase only for vtable function-pointer members "to mirror the
function name." That is the kind of implicit semantic encoding Clean Code
argues against — case meaning shifted based on what kind of thing the
member held. Tier 4 now states a single rule.

### The `struct X X;` shape

Because struct tags are also PascalCase (Tier 1), this convention
produces legal declarations like:

```c
struct SolidSyslogBlockStore
{
    struct SolidSyslogRecordStore   RecordStore;
    struct SolidSyslogBlockSequence BlockSequence;
};
```

The struct tag and the member identifier live in separate C namespaces,
so this is unambiguous to the compiler and to MISRA. To a reader it parses
naturally after one or two exposures — the `struct` keyword introduces
the type, the trailing identifier is the member.

### Uniqueness within a struct

Struct members live in their own name space, so MISRA does not require
uniqueness across structs. Access at the call site is already qualified
by the struct instance: `policy->IntegrityCheck` is self-documenting.

---

## No struct typedefs

SolidSyslog does not use `typedef struct` for its own struct types,
whether the type is opaque or value-typed. Code refers to struct types by
tag everywhere:

```c
/* Yes */
struct SolidSyslogBuffer*               buffer;
const struct SolidSyslogBuffer*         readOnlyBuffer;
struct SolidSyslogSecurityPolicy        policy;
const struct SolidSyslogSecurityPolicy* readOnlyPolicy;

/* No — do not introduce a typedef for any struct type */
typedef struct SolidSyslogBuffer         SolidSyslogBuffer;
typedef struct SolidSyslogBuffer*        SolidSyslogBufferHandle;
typedef const struct SolidSyslogBuffer*  SolidSyslogBufferConstHandle;
```

There are three reasons:

1. **Readability.** A typedef'd struct value type hides that it is a struct,
   and a typedef'd pointer-to-struct hides one level of indirection. Both
   make pointer and `const` placement ambiguous to the reader. The tag form
   keeps the type's nature visible at every declaration.

2. **MISRA Rule 5.6 plus header coupling.** A typedef is a *definition* and
   under Rule 5.6 must appear exactly once across the program — so it has to
   live in one canonical header. Any translation unit that wants to reference
   the typedef'd name must `#include` that header. By contrast, a tag
   forward declaration `struct SolidSyslogBuffer;` is not a definition and
   may be repeated wherever it is needed. Sticking to tags lets headers
   reference each other's types via local forward declarations and avoids a
   dense `#include` graph.

3. **The `const` trap.** `const SolidSyslogBufferHandle` does not mean
   "pointer to const buffer" — it means "const pointer to non-const buffer",
   because the `const` qualifies the typedef'd pointer rather than the
   pointee. The tag form `const struct SolidSyslogBuffer*` cannot be
   misread.

### Forward declarations are encouraged

In any header that needs to reference a struct only through a pointer, use
a local forward declaration rather than `#include`-ing the defining header.
This minimises header coupling and keeps compilation fast:

```c
/* SolidSyslogTransport.h — does not need to see Buffer's layout */
struct SolidSyslogBuffer;

int SolidSyslogTransport_Send(struct SolidSyslogTransport*    transport,
                              const struct SolidSyslogBuffer* source);
```

### Typedefs that are permitted

Typedefs are used only for:

- **Enum types** intended to be passed by value:
  `typedef enum SolidSyslogSeverity SolidSyslogSeverity;`
- **Function pointer types** in vtables:
  `typedef int (*SolidSyslogTransport_SendFn)(struct SolidSyslogTransport*, ...);`
- **Scalar aliases** where the underlying type is an implementation detail.
  Use sparingly.

---

## Macros

**Form:** `SOLIDSYSLOG_SCREAMING_SNAKE_CASE` for public macros,
`CLASS_SCREAMING_SNAKE_CASE` for file-scope macros.

```c
/* Public, in a header */
#define SOLIDSYSLOG_MAXIMUM_RECORD_LENGTH 2048U

/* File-scope, in Buffer.c */
#define BUFFER_RECORD_MAGIC 0xA53CU
```

Rule 5.4 requires macro uniqueness; rule 5.5 forbids reuse of a name as both
a macro and a non-macro identifier. The all-caps convention plus the prefix
handles both. (Note: macros use the joined `SOLIDSYSLOG_` form rather than
`SOLID_SYSLOG_` to match the existing codebase and avoid first-N-character
pressure from rule 5.4.)

**Exceptions:** CppUTest's `TEST`, `TEST_GROUP`, `CHECK_*`, `LONGS_EQUAL`,
etc. are used unmodified — see Tests below.

### Pool-size tunables are named by role, not platform

Every stateful Created class lives in a static pool sized by a
`SOLIDSYSLOG_..._POOL_SIZE` tunable (see CLAUDE.md, *Pool Allocation (E11)*).
For classes selected by platform or crypto vendor — where a build links
exactly one implementation of a given role — the tunable is named for the
**role**, not the implementation:

```c
#define SOLIDSYSLOG_TCP_STREAM_POOL_SIZE 2U   /* not _POSIX_TCP_STREAM_ */
#define SOLIDSYSLOG_MUTEX_POOL_SIZE      1U   /* not _POSIX_MUTEX_ / _WINDOWS_MUTEX_ */
#define SOLIDSYSLOG_TLS_STREAM_POOL_SIZE 1U   /* OpenSSL or Mbed TLS, one name */
```

The integrator reasons about "how many TCP streams", never "how many POSIX
streams". `SOLIDSYSLOG_ADDRESS_POOL_SIZE` established the pattern; the role
pools (`TCP_STREAM`, `DATAGRAM`, `RESOLVER`, `MUTEX`, `FILE`, `ATOMIC_COUNTER`,
`TLS_STREAM`, `HMAC_SHA256_POLICY`) follow it. Do not reintroduce a
per-platform pool name when adding a new OS, network stack, or crypto vendor —
the new implementation references the existing role tunable.

The pool counts **instances, not implementations**. The naming holds only
because a build links one implementation per role. If a future build ever
wires two implementations of the same role into one executable (e.g. the lwIP
numeric and DNS resolver, or two crypto vendors), size that role's pool to
the sum of the concurrent instances rather than splitting the name again.

Classes with no platform/vendor variants keep their class-specific name
(`SOLIDSYSLOG_BLOCK_STORE_POOL_SIZE`, `SOLIDSYSLOG_ORIGIN_SD_POOL_SIZE`, etc.).

### Enum constants

All enum constants — tagged or anonymous, public or TU-local — are
`SCREAMING_SNAKE`. One rule, mechanically enforced by clang-tidy
(`EnumConstantCase: UPPER_CASE`, no exceptions).

```c
/* Tagged public enum — Tier 1 type with named members */
enum SolidSyslogSeverity
{
    SOLIDSYSLOG_SEVERITY_EMERGENCY = 0,
    SOLIDSYSLOG_SEVERITY_ALERT     = 1,
    /* ... */
};

/* Anonymous public enum — Tier 1 macro-equivalent */
enum
{
    SOLIDSYSLOG_CIRCULAR_BUFFER_OVERHEAD = 7,
    SOLIDSYSLOG_CIRCULAR_BUFFER_HEADER_BYTES = sizeof(uint16_t)
};

/* Anonymous TU-local enum — Tier 2 macro-equivalent */
enum
{
    HEADER_BYTES = SOLIDSYSLOG_CIRCULAR_BUFFER_HEADER_BYTES
};
```

**Word boundaries.** Snake-separate at every CamelCase boundary in the
source identifier (`DatagramSendResult` → `DATAGRAM_SEND_RESULT`,
`AuthPriv` → `AUTH_PRIV`). Trailing digits stay glued to the preceding
word (`Local0` → `LOCAL0`).

**Project prefix.** Public sites (anywhere visible outside a single
TU) carry `SOLIDSYSLOG_`. TU-local anonymous-enum constants
(`IPV4_HEADER_BYTES`, `UINT32_MAX_DECIMAL_DIGITS`) don't. clang-tidy
cannot distinguish public from TU-local enum constants syntactically;
the prefix rule for public sites is enforced by review and by
cppcheck-misra rule 5.4 distinctness.

The anonymous-enum named-constant idiom is itself unchanged — it's
still the project's type-safe alternative to `#define` for integer
constants, distinct in shape from tagged enums in purpose if not in
casing. MISRA rule 2.4 (unused tag declarations) cppcheck-fires on
anonymous enums; the project-wide deviation **D.009** covers all such
sites — see `docs/misra-deviations.md#d009`.

A single rule is used deliberately, rather than splitting tagged-enum
constants (`SolidSyslog<Class>_Constant`, PascalCase, class-scoped) from
anonymous-enum constants (SCREAMING_SNAKE): that split is hard to enforce
mechanically, since only judgement separates the two cases.

---

## Tests

Test code uses production conventions where natural, with these relaxations:

- **lowerCamelCase locals** preferred but not enforced; no rename sweep of
  existing test code.
- **PascalCase for static test helpers** when present
  (e.g. `SpyGetHost`, `GetDefaultPort`).
- **CppUTest macros** (`TEST`, `TEST_GROUP`, `TEST_GROUP_BASE`, `TEST_BASE`,
  `CHECK_*`, `LONGS_EQUAL`, etc.) are used as-is — the identifiers they
  expand to (e.g. `TEST_GroupName_TestName_TestShell`) are exempt from
  Tier 1 and routinely exceed any character limit.
- **Test-helper macros** in test translation units (`CALLED_FAKE`,
  `CALLED_DATAGRAM_SEND`, `CHECK_REPORTED_ERROR`, etc.) use whatever
  SCREAMING_SNAKE shape reads well; no project prefix required.
- **Test fakes and spies** drop the `SolidSyslog` prefix
  (e.g. `SocketFake_Reset`, `DatagramFake_SendCallCount`) so they read
  obviously as test infrastructure at the call site.
- **Test group names** carry a `Test` suffix and the `SolidSyslog` prefix
  because `TEST_GROUP(...)` macros expand to external-linkage identifiers
  (rule 5.8). Three forms are permitted:

  ```c
  /* Class-level group, when the tests cover the class as a whole */
  TEST_GROUP(SolidSyslogBufferTest) { /* ... */ };

  /* Function-level group, when a single function deserves its own group */
  TEST_GROUP(SolidSyslogBuffer_AppendRecordTest) { /* ... */ };

  /* Integration group, exercising more than one class */
  TEST_GROUP(SolidSyslogIntegrationTlsStoreAndForward) { /* ... */ };
  ```

- **Test case names** use UpperCamelCase describing the behaviour:

  ```c
  TEST(SolidSyslogBufferTest, AppendsRecordWhenSpaceAvailable)
  {
      /* ... */
  }
  ```

No MISRA rules apply to test code. Test code converges to these
relaxations organically as it is touched, not via a sweep.

---

## Writing identifiers in prose

Comments and Markdown name an API function in full —
`SolidSyslogCircularBuffer_Create`, never a bare `_Create`. The elided
form reads as a typo, and it stops meaning anything the moment the
surrounding paragraph mentions a second class, which the header tables
in `CLAUDE.md` do on nearly every row.

Where the statement is about the pattern rather than about one class,
name the placeholder instead. `docs/porting.md` already writes
`SolidSyslog<Adapter>.h` for the same reason.

```text
SolidSyslogCircularBuffer_Create   a specific class is meant
<Class>_Destroy                    true of every class in the tree
_Create                            never
```

The rule covers prose only. Code is unaffected — every call site spells
the identifier in full already, because nothing else compiles.

Enforced by a grep guard in the `analyze-format` CI lane, which allows
the reserved identifiers that legitimately begin `_X` (`_Atomic`,
`_Bool`, `_Static_assert`, `_Exit`, and friends). This file is exempt
from the guard — it is the one place that has to quote the form it
forbids.

---

## Worked example

A small slice showing every tier in one place, including the derived-class
vtable shape with its `SelfFromBase` helper.

```c
/* Core/Interface/SolidSyslogBufferDefinition.h -------------------------- */

/* Tier 1 — abstract base struct with vtable function-pointer members.
   Function-pointer parameter names are `base` (Tier 3 this-pointer rule:
   declared type is the abstract base). */
struct SolidSyslogBuffer
{
    void (*Write)(struct SolidSyslogBuffer* base, const void* data, size_t size);
    bool (*Read)(struct SolidSyslogBuffer* base, void* data, size_t maxSize, size_t* bytesRead);
};

/* Core/Interface/SolidSyslogCircularBuffer.h ---------------------------- */

#define SOLIDSYSLOG_CIRCULAR_BUFFER_RING_BYTES(maxMessages) /* ... */

/* Tier 1 — public Create returns the base-class view. The caller supplies the
   backing ring, not the instance: the instance itself is a pool slot.
   SolidSyslogCircularBuffer_Destroy takes the base type (matches the
   abstract Buffer contract), so its parameter is `base`. */
struct SolidSyslogBuffer* SolidSyslogCircularBuffer_Create(
    struct SolidSyslogMutex* mutex, uint8_t* ring, size_t ringBytes
);
void SolidSyslogCircularBuffer_Destroy(struct SolidSyslogBuffer* base);

/* Core/Source/SolidSyslogCircularBuffer.c ------------------------------- */

#include "SolidSyslogCircularBuffer.h"
#include "SolidSyslogBufferDefinition.h"

/* Tier 2 — concrete struct definition (uses the public tag verbatim per
   the opaque-impl pattern). */
struct SolidSyslogCircularBuffer
{
    struct SolidSyslogBuffer Base;
    /* ... per-instance state ... */
};

/* Tier 2 — vtable entry points: declared type is the abstract base, so
   parameters are `base`. */
static bool CircularBuffer_Read(struct SolidSyslogBuffer* base, void* data, size_t maxSize, size_t* bytesRead);
static void CircularBuffer_Write(struct SolidSyslogBuffer* base, const void* data, size_t size);

/* Tier 2 — named downcast helper. */
static inline struct SolidSyslogCircularBuffer*
CircularBuffer_SelfFromBase(struct SolidSyslogBuffer* base);

/* Tier 2 — internal helpers: declared type is the concrete class, so
   parameters are `self`. */
static inline bool CircularBuffer_IsEmpty(const struct SolidSyslogCircularBuffer* self);

/* Core/Source/SolidSyslogCircularBufferStatic.c ------------------------- */

struct SolidSyslogBuffer* SolidSyslogCircularBuffer_Create(
    struct SolidSyslogMutex* mutex, uint8_t* ring, size_t ringBytes
)
{
    /* Tier 3 — `index` and `handle` are locals; the pool slot is the instance,
       so there is no cast from caller-supplied storage. On exhaustion the
       shared NullBuffer is returned and the caller keeps running. */
    size_t index = SolidSyslogPoolAllocator_AcquireFirstFree(&CircularBuffer_Allocator);
    struct SolidSyslogBuffer* handle = SolidSyslogNullBuffer_Get();
    if (SolidSyslogPoolAllocator_IndexIsValid(&CircularBuffer_Allocator, index))
    {
        SolidSyslogCircularBuffer_Initialise(&CircularBuffer_Pool[index].Base, mutex, ring, ringBytes);
        handle = &CircularBuffer_Pool[index].Base;
    }
    return handle;
}

void SolidSyslogCircularBuffer_Destroy(struct SolidSyslogBuffer* base)
{
    struct SolidSyslogCircularBuffer* self = CircularBuffer_SelfFromBase(base);
    self->Base.Read  = NULL;
    self->Base.Write = NULL;
    /* ... */
}

static inline struct SolidSyslogCircularBuffer*
CircularBuffer_SelfFromBase(struct SolidSyslogBuffer* base)
{
    return (struct SolidSyslogCircularBuffer*) base;
}

static bool CircularBuffer_Read(struct SolidSyslogBuffer* base, void* data, size_t maxSize, size_t* bytesRead)
{
    /* Tier 3 — `base` is the abstract-base this-pointer the vtable hands us;
       downcast names the concrete view as `self`. */
    struct SolidSyslogCircularBuffer* self = CircularBuffer_SelfFromBase(base);

    bool delivered = !CircularBuffer_IsEmpty(self);
    /* ... */
    return delivered;
}

static inline bool CircularBuffer_IsEmpty(const struct SolidSyslogCircularBuffer* self)
{
    /* ... */
}
```

---

## Quick reference

| Identifier kind                       | Form                                       | Example                                    |
|---------------------------------------|--------------------------------------------|--------------------------------------------|
| Public function                       | `SolidSyslogClass_Function`                | `SolidSyslogBuffer_Append`                 |
| Public struct tag                     | `SolidSyslogClass`                         | `struct SolidSyslogBuffer`                 |
| Platform pack class                   | `SolidSyslogRegistryTokenThing`            | `SolidSyslogPosixResolver`                 |
| Public enum type                      | `SolidSyslogClass`                         | `enum SolidSyslogSeverity`                 |
| Public enum constant                  | `SOLIDSYSLOG_CLASS_CONSTANT`               | `SOLIDSYSLOG_SEVERITY_EMERGENCY`            |
| Class error code                      | `SOLIDSYSLOG_CLASS_ERROR_NAME`             | `SOLIDSYSLOG_CIRCULAR_BUFFER_ERROR_POOL_EXHAUSTED` |
| Public macro                          | `SOLIDSYSLOG_SCREAMING_SNAKE`              | `SOLIDSYSLOG_MAXIMUM_RECORD_LENGTH`        |
| Public typedef (enum/fn-pointer only) | `SolidSyslogClass` / `SolidSyslogClass_Fn` | `SolidSyslogTransport_SendFn`              |
| Static function                       | `Class_Function`                           | `Buffer_WriteMagic`                        |
| Static variable / constant            | `Class_Variable`                           | `Buffer_DefaultPolicy`                     |
| File-scope macro                      | `CLASS_SCREAMING_SNAKE`                    | `BUFFER_RECORD_MAGIC`                      |
| Function parameter / local            | `lowerCamelCase`                           | `recordLength`, `bytesAvailable`           |
| This-pointer parameter                | `self` (own type) / `base` (abstract base) | `* self` in helpers; `* base` in vtable impls |
| Downcast helper                       | `Class_SelfFromBase` / `Class_SelfFromArg`  | `CircularBuffer_SelfFromBase`              |
| Boolean condition / predicate         | `isX` / `hasX` / `canX`                    | `isValid`, `hasUnsent`                     |
| Boolean result local                  | short domain word, lowerCamelCase          | `ok`, `parsed`, `released`                 |
| Loop variable                         | short domain word, lowerCamelCase          | `index`, `count`, `cursor`                 |
| Struct member                         | `PascalCase`                               | `WriteCursor`, `IntegrityCheck`, `Write` (function-pointer member) |
| Test group (class)                    | `SolidSyslogClassTest`                     | `SolidSyslogBufferTest`                    |
| Test group (function)                 | `SolidSyslogClass_FunctionTest`            | `SolidSyslogBuffer_AppendTest`             |
| Test group (integration)              | `SolidSyslogIntegrationDescription`        | `SolidSyslogIntegrationTlsStoreAndForward` |
| Test case                             | `UpperCamelCaseSentence`                   | `AppendsRecordWhenSpaceAvailable`          |
| Identifier in prose                   | full name, or `<Class>_Function`           | `SolidSyslogCircularBuffer_Create`         |

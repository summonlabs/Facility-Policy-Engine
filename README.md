# Facility Policy Engine

Facility Policy Engine is the deterministic facility-wide policy evaluation runtime. It answers one question, and refuses to
answer any other:

> **Given one exact published policy generation and one typed, generation-tagged set of
> authoritative facility facts, what does facility policy decide, why did it decide that,
> and is that decision still current?**

It owns the policy representation, the evaluation, and the durable publication of policy
generations. It does not own, read, or invent the facility state it reasons about, and it
never performs the action a decision authorizes.

---

## Contents

- [Core question](#core-question)
- [Owned boundary](#owned-boundary)
- [Explicit non-ownership](#explicit-non-ownership)
- [Principal invariants](#principal-invariants)
- [The policy model](#the-policy-model)
- [Decision semantics](#decision-semantics)
- [Authority, generations, and fencing](#authority-generations-and-fencing)
- [Persistence and recovery](#persistence-and-recovery)
- [Concurrency model](#concurrency-model)
- [Error and refusal semantics](#error-and-refusal-semantics)
- [Command line interface](#command-line-interface)
- [Library integration](#library-integration)
- [Building, testing, and installing](#building-testing-and-installing)
- [Validation performed](#validation-performed)
- [Hardening defects found and fixed](#hardening-defects-found-and-fixed)
- [Benchmarks](#benchmarks)
- [SYNTHETIC versus REAL validation](#synthetic-versus-real-validation)
- [Unsupported and unvalidated behavior](#unsupported-and-unvalidated-behavior)
- [License](#license)

---

## Core question

A facility control plane has many authoritative sources: capacity, physical placement,
maintenance windows, tenancy, incident state, service class, entitlement, and operational
authority. Each of those is owned by a different runtime. None of them should contain a copy
of facility-wide policy, and none of them should be trusted to interpret policy consistently
with the others.

Facility Policy Engine is the single place where facility policy is written down, validated,
digested, published, evaluated, and explained. Its contribution is not "a rule engine". Its
contribution is that a decision made here is *attributable and fenceable*: it names the exact
policy generation, the exact policy digest, the exact authoritative input digest and the
authority generations behind it, the rules that matched, the rules that could not decide and
why, and the control epoch it belongs to. Given those, another runtime can tell whether the
decision is still current, or whether policy moved underneath it.

---

## Owned boundary

This repository owns:

- the canonical policy bundle and ruleset representation and its lifecycle
  (document -> validated -> canonical -> digested -> published generation);
- deterministic evaluation of a canonical policy bundle over typed authoritative inputs;
- rule applicability, precedence, conflict detection, decision composition, explanation, and
  provenance;
- explicit ```allow```, ```refuse```, ```unknown```, and ```defer``` semantics;
- generation-bound decision artifacts that consumers can bind to and fence;
- safe evolution from one policy generation to another, including hot reload and the fencing
  of decisions made under a superseded generation or a superseded store incarnation;
- a durable, single-writer, append-only store of published policy generations, with an
  integrity-checked format, an atomic commit point, and explicit recovery;
- the ```fpe``` command line tool and the installable CMake package.

## Explicit non-ownership

This repository does **not** own, and does not attempt to obtain:

- **The authoritative state of anything.** Tenant identity, capacity, placement topology,
  maintenance state, incident state, service class, and entitlement are facts that an
  adjacent runtime asserts. This runtime receives them as typed values with a presence state
  and a provenance, validates their shape and bounds, and reasons about them. It never reads
  a facility system itself, never polls, never subscribes, and never derives a fact's state
  from a clock.
- **The execution of any resulting action.** A decision artifact is a record, not an effect.
  Nothing in this repository drains a node, moves a workload, opens a ticket, or notifies a
  tenant. Obligations in a decision are names a consumer must act on.
- **ASI or DFI policy engines.** Those are separate boundaries with separate rule languages
  and separate authority.
- **Arbitrary scripting.** The policy language is a closed, typed, bounded predicate model.
  There is no embedded interpreter, no expression evaluation, no user-defined function, no
  arithmetic, no string manipulation, and no facility to call out. A policy bundle is data.

---

## Principal invariants

1. **Observation is not authority.** A fact is only usable when its owning authority says it
   was observed, and only while that observation is valid at the evaluation instant.
2. **Unknown is a value, never a default.** Missing, unknown, stale, expired, unsupplied, and
   type-conflicting inputs are all distinct, and all of them remain unknown through
   evaluation. None of them can become false, zero, healthy, permitted, or safe.
3. **A contradiction never resolves to allow.** Two hard rules of equal priority that disagree
   produce a refusal that says so.
4. **An unproven rule grants nothing.** A rule whose applicability cannot be established does
   not permit; and while such a rule sits at or above the deciding priority, nothing else
   permits either.
5. **The only fail-open behaviour is declared, per rule, and always reported.** A rule may
   declare ```on_unknown: skip```. When it does and it is skipped, the artifact sets
   ```failed_open``` and lists the rule.
6. **A decision belongs to one policy generation and one control epoch.** It carries both, and
   fencing compares both.
7. **Order does not matter unless priority says it does.** Semantically identical policies
   written in different insertion orders have the same digest and produce the same outcome.
8. **A refusal is safe; a grant is not.** The engine will refuse while inputs are unknown. It
   will not permit while they are.
9. **Every durable byte is verified before it is interpreted.** Magic, format version, record
   kind, declared length, checksum, and digest, in that order.
10. **A store either yields exactly one verified authoritative generation or fails closed.**
    It never guesses, never merges, and never starts empty when durable state exists.

---

## The policy model

A **policy bundle** is a JSON document with a closed schema. Everything in it is bounded:
identifier lengths, text lengths, rule counts, fact counts, named-predicate counts, condition
depth, condition node counts, operand collection sizes, obligations per rule, expression
steps, and canonical byte size. The defaults are well below the hard ceilings, and no caller,
configuration file, or bundle can raise a ceiling.

### Facts

A fact is declared with a key, a value domain, and optionally the authority that owns it, the
scope it belongs to, and whether the bundle requires it:

```json
{"key": "zone.temperature", "type": "quantity", "authority": "thermal-control", "required": true}
```

The value domains are closed: ```boolean```, ```integer```, ```symbol```, ```text```, ```symbol-set```,
and ```quantity``` (an integer magnitude with an explicit unit symbol). There is no floating
point anywhere in the model, so a policy number can never quietly become a rounded double.

At evaluation time a fact arrives with a **presence state**: ```observed```, ```missing```,
```unknown```, or ```stale```. Only ```observed``` carries a value, and a document that supplies a
value for a non-observed fact is rejected rather than interpreted.

A fact may also carry provenance: an authority identity, that authority's generation, and a
digest of the evidence. Provenance is all-or-nothing. Every decision artifact lists every
distinct authority generation that contributed to it.

### Conditions

Conditions are a bounded, closed expression language over declared facts:

```json
{"all": [ ... ]}
{"any": [ ... ]}
{"not": { ... }}
{"test": {"fact": "zone.temperature", "op": "greater-or-equal", "operands": [{"magnitude": 35, "unit": "celsius"}]}}
{"named": "zone.hot"}
```

The operators are ```exists```, ```not-exists```, ```is-unknown```, ```is-stale```, ```is-missing```,
```equals```, ```not-equals```, ```less-than```, ```less-or-equal```, ```greater-than```,
```greater-or-equal```, ```in-set```, ```contains-all```, and ```contains-any```. Every operand is
type-checked against the declared fact domain when the bundle is compiled, so a type error is
a policy defect found at publication time rather than a surprise at decision time.

Ordering comparisons are permitted only for ```integer``` and ```quantity```, where the meaning of
"less than" is unambiguous. A quantity comparison between two different units evaluates to
unknown: the engine performs no unit conversion and will not claim two magnitudes are
comparable when it cannot know that they are.

**Named predicates** are reusable conditions. They may reference each other, and the graph is
checked for cycles at compile time, deterministically and with the cycle named in the error.

### Rules

```json
{
  "id": "refuse.hot.zone",
  "priority": 100,
  "effect": "refuse",
  "on_unknown": "fail-closed",
  "when": {"named": "zone.hot"},
  "prerequisites": ["zone.temperature"],
  "obligations": ["notify.tenant"],
  "reason": "thermal.zone-too-hot",
  "description": "Refuse work in a zone above the thermal limit"
}
```

- ```priority``` decides which rules are even considered: only the highest priority band that is
  not provably inapplicable can decide.
- ```effect``` is ```allow```, ```refuse```, or ```defer```.
- ```prerequisites``` name facts that must be fresh observations for the rule to decide at all.
  They are reported individually when they are not.
- ```on_unknown``` is the rule's explicit statement about its own uncertainty: ```fail-closed```
  (the default, undecided), ```refuse``` (an explicit refusal because the prerequisite is
  unknown), or ```skip``` (the only fail-open behaviour, and it is recorded).
- ```obligations``` attach to a permission, and the artifact lists the union of the obligations
  of the rules that actually decided the grant.
- ```reason``` is a stable machine identity; ```description``` is bounded human text.

### Bundles and imports

A bundle may import other bundles. An import binds to the **exact digest** of the imported
canonical bundle:

```json
{"imports": [{"bundle": "thermal.limits", "digest": "6f1c...e4"}]}
```

There is no version range and no "latest". A policy set cannot silently pick up a different
upstream bundle, because a different bundle has a different digest and the import is refused.
Import graphs must be acyclic; a cycle is refused with the path named. A bundle may reference
facts and named predicates declared by its imports, and a conflicting redeclaration across
bundles is refused rather than resolved by precedence.

### Canonical form and digest

A canonical bundle is serialized as canonical JSON: UTF-8, object members in byte order,
integers only, no insignificant whitespace, and the shortest escape for every string byte.
Facts, predicates, rules, imports, prerequisites, and obligations are stored in canonical
order. The bundle digest is SHA-256 over those bytes.

The consequence is a proof obligation this repository tests directly: two documents that mean
the same thing digest identically no matter how their rules, facts, and predicates were
ordered, and produce identical decisions.

---

## Decision semantics

### Three-valued appraisal

Every condition is evaluated in Kleene three-valued logic over the facts, giving true, false,
or unknown. The appraisal of a single fact is what turns an authoritative claim into a
policy-relevant one:

| Fact state | ```exists``` | ```not-exists``` | ```is-unknown``` | ```is-stale``` | ```is-missing``` | comparison |
|---|---|---|---|---|---|---|
| not supplied | unknown | unknown | unknown | unknown | unknown | unknown |
| observed, fresh | true | false | false | false | false | evaluated |
| observed, expired | false | true | false | false | false | unknown |
| observed, deadline declared, no evaluation instant given | unknown | unknown | false | false | false | unknown |
| stale | false | true | false | true | false | unknown |
| missing | false | true | false | false | true | unknown |
| unknown | unknown | unknown | true | false | false | unknown |
| type conflict with the policy declaration | unknown | unknown | unknown | unknown | unknown | unknown |

Two rows deserve emphasis. A fact that was never supplied is **unknown**, not missing: claiming
it does not exist would assert something the caller never asserted. And a fact that declares a
validity deadline is **never** silently treated as current when the caller does not say which
instant the decision is for.

### Composition

Only one priority band decides: the highest priority among rules that are not provably
inapplicable. Within that band, in order:

1. **Refuse.** Any matched refusal decides, even when other rules in the band are undecided.
   If a matched permission is in the same band, the result is still refuse and
   ```contradictory_hard_rules``` is set.
2. **Defer.** A matched deferral decides, unless an undecided rule sits in the same band, in
   which case the outcome is unknown.
3. **Allow.** A matched permission decides only when no rule in the band is undecided and the
   bundle's required facts are all fresh observations. Obligations are collected from the
   permissions that decided.
4. Otherwise the outcome is **unknown**: the band holds only undecided rules, and being unable
   to establish permission is not permission.

When no band has any rule that could decide, the bundle's declared ```default_outcome``` applies.
It may be ```unknown``` (the default) or ```refuse```. It may not be ```allow```.

### Outcomes

- **allow** — permission established, with the obligations of the deciding rules.
- **refuse** — prohibition established, either by a matched refusal or by a rule that declared
  that its own uncertainty means refusal.
- **defer** — no rule in the deciding band established permission or prohibition, and none was
  undecided either: the decision is explicitly not this engine's to make.
- **unknown** — permission could not be established. This is a decision, not an error, and it
  carries the same full attribution as any other.

### Explanation

Every artifact carries an ordered, bounded explanation: the outcome and the band that decided
it, one line per rule that was not provably inapplicable (its effect, its disposition, its
cause, its reason code, and the facts that stopped it), one line per unresolved required fact,
and one line per contributing authority generation. A refusal is always attributable to
specific rules, facts, generations, or constraints. If it were not, that would be the defect.

---

## Authority, generations, and fencing

Four counters and one digest identify authority in this subsystem:

| Identity | Meaning | Advances when |
|---|---|---|
| **policy generation** | Which published policy set is authoritative | A new bundle is published |
| **publication sequence** | Durable ordering of publications, distinct from the generation number | A new bundle is published |
| **control epoch** | Which store incarnation owns the store | Any writer opens the store, even if it publishes nothing |
| **revision** | The author's revision of a bundle document | The author says so |
| **bundle digest** | The exact content of the policy | The content changes |

A decision artifact carries the policy generation, the control epoch, the bundle identity,
the bundle revision, the bundle digest, the input digest, and the authority generations behind
the inputs. Fencing a decision against the policy state a consumer currently trusts produces
exactly one specific diagnosis:

| Fence result | Meaning |
|---|---|
| ```current``` | The decision was produced by exactly the policy state that is current |
| ```artifact-digest-mismatch``` | The artifact's own digest does not match its contents |
| ```evaluator-revision-changed``` | A different evaluator revision produced the decision |
| ```bundle-changed``` | A different bundle, or a different revision of the same bundle |
| ```unbound-decision``` | The decision is not bound to a published generation |
| ```unbound-current-policy``` | The current policy is not bound to a published generation |
| ```stale-generation``` | A newer policy generation is current |
| ```generation-regressed``` | The current generation is older than the one the decision names |
| ```stale-epoch``` | A newer store incarnation is current |

Checks are applied in that fixed order, so the same situation always produces the same
diagnosis rather than a generic failure.

**Hot reload** is explicit. ```PolicyRuntime::reload()``` re-reads the manifest and picks up a
newer published generation, reporting whether the policy actually changed. Decisions produced
before a reload are unchanged and still verify; they are simply no longer current, and the
fence says so. Nothing is inherited across a policy change, and nothing is inherited across a
restart: the first writer to open a store after a crash publishes a new control epoch, which
fences every decision made before it.

---

## Persistence and recovery

### Layout

```
<store>/
  MANIFEST.bin      fixed 184-byte record; atomically replaced; names the current generation
  LOCK              the single-writer lock file; never read, only held
  gen/<16 hex>.fpg  immutable published generation records
```

### Format

Every record is little-endian and fixed-layout:

- magic, format version, record kind, and reserved fields, all validated;
- a 32-bit CRC over the fixed header, and a second CRC over the payload, so accidental
  corruption and deliberate substitution are distinguishable in diagnostics;
- a 32-bit CRC of the empty payload in the manifest, which must be zero: a real check, not a
  decorative field;
- a SHA-256 digest over the fixed header (excluding the digest field) followed by the payload;
- an exact declared payload length, so a truncated or extended file is refused rather than
  partially interpreted.

The generation record also carries the store identity, so a manifest can be rebuilt from a
record without reading the manifest being replaced.

### Publication and the commit point

Publication is: encode the record -> create the staging file exclusively -> write -> flush ->
close -> read back and compare byte for byte -> atomically replace the generation record ->
encode the new manifest -> stage -> flush -> read back and verify -> atomically replace the
manifest.

**The commit point is the atomic replacement of the manifest.** Before it, the store still
reports the previous generation and the new record is invisible. After it, the new generation
is authoritative. A crash anywhere before it leaves the previous state exactly as it was, plus
at most one abandoned staging file, which the next publication clears.

A published generation is self-contained: it carries the root bundle and every bundle it
imports, in dependency order. A later reader resolves the whole policy set from the published
bytes alone, with no external documents and no compiler.

### Recovery

Opening a store verifies the manifest, the generation record it names, and that the two agree
on generation, sequence, store identity, record digest, and policy digest. If any of that
fails, the store refuses to open, and a writer opens in a recovery-required state where it
refuses to publish.

Recovery is explicit and never guesses. The operator names exactly one generation;
```recover_to``` verifies that record completely, verifies its link to its predecessor, and
rebuilds the manifest from it under a control epoch strictly newer than every epoch any record
in the store has ever named — so recovery itself cannot resurrect authority that a previous
incarnation held.

A store whose manifest is missing while generation records are present is not an empty store.
It fails closed with ```corrupt-manifest```, and the message says to open a writer and recover an
explicit generation.

### Rollback protection

Each generation record links to its predecessor by digest, and the manifest carries a
monotonic publication sequence and a rollback floor. Opening refuses a manifest whose
generation is below its own floor. A record that does not link to its predecessor, a sequence
that does not increase, or a store identity that changes mid-history are all refused.

A store directory that is rolled back *in its entirety* — manifest, records, and all — is
internally consistent, and nothing inside it can reveal the rollback. That is what **anchors**
are for. ```fpe store anchor``` writes a small out-of-band document recording the store identity,
generation, sequence, and manifest digest, and ```--anchor``` checks a store against it. Without
an anchor, this subsystem can prove internal consistency and the absence of partial rollback,
and the documentation says exactly that rather than implying more.

**Compaction and snapshots.** There are none, deliberately. Generations are immutable and
append-only, so there is no rewrite path that could construct a state the ordinary reader
would refuse. Growth is bounded by the operator's own publication rate and by the rollback
floor.

---

## Concurrency model

**The library uses no mutexes, no condition variables, no threads, and no callbacks.** Every
lock it takes is an operating-system lock, and every operation completes synchronously.

- **Readers take no lock at all.** Any number of processes may read while a writer publishes.
  A reader verifies the manifest and the generation record it names, and observes either the
  generation that was current when it read or a later one; a partially written generation is
  never visible, because a generation record is written and flushed under a staging name
  before it is renamed, and the manifest that names it is replaced atomically afterwards.
- **The writer lock is the store's ```LOCK``` file**, opened with a share mode that permits other
  readers but denies a second writer. A second writer in this or any other process is refused
  with ```lock-held```. The kernel releases the lock when the holding process exits for any
  reason, including abrupt death, so a crashed writer never leaves a store permanently
  unwritable. This is proved with real processes, including a real abrupt kill.
- **A stale view cannot be held by accident.** ```head()``` returns a copy, so a caller cannot
  keep a reference into cached state across ```refresh()``` and observe a changed or torn value.
- **Publication performs durable I/O while the writer lock is held**, and that is not
  avoidable: the lock *is* the mutual exclusion for publication, and releasing it between the
  record write and the manifest write would let two writers interleave. Readers are unaffected
  because they take no lock.

Thread safety is therefore stated per object rather than globally:

- **Safe to call concurrently on distinct or shared read-only inputs:** ```evaluate```,
  ```appraise_inputs```, ```parse_json```, ```to_canonical_json```, ```require_canonical_json```,
  ```Digest256::of```, ```bundle_from_json```, ```canonicalize_bundle```,
  ```compile_standalone_bundle```, ```input_set_from_json```, ```artifact_from_json```,
  ```artifact_to_json```, ```artifact_document```, ```verify_artifact```,
  ```compute_artifact_digest```, ```fence_decision```, and every name and helper function.
- **One thread at a time per handle:** ```StoreReader``` (```refresh```, ```policy```,
  ```current_policy``` update cached state), ```StoreWriter``` (a writer is single by construction),
  ```BundleCompiler```, and ```PolicyRuntime```, which owns a reader. Concurrent *handles* are safe;
  concurrent use of one handle is not.

### Reentrancy, lock order, and lifetime audit

The concurrency contract was audited by inspecting ownership and call paths, not only by
testing:

- **No read-lock to write-lock upgrade exists**, because there is no in-process lock to
  upgrade: readers take nothing and the writer takes exactly one operating-system lock.
- **No write lock is re-entered.** ```publish```, ```raise_floor```, and ```recover_to``` call
  encoding, file-system, and digest helpers only; none of them reaches back into the writer.
- **No callback, observer, or log sink is invoked anywhere**, so nothing can run beneath a
  held lock.
- **No lock ordering exists to invert**, because exactly one lock exists in the whole library.
- **Nothing joins, waits on, or is waited on by a worker**, because the library creates no
  threads and no asynchronous work.
- **Cancellation and shutdown do not reverse any order.** ```StoreWriter::close()``` closes the
  lock handle and nothing else; destruction closes it too, and closing twice is harmless.
- **Stale asynchronous completion is not possible**, because nothing is asynchronous. A
  decision is produced synchronously under a named generation and epoch, and fencing is what
  detects that policy moved afterwards.
- **Handles are RAII values.** The store's file handles are non-copyable move-only owners; the
  only raw handles are inside the platform layer's ```FileHandle```, closed by its destructor. No
  path returns a borrowed handle.

---

## Error and refusal semantics

Failures are values, not exceptions and not sentinel returns. A ```Status``` carries exactly one
highest-precedence failure code plus any suppressed failures as secondary evidence, so a
refusal never loses the conditions that contributed to it.

Codes are grouped, and the numeric value *is* the precedence. When several failures coexist,
the lowest code is reported and the others are kept:

| Group | Stage |
|---|---|
| 1xx | address, path, existence |
| 2xx | operating system, locking, I/O durability |
| 3xx | durable container format: magic, version, kind, length, checksum, digest |
| 4xx | semantic range, counters, store state |
| 5xx | identity, text, encoding |
| 6xx | JSON document |
| 7xx | policy schema, references, cycles, compatibility |
| 8xx | resource limits |
| 9xx | evaluation, decision, fencing |

Two consequences matter in practice. A structural precondition — a buffer long enough to hold
the fixed fields — is checked before field-level validation, because the fields cannot be read
otherwise; everything after that follows the table. And a limit breach produces no decision at
all rather than a decision of convenience: the evaluator reports ```evaluation-limit-reached```
and returns no artifact.

The CLI maps outcomes to exit codes so that a script never has to parse output: ```0``` for a
completed command whose decision was allow, ```1``` for a tool failure, ```2``` for refuse (or a
decision that is no longer current), and ```3``` for unknown or defer.

---

## Command line interface

```
fpe <command> [options]

Policy documents
  policy check <document.json>            Compile and report identity and digest
  policy digest <document.json>           Print the canonical policy digest
  policy canonicalize <document.json>     Print the canonical JSON form
  policy compile --root <id> <doc>...     Compile a set with imports

Durable store
  store create <dir>                      Create an empty store
  store publish <dir> --root <id> <doc>...  Publish a new policy generation
  store show <dir>                        Report the current generation
  store verify <dir>                      Verify the manifest and history
  store recover <dir> --generation <n>    Rebuild the manifest from one generation
  store floor <dir> --generation <n>      Raise the rollback floor
  store anchor <dir> --out <file>         Write an out-of-band anchor

Decisions
  eval <dir> --input <facts.json>         Evaluate the current generation
  appraise <dir> --input <facts.json>     Report how every declared fact is seen
  decision verify <artifact.json>         Verify a decision artifact
  selftest                                Run built-in known-answer checks
```

### A complete worked example

```console
$ fpe policy check thermal.json
bundle          facility.thermal
revision        1
digest          5a1c68bb4126e07bd0525feb473e5516de0141afb13c3c53d893a93aadfc1ac5
canonical bytes 921
rules           2
facts           2
predicates      1
imports         0

$ fpe store create ./facility-policy
store            d3d24a3ad45a4d82a0ae89aab12c8556
generation       0
control epoch    1
sequence         0
rollback floor   0
manifest digest  de3a2e1bf564722bad80180e4d763efe437504b4623224b0dc67a36c51b4bb06
record digest    0000000000000000000000000000000000000000000000000000000000000000
policy digest    0000000000000000000000000000000000000000000000000000000000000000

$ fpe store publish ./facility-policy --root facility.thermal thermal.json
published generation 1 bundle facility.thermal digest 5a1c68bb4126e07bd0525feb473e5516de0141afb13c3c53d893a93aadfc1ac5

$ fpe store verify ./facility-policy
verified 1 generation record(s)
  generation 1 sequence 1 epoch 2 record f4480bfc3f984709 policy 5a1c68bb4126e07b

$ fpe eval ./facility-policy --input facts.json
refuse: bundle 'facility.thermal' revision 1 digest 5a1c68bb4126e07b generation 1 epoch 2 input d2ce31370dadcc86 rules 2 (matched 2, refused 1, undecided 0)
artifact digest  b58e3e27431c8c7c132388780de39669f54d2d193fd86a68aba361de21d762a7
  outcome refuse decided at priority 100
  rule 'allow.occupied' priority 50 effect allow -> matched (none) reason tenancy.known-occupant
  rule 'refuse.hot.zone' priority 100 effect refuse -> matched (none) reason thermal.zone-too-hot
  authority 'tenant-registry' generation 2 digest 2222...2222
  authority 'thermal-control' generation 4 digest 1111...1111
```

The exit code is ```2```, because the decision was a refusal. A script that only needs the
outcome never has to parse the text.

### Machine-readable output and verification

```console
$ fpe eval ./facility-policy --input facts.json --json > decision.json
$ fpe decision verify decision.json --store ./facility-policy
artifact digest  701348daca21013d629f121830b1524d29c7d62b5dd7c9feb4e9c84ab99c90a2
outcome          refuse
bundle           facility.thermal
bundle digest    5a1c68bb4126e07bd0525feb473e5516de0141afb13c3c53d893a93aadfc1ac5
input digest     d2ce31370dadcc862b2e73f65bfc7d37b1c33a4c3cdfba5a42a780c1a6bef4e6
fence            current
fence detail     decision matches the current policy generation and control epoch
```

Editing one byte of ```decision.json``` makes the verification fail rather than succeed with a
different decision.

### Detecting a rollback

```console
$ fpe store anchor ./facility-policy --out policy.anchor
anchored generation 1 sequence 1 manifest e24b97d71c5365e1e26b93e26fbdf829d1e106d27faef4a39dee24dc70afdffb to policy.anchor

$ fpe store verify ./facility-policy --anchor policy.anchor
verified 1 generation record(s)

# ... the store directory is destroyed and recreated empty ...
$ fpe store verify ./facility-policy --anchor policy.anchor
store verify: digest-binding-mismatch: anchor names store 367dd30c... but this store is ...
```

Recreating the store produces a directory that is internally consistent in every byte. Only
the out-of-band anchor can reveal that it is not the store the operator had.

### Self-verification

```console
$ fpe selftest
PASS sha256-empty
PASS sha256-abc
PASS sha256-two-block
PASS crc32-check-value
PASS json-canonical-order
PASS bundle-compiles
PASS bundle-insertion-order-invariant
PASS input-set-builds
PASS evaluation-runs
PASS undecided-refusal-blocks-allow
selftest passed
```

```fpe selftest``` runs known-answer vectors and end-to-end invariants from the installed
binary, so an installed artifact can be checked without the source tree or the test suite.

---

## Library integration

The library links as one target, ```FacilityPolicyEngine::fpe```, and it is a static library on
purpose: the public API passes standard-library types across the boundary, and a shared-library
build would create a DLL ABI surface that this release has not validated. Position-independent
code is enabled so the static library can be embedded into a shared object by a consumer.

A complete consumer that loads a published generation, evaluates typed facts, and fences the
result lives in ```examples/facility-policy-gate```. Its core is:

```cpp
#include "fpe/runtime.hpp"

// Open the published policy. This takes no lock and changes nothing.
auto runtime = fpe::PolicyRuntime::open(store_directory, fpe::Limits::defaults());
if (!runtime) {
  return report(runtime.status());
}

// Build the typed input set. Anything the policy needs that is not here stays unknown.
auto inputs = fpe::input_set_from_json(document, fpe::Limits::defaults());
if (!inputs) {
  return report(inputs.status());
}

fpe::EvaluationOptions options;
options.as_of = evaluation_instant;   // the engine never reads a clock itself

auto artifact = runtime.value().decide(inputs.value(), options);
if (!artifact) {
  return report(artifact.status());   // a bound breach produces no decision at all
}

// The decision carries the exact policy generation, control epoch, and input digest.
consume(artifact.value().outcome, artifact.value().obligations);

// Later, or in another process, ask whether it is still current.
auto fence = runtime.value().fence(artifact.value());
if (fence && !fence.value().is_current()) {
  abandon(artifact.value(), fence.value().status);
}
```

Three things a consumer should not do, because the API makes them unnecessary:

- it should not treat ```Outcome::Unknown``` as an error. Unknown is a decision with full
  attribution, and it is the correct answer when permission cannot be established;
- it should not re-derive a fact's state or freshness. Supply the evaluation instant and the
  authoritative state, and let the engine appraise them;
- it should not act on an artifact without fencing it against the policy state it trusts. The
  artifact is a record of what policy said at a generation; it is not standing authority.

---

## Building, testing, and installing

Requirements: a C++20 compiler, CMake 3.20 or newer, and nothing else. There is no
third-party runtime dependency, and the tests use a first-party harness.

```console
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure -C Release
cmake --install build --prefix /some/prefix
```

Options:

| Option | Default | Meaning |
|---|---|---|
| ```FPE_BUILD_TESTS``` | ON when top level | Build the test suite |
| ```FPE_BUILD_BENCHMARKS``` | ON when top level | Build the benchmark harness |
| ```FPE_STRICT_WARNINGS``` | ON | Promote first-party warnings to errors |
| ```FPE_ENABLE_ASAN``` | OFF | Build with AddressSanitizer |
| ```FPE_INSTALL_CMAKEDIR``` | ```lib/cmake/FacilityPolicyEngine``` | Where the package files are installed |

A downstream project consumes the installed package with:

```cmake
find_package(FacilityPolicyEngine CONFIG REQUIRED)
target_link_libraries(my_target PRIVATE FacilityPolicyEngine::fpe)
```

### Test layout

| File | What it proves |
|---|---|
| ```tests/test_digest.cpp``` | SHA-256 and CRC-32 known-answer vectors, streaming equivalence for every chunking, block-boundary padding, hex round trips |
| ```tests/test_types_json.cpp``` | Identifier alphabet and reserved names, UTF-8 rejection classes, canonical JSON, hostile documents, integer range, bounds |
| ```tests/test_policy.cpp``` | Compilation, insertion-order digest invariance, duplicate identities, unknown references, cycles, import digest binding, operand typing, limits |
| ```tests/test_engine.cpp``` | Every outcome, contradiction handling, priority bands, unknown preservation, freshness, type conflicts, unit mismatch, obligations, step bounds, explanation bounds, permutation invariance |
| ```tests/test_decision_store.cpp``` | Artifact digests, JSON round trips, the whole fence matrix, store publication, single-bit corruption sweeps, truncation and extension sweeps, floors, anchors, recovery, path validation |
| ```tests/test_statemachine.cpp``` | Seeded random store state machine with invariants checked after every action; seeded policy permutation sweeps; a printed seed on every randomised case |
| ```tests/test_adversarial.cpp``` | Impossible enums, absurd declared sizes, integer boundaries, malformed digests, duplicate identities, hostile input documents, hostile identifiers, deep nesting, non-manifest bytes |
| ```tests/test_multiprocess.cpp``` | Real writer-lock exclusion, real kernel lock release after an abrupt kill, real concurrent readers during publication, real crash injection during publication |
| ```tests/test_cli.cpp``` | End-to-end command line behaviour and exit codes, JSON output that parses back into a real artifact, anchors, canonical-form enforcement |

Randomised cases print the seed they used, and ```--seed``` reproduces a run exactly. No test
sets or relies on a timeout: a hanging case is a defect to diagnose, not something to hide
behind a watchdog. The two places that wait for a real child process use an explicit
synchronisation bound and report what they were waiting for if it expires.

---

## Validation performed

Everything below was run on this repository at the release commit. Nothing in this section is
projected, estimated, or carried over from another machine.

**Builds.** Release and Debug configurations built with MSVC 19.44 (Visual Studio 2022 17.14)
under ```/W4 /WX /permissive- /utf-8 /Zc:__cplusplus /Zc:preprocessor```. Both configurations
compile with zero warnings and zero errors. The library, the CLI, the test suite, and the
benchmark harness are all built in both configurations.

**Test suite.** 108 test cases, run to completion in all three configurations:

| Configuration | Result |
|---|---|
| Release | 108/108 passed |
| Debug (```/RTC1```, iterator debugging) | 108/108 passed |
| AddressSanitizer (RelWithDebInfo, ```/fsanitize=address /Zi```) | 108/108 passed, no sanitizer reports |

**Sanitizer.** AddressSanitizer is genuinely available on this toolchain, through the Visual
Studio 2022 **Build Tools** installation, which ships the x64 ```clang_rt.asan``` runtime. The
Community installation on the same host ships only the x86 ASan runtime, so the ASan
configuration is built with the Build Tools toolchain. The ASan build compiles clean, the
self-test passes, and the full suite passes with no address or leak reports.

**Multiprocess and crash behaviour.** Proved with real, independently started operating-system
processes, not threads and not simulation:

- a second process is refused ```lock-held``` while a first process holds the writer;
- after the holder is terminated abruptly with ```TerminateProcess``` — no cleanup, no unwinding
  — the lock is released by the kernel and the next writer acquires it;
- three reader processes repeatedly open the store and evaluate while the parent publishes 25
  generations; every reader completes every iteration, every artifact verifies, and no reader
  ever observes a partially published generation;
- six rounds of a publisher process being killed at randomly chosen instants during
  publication; after every kill the store opens, its history verifies, the published policy
  resolves, and a new generation can be published.

**Corruption and truncation.** For a store with one published generation, every single-bit
flip in the manifest and in the generation record — every byte offset, including header,
digest, reserved, and payload regions — was applied and the store was required to refuse to
open. Every prefix of both files shorter than the declared length was applied and refused, and
a one-byte extension of both files was refused as trailing content. A store whose manifest is
missing while records are present was refused as ```corrupt-manifest``` and recovered only by
naming the generation explicitly.

**Packaging and downstream.** A staged install into a clean prefix, followed by an independent
out-of-tree CMake project that configures against that prefix alone with
```find_package(FacilityPolicyEngine CONFIG REQUIRED)```, builds, and runs its own CTest cases
covering allow, refuse, unknown, and stale-fencing behaviour through the public API.

**Fresh clone.** The release commit was cloned into a clean directory and the whole sequence —
configure, build, test, install, and downstream consumer — was run from that clone.

**Benchmarks.** Run three times on an otherwise idle host; see below.

---

## Hardening defects found and fixed

These were found during this work, not hypothesised. Each one is fixed in the released tree.

1. **The durable records hashed a different byte range than the verifier checked.** The
   manifest and generation-record encoders computed the digest over the whole buffer including
   the not-yet-written digest field, while the readers re-hashed only the prefix and payload.
   Every store failed to open with a digest mismatch. Found by an end-to-end smoke run before
   any test covered it. Fixed by defining the covered range identically in both directions and
   documenting it at the encoding site.
2. **Named predicates were never registered with the evaluator.** A condition that referenced
   a named predicate evaluated to unknown — fail-closed, but wrong, and it silently disabled
   every reusable predicate in every policy. Found by inspecting a real refusal that should
   have come from a named predicate. Fixed by resolving predicate bodies across the whole
   dependency closure when the evaluator is constructed.
3. **A reader refused every store after a second writer opened it.** The reader compared the
   generation record's control epoch to the manifest's, but a writer open advances the
   manifest epoch without republishing the current record, so the two legitimately differ.
   Found by the seeded state machine and the multiprocess reader test. Fixed by removing the
   equality check and documenting that the record's epoch is provenance while the manifest's is
   the current incarnation.
4. **A publication could fail because another process was reading.** Replacing the manifest
   with ```MoveFileExW``` returned ```ERROR_ACCESS_DENIED``` while a concurrent reader held the
   file, which made an atomic replacement non-atomic from the writer's point of view. Found by
   repeating the multiprocess test. Fixed with a bounded retry for genuinely transient sharing
   conflicts on replace, remove, and open, with the rationale documented and a real error still
   reported after the bound.
5. **Set and membership operators were type-checked against the wrong domain.**
   ```in-set```, ```contains-all```, and ```contains-any``` had each operand validated as a value of
   the fact's own domain rather than as a symbol, which rejected every valid symbol-set policy.
   Found by the operand-typing test. Fixed by validating collection operands as symbols.
6. **The evaluation step bound did not cover condition evaluation.** Only one step per rule was
   charged, so a wide or deeply nested condition was unbounded work. Found by the step-bound
   test. Fixed by charging per condition node and per operand, reporting
   ```evaluation-limit-reached``` and returning no artifact rather than a decision of
   convenience.
7. **A required input could be ignored when granting.** ```unresolved_requirements``` was
   computed after composition instead of before it, so a bundle that declared a fact required
   could still allow while that fact was missing. Found by the required-fact test. Fixed by
   resolving the requirements before composition.
8. **```head()``` returned a reference into mutable cached state.** A caller could hold it across
   ```refresh()``` and observe a changed, or partially updated, generation. Found by the
   concurrency audit. Fixed by returning the head by value.
9. **A decision artifact's exported JSON omitted its own digest**, so a round trip through a
   file could never verify: parsing back either failed or produced a document that claimed to
   be unverified. Found by the CLI round-trip test. Fixed by separating the hashed content form
   from the exported document form, so the digest is never an input to itself but is always
   present in what a consumer stores.
10. **The test harness counted soft assertion failures without failing the case.** A run could
    print assertion failures and still report the case as passing, which is exactly how a real
    regression hides. Found by reading a run where failures were printed next to an ```OK```.
    Fixed so that any recorded failure fails its case.
11. **Debug builds rejected an unreachable composition path** that Release optimization
    removed. Found by the required Debug build under ```/WX```. Fixed by restructuring
    composition around the single deciding band, which is both what the semantics say and
    simpler to read.

---

## Benchmarks

```bench/fpe_bench.cpp``` measures completed operations only. The durable figure includes the
whole durable path — stage, flush, read back and verify, and the atomic replacement — because
that path is the guarantee. Warm-up runs are excluded. No speedup or before/after claim is
made, and none can be derived from these numbers.

**Host.** Windows x64, hardware concurrency 16. Single host, single process. No background
load was introduced, and none was measured. The benchmark store is on the host's local file
system.

**Methodology.** ```fpe_bench --iterations 200``` was run three times on an otherwise idle host.
The three runs are reported in full rather than averaged, so the spread is visible. The
synthetic policy set has 512 rules over 64 integer facts; the durable store publishes a
64-rule, 16-fact policy 100 times.

| Provenance | Operation | Run 1 | Run 2 | Run 3 |
|---|---|---|---|---|
| SYNTHETIC | SHA-256 over 4 KiB | 2.79 ns/byte | 2.62 ns/byte | 3.06 ns/byte |
| SYNTHETIC | Compile a 512-rule bundle | 2.10 ms | 2.03 ms | 2.02 ms |
| SYNTHETIC | Evaluate 512 rules over 64 facts | 1.11 ms | 1.20 ms | 1.06 ms |
| SYNTHETIC | Canonical JSON serialization | 3.50 ns/byte | 3.66 ns/byte | 3.31 ns/byte |
| REAL | Durable publish (stage + flush + verify + swap) | 14.80 ms | 14.80 ms | 15.69 ms |
| REAL | Open + verify + resolve a published policy | 862 us | 858 us | 824 us |

Reading these numbers:

- **The durable publish figure is the cost of the guarantee.** It is roughly four orders of
  magnitude more expensive than evaluating a policy, and that is the honest shape of the
  trade: publication is a rare, deliberate, durable act, while evaluation is a frequent,
  in-memory one. The harness refuses to report the in-memory portion of publication as if it
  were the whole operation.
- **Evaluation cost is linear in rules times matched facts**, and bounded in both by
  configuration. The 512-rule figure is a synthetic upper bound for a facility policy set of
  that size, not a typical one.
- **Component selection.** The digest and canonicalization figures are single-threaded scalar
  implementations with no platform intrinsics, chosen because the digest is a load-bearing part
  of the policy binding contract and is validated against published known-answer vectors.

---

## SYNTHETIC versus REAL validation

- **REAL**: the durable store format, atomic publication, single-writer locking, kernel lock
  release after abrupt process death, cross-process reader consistency, crash consistency,
  corruption and truncation detection, recovery, anchors, staged installation, and the
  out-of-tree downstream consumer. These exercise the operating system on this host's file
  system with real processes, real kills, and real bytes.
- **SYNTHETIC**: every policy set and every input set used by the benchmarks and by most tests.
  They are constructed in memory by the harness. They are not recordings of a production
  facility, and no claim is made that they represent a real facility's policy shape.
- **Not claimed at all**: physical hardware behaviour. No accelerator, network interface,
  power distribution unit, cooling device, or rack was involved in any measurement here, and
  nothing in this repository's measurements should be read as a statement about such hardware.

---

## Unsupported and unvalidated behavior

Stated plainly, because a limitation that is not written down is a defect waiting to happen:

- **Only Windows x64 was built, tested, sanitized, installed, benchmarked, and validated.**
  The toolchain used is MSVC 19.44 from Visual Studio 2022 17.14.
- **The POSIX file-system backend is provided but was not compiled or executed in this
  release.** ```src/platform_posix.cpp``` implements the same boundary with ```open```, ```flock```,
  ```fsync```, and ```rename```, and the library source is otherwise platform-neutral, but no
  portability claim is made for it here. It has not been compiled, so it has not been proven to
  compile.
- **Shared-library builds are not supported by this release.** The CMake package installs a
  static library; the public API passes standard-library types across the boundary and a DLL
  ABI surface has not been validated.
- **The CLI interprets non-ASCII command-line arguments as UTF-8 on Windows** by using the wide
  entry point. A narrow-argument build on another platform would use the platform's narrow
  encoding.
- **AddressSanitizer validates only the paths the test suite exercises.** It is evidence about
  those paths, not a proof of memory safety for the whole program.
- **The rollback floor and anchors detect what they can detect.** A store directory rolled back
  in its entirety is internally consistent; only an out-of-band anchor reveals it. Without an
  anchor, this subsystem proves internal consistency and the absence of partial rollback, and
  claims nothing more.
- **No timing, latency, throughput, or scale claim is made for any hardware other than the
  measurement host described above.**

---

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.

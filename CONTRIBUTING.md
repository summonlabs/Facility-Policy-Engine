# Contributing to Facility Policy Engine

Facility Policy Engine is an open-source project of Summon Software Labs. Contributions
are accepted under the terms of the Apache License, Version 2.0 (see `LICENSE`).

## Contribution terms

By submitting a contribution (a patch, pull request, or any other form of material) you
agree that the contribution is your original work, or that you have the right to submit
it, and you license it to the project and to recipients of the software under the terms
of the Apache License, Version 2.0, without additional terms or conditions.

There is **no Contributor License Agreement (CLA)** and no copyright assignment. You
retain copyright of your contribution. Section 5 of the Apache License, Version 2.0
governs inbound contributions: unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in this project is provided under the Apache
License, Version 2.0, on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.

Do not add `Co-authored-by` trailers, generator signatures, or tool attribution to
commits. Commit messages must be public-facing, neutral, and describe the change.

## Build and test expectations

Every change must build cleanly and keep the entire test suite green.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

The project is built with a strict first-party warning policy: MSVC uses
`/W4 /WX /permissive-`, and other toolchains use the equivalent `-Wall -Wextra
-Wpedantic -Werror` set. Warnings are defects. Do not silence a warning by disabling the
diagnostic globally; fix the cause or scope a narrowly justified suppression to the
single construct that needs it.

Debug and Release are both first-class configurations, and both must pass.

## Code quality expectations

- C++20, no third-party runtime dependencies. Adding one requires a strong written
  justification in the pull request and a change to the README dependency statement.
- No TODOs, placeholders, fake handlers, or abandoned experiments in the tree.
- All external input is untrusted: validate identity shapes, lengths, counters, enums,
  encodings, and reserved fields at every API and persistence boundary, and bound every
  collection, recursion, and text field before allocating.
- Missing, unknown, stale, unmeasured, or undetermined data must never silently become
  zero, false, healthy, ready, eligible, permitted, or safe.
- Every mutating decision binds to the exact identities, generations, epochs, revisions,
  policy state, and evidence that justified it. Stale authority is fenced, never
  inherited.
- Deterministic behaviour is required for equivalent authoritative inputs. Digest and
  serialization changes are behavioural changes and need explicit tests.
- Never report a benchmark number for work that was only submitted, and never claim
  hardware or platform behaviour that was not actually measured on that hardware or
  platform.

## Tests are proof obligations

A behavioural change needs a test that fails before the change and passes after it.
Prefer a focused deterministic test over a broad flaky one. Randomised tests must be
seeded, and the seed must be printed on failure so the run can be reproduced exactly.
Corruption, truncation, adversarial, boundary, replay, stale-generation, restart,
multiprocess, and crash-consistency behaviour are part of the contract and are expected
to be covered where the change affects them.

## Reporting a defect

Include the exact command, the observed result, the expected result, and (for policy
evaluation) the canonical policy digest and the input digest from the decision artifact.
A refusal must always be attributable to specific policy, evidence, generation, or
constraint inputs; if it is not, that itself is the defect.

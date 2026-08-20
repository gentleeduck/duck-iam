---
'@gentleduck/iam': major
---

Reject a policy whose target names a pair no allow rule covers, instead of warning.

`UNREACHABLE_TARGET` was a warning, so `PolicyBuilder.build()` accepted the policy and
the only symptom was a denial at request time. A denial reads as the permission system
working, which is why this cost five separate incidents to recognise: widening a target
is one line and widening the rules is another, nothing couples them, and the drift is
silent.

It is now an error, so `build()` throws where the policy is written.

Two supporting fixes:

- The check treated a dimension the target omits as a literal `*`, which demanded that
  every rule be a wildcard. A target naming only `impersonate` was reported unreachable
  because its allow rule named `.of('users')`. An omitted dimension is one the target
  does not constrain, so only the dimensions it names are checked.
- `PolicyBuilder.build()` dropped the validator's message and reported only the code and
  path, so every build failure was cryptic. It now includes the message and the policy id.

Also re-enables the two drizzle adapter suites, commented out wholesale in f3f57cb8
"pending rename follow-up" that never landed. `IamDrizzle.IConfig` had gained
`<TDb, TType>` in that rename and the suites still referenced it bare. 62 tests back,
and they are not decorative: removing the JSONB shape guard, silencing `onPolicyError`,
and dropping the WHERE from the single-row lookup are each caught.

BREAKING: a policy with an unreachable target now throws at build time rather than
loading with a silent denial.

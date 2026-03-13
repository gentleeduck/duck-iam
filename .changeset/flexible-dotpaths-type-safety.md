---
'@gentleduck/iam': patch
---

feat: FlexibleDotPaths for DefaultContext autocomplete and strict ConditionValue type safety

- DotPaths now bails to `never` (not `string`) for string-indexed types, preventing
  union pollution that killed IDE autocomplete.
- New FlexibleDotPaths<T> detects open-ended attribute bags (like DefaultContext) and
  adds `(string & {})` so known structural paths autocomplete while arbitrary strings
  are still accepted. Fully typed contexts remain strict.
- ConditionValue correctly restricts non-string value types: `env('hour', 'lt', '')`
  now errors when `hour` is `number`, instead of accepting any AttributeValue.

# @gentleduck/iam

## 1.3.2

### Patch Changes

- 2dd9f8b: feat: FlexibleDotPaths for DefaultContext autocomplete and strict ConditionValue type safety

  - DotPaths now bails to `never` (not `string`) for string-indexed types, preventing
    union pollution that killed IDE autocomplete.
  - New FlexibleDotPaths<T> detects open-ended attribute bags (like DefaultContext) and
    adds `(string & {})` so known structural paths autocomplete while arbitrary strings
    are still accepted. Fully typed contexts remain strict.
  - ConditionValue correctly restricts non-string value types: `env('hour', 'lt', '')`
    now errors when `hour` is `number`, instead of accepting any AttributeValue.

## 1.3.1

### Patch Changes

- b62bb5b: fix: prevent DotPaths from recursing into array methods and functions

  DotPaths now treats arrays as leaf paths and skips function-valued properties,
  so autocomplete only shows real data properties instead of array methods like
  `length`, `push`, `toString`, etc.

## 1.3.0

### Minor Changes

- Add DollarPaths type for $-variable autocomplete in conditions, refactor core into modular folders, and add comprehensive JSDoc and inline FAQs to documentation

## 1.2.0

### Minor Changes

- 7fe860f: Add TContext type parameter for typed dot-path intellisense and per-resource attribute narrowing. Split types.ts into modular types/ directory. Add comprehensive JSDoc across all source files.

## 1.1.2

### Patch Changes

- 66608fe: Add publishConfig with public access for scoped npm package.

## 1.1.1

### Patch Changes

- 37339e8: Fix release workflow to skip redundant CI checks during publish.

## 1.1.0

### Minor Changes

- 29ed55d: Initial release of @gentleduck/iam - identity and access management utilities.

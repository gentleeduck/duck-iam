---
'@gentleduck/iam': patch
---

fix: prevent DotPaths from recursing into array methods and functions

DotPaths now treats arrays as leaf paths and skips function-valued properties,
so autocomplete only shows real data properties instead of array methods like
`length`, `push`, `toString`, etc.

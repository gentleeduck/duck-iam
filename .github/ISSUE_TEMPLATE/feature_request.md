---
name: "✨ Feature Request"
about: Suggest a new feature or improvement for Gentleduck
title: "[Feature] "
labels: enhancement
assignees: ""
---

## Feature Description
A clear and concise description of the feature you’d like to see.

---

## Problem Statement
- Is your feature request related to a specific problem or limitation?  
- Why is this feature important?  
- Who would benefit from it (end users, developers, or both)?  

---

## Proposed Solution
- Describe the solution you’d like in detail.  
- Share API design ideas, function signatures, or config options if relevant.
- Provide examples of how developers would use it in their code:  

```tsx
// Example usage
import type { ApiRoutes } from "@gentleduck/gen/nestjs"
import { createDuckQueryClient } from "@gentleduck/query"

const client = createDuckQueryClient<ApiRoutes>({ baseURL: "/api" })
```

---

## Alternatives Considered

* What alternatives or workarounds have you tried?
* Why are these alternatives not sufficient?

---

## Use Cases

List 2–3 practical use cases for this feature:

1. …
2. …
3. …

---

## Priority

How important is this feature to you?

* [ ] Critical – I cannot use Gentleduck without it
* [ ] High – It would significantly improve my workflow
* [ ] Medium – Useful, but I can manage without it
* [ ] Low – Nice to have

---

## Potential Risks

* Could this feature introduce breaking changes?
* Could it add performance overhead?

---

## References

If applicable, add links to similar implementations in other libraries or relevant documentation.

---

## Additional Context

Add any other context, references, or related issues here.

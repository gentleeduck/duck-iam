---
name: "🐛 Bug Report"
about: Report a reproducible bug in Gentleduck
title: "[BUG] "
labels: bug
assignees: ""
---

## Bug Description
A clear and concise description of the bug.

---

## Steps to Reproduce
Provide a step-by-step guide to reproduce the issue (the smaller the reproduction, the better):

1. Setup project with version `X.Y.Z`
2. Configure `duck-gen.json` with `{...}`
3. Run command `bun run generate`
4. See error

---

## Expected Behavior
What you expected to happen.

---

## Actual Behavior
What actually happened (include exact error messages, console output, or failed network requests).

---

## Screenshots / Recordings
If applicable, add screenshots, GIFs, or a screen recording that demonstrates the issue.

---

## Environment
Please complete the following information:

- **OS:** [e.g. Ubuntu 22.04, Windows 11, macOS Sonoma]
- **Browser & Version:** [e.g. Chrome 118, Firefox 118]
- **Bun Version:** [e.g. 1.3.5]
- **Gentleduck Package(s) & Versions:**  
  - `@gentleduck/gen@X.Y.Z`  
  - `@gentleduck/query@X.Y.Z`  
  - …  

---

## Project Context
- Framework: [e.g. NestJS 11, Express 5]
- Build Tool: [e.g. Turborepo, Nx, plain Bun workspaces]
- Configurations:
  - `duck-gen.json` config (if relevant)
  - Custom TypeScript settings (if relevant)

---

## Minimal Reproduction Repo
Please provide a link to a **minimal GitHub repo** or **CodeSandbox/StackBlitz** that reproduces the bug.  
This speeds up fixing by 10x.  

---

## Logs
Paste any relevant logs or error messages (console, server, or build logs):  

```bash
# Example
bun run generate
Error: Failed to resolve schema at path...
```

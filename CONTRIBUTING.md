# Contributing to duck-iam

First off, thank you for considering contributing to **Gentleduck**!
We welcome all kinds of contributions — from bug reports and documentation improvements to feature requests and new packages.

This document provides guidelines to help you get started.

---

## Code of Conduct

By participating in this project, you agree to uphold our [Code of Conduct](./CODE_OF_CONDUCT.md).
Please treat everyone with respect and kindness.

---

## 🛠 Getting Started

### 1. Fork & Clone

```bash
<<<<<<< HEAD
git clone https://github.com/gentleeduck/duck-ui.git
cd duck-ui
=======
git clone https://github.com/gentleeduck/duck-gen.git
cd duck-gen
>>>>>>> 68028f2b8f071c10853ff31e15c817d8fd06f964
```

### 2. Install Dependencies

We use **Bun** with workspaces:

```bash
bun install
```

### 3. Build All Packages

```bash
bun run build
```

### 4. Run in Development

```bash
bun run dev
```

This will spin up local development environments for the packages and docs.

---

## Working with Packages

* All code lives under the `packages/` directory.
* Each package has its own `package.json` and may depend on other internal packages.
* Use [Turborepo](https://turbo.build/) commands to build, test, and lint efficiently.

---

## Development Workflow

1. **Branching**

   * Create a new branch from `main`.
   * Use a descriptive name, e.g. `fix/gen-output`, `feat/new-generator`, `docs/readme-update`.

   ```bash
   git checkout -b feat/new-generator
   ```

2. **Coding Standards**

   * Use **TypeScript**.
   * Follow existing **Biome** rules.
   * Write clear, self-documenting code.

3. **Commit Messages**
   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   Also make sure that you pass the `Husky` checks.

   ```
   feat: add new generator for express routes
   fix: resolve schema validation edge case
   docs: update contributing guide
   ```

4. **Testing**

   * Write unit tests for new functionality.
   * Run all tests before pushing:

     ```bash
     bun run test
     ```

---

## Submitting a Pull Request

1. Push your branch:

   ```bash
   git push origin feat/new-generator
   ```

2. Open a Pull Request (PR) against the `main` branch.

3. Fill out the PR template with:

   * A clear description of your changes
   * Any related issues (`Closes #123`)
   * Code samples or terminal output (if relevant)

---

## Reporting Issues

If you find a bug, please [open an issue](https://github.com/gentleeduck/duck-gen/issues) with:

* Steps to reproduce
* Expected behavior
* Actual behavior
* Screenshots (if applicable)

---

## Ways to Contribute

* **Code**: Bug fixes, features, optimizations
* **Docs**: Tutorials, guides, API references
* **Community**: Helping others in discussions, writing blog posts, or sharing Gentleduck

---

## Tips

* Start small - even fixing a typo helps!
* Look at the ["good first issue"](https://github.com/gentleeduck/duck-gen/labels/good%20first%20issue) label for beginner-friendly contributions.
* Ask questions! We’re happy to guide you.

---

## License

By contributing, you agree that your contributions will be licensed under the project’s [MIT License](./LICENSE).

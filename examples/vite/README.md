# React + TypeScript + Vite

The stock Vite React scaffold, kept as a baseline. It depends on `react` and
`react-dom` only - nothing here imports `@gentleduck/iam` or `@gentleduck/auth`.
For a worked authorization example see [`../blogduck`](../blogduck).

## Run it

```bash
bun install          # from the repo root; this is a workspace package
bun run dev          # vite dev server
bun run build        # tsc -b && vite build
bun run preview      # serve the build
bun run lint         # eslint, configured in eslint.config.js
```

`bun run lint` is the one place in this repo that runs ESLint; everything else
uses Biome.

## React Compiler

The React Compiler is enabled: `vite.config.ts` passes `reactCompilerPreset()`
to `@rolldown/plugin-babel` alongside `@vitejs/plugin-react`. See
[the React docs](https://react.dev/learn/react-compiler) for what it does.

Note: This will impact Vite dev & build performances.

## Expanding the ESLint configuration

If you are developing a production application, we recommend updating the configuration to enable type-aware lint rules:

```js
export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...

      // Remove tseslint.configs.recommended and replace with this
      tseslint.configs.recommendedTypeChecked,
      // Alternatively, use this for stricter rules
      tseslint.configs.strictTypeChecked,
      // Optionally, add this for stylistic rules
      tseslint.configs.stylisticTypeChecked,

      // Other configs...
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```

You can also install [eslint-plugin-react-x](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-x) and [eslint-plugin-react-dom](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-dom) for React-specific lint rules:

```js
// eslint.config.js
import reactX from 'eslint-plugin-react-x'
import reactDom from 'eslint-plugin-react-dom'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...
      // Enable lint rules for React
      reactX.configs['recommended-typescript'],
      // Enable lint rules for React DOM
      reactDom.configs.recommended,
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```

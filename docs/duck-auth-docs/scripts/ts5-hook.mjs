// TypeDoc's compiled output does `import ts from 'typescript'`, which Node's normal
// resolution walks up from typedoc's own install location and finds the workspace's
// hoisted typescript@7 — a version whose SyntaxKind enum TypeDoc can't read yet (TS 7.0
// ships the tsc binary only; the compiler API TypeDoc needs returns in 7.1). This hook
// redirects that one specifier to the 5.9.3 copy pinned in this package's own
// node_modules, without touching typescript resolution anywhere else in the workspace.
const ts5Url = new URL('../node_modules/typescript/lib/typescript.js', import.meta.url).href

export function resolve(specifier, context, nextResolve) {
  if (specifier === 'typescript') {
    return { url: ts5Url, shortCircuit: true }
  }
  return nextResolve(specifier, context)
}

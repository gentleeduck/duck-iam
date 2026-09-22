import path from 'node:path'
import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  turbopack: {
    root: path.resolve(process.cwd(), '../../../..'),
  },
  transpilePackages: [
    '@gentleduck/iam',
    '@gentleduck/primitives',
    '@gentleduck/libs',
    '@gentleduck/variants',
    '@gentleduck/hooks',
    // The IAM devtools v2 panel is built from duck-ui, and both of these ship
    // TypeScript source rather than a build. Turbopack refuses a `.ts` file in
    // node_modules unless the package is named here.
    '@gentleduck/registry-ui',
    '@gentleduck/motion',
  ],
}

export default nextConfig

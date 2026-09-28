import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  // These ship TypeScript source rather than a build; Turbopack refuses a `.ts` file in node_modules
  // unless the package is named here.
  transpilePackages: ['@examples/duck-auth-shared', '@examples/duck-auth-ui', '@gentleduck/registry-ui'],
}

export default nextConfig

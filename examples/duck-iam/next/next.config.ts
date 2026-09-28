import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  // @gentleduck/iam and @examples/duck-iam-shared both ship TypeScript source rather than a
  // build; Turbopack refuses a `.ts` file in node_modules unless the package is named here.
  transpilePackages: ['@gentleduck/iam', '@examples/duck-iam-shared'],
}

export default nextConfig

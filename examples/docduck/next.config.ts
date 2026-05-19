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
  ],
}

export default nextConfig

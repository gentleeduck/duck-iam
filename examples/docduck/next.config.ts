import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  transpilePackages: ['@gentleduck/ui', '@gentleduck/iam'],
}

export default nextConfig

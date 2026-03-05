import path from 'node:path'
import { fileURLToPath } from 'node:url'
import type { NextConfig } from 'next'

const currentDir = path.dirname(fileURLToPath(import.meta.url))
const monorepoRoot = path.join(currentDir, '../..')

const nextConfig: NextConfig = {
  devIndicators: false,
  outputFileTracingRoot: monorepoRoot,
  turbopack: {
    root: monorepoRoot,
  },
  experimental: {
    externalDir: true,
    // swcPlugins: [['@lingui/swc-plugin', {}]],
  },
  images: {
    remotePatterns: [
      {
        hostname: 'avatar.vercel.sh',
        protocol: 'https',
      },
      {
        hostname: 'zpgqhogoevbgpxustvmo.supabase.co',
        protocol: 'https',
      },
      {
        hostname: 'media.discordapp.net',
        protocol: 'https',
      },
      {
        hostname: 'images.unsplash.com',
        protocol: 'https',
      },
      {
        hostname: 'images.pexels.com',
        protocol: 'https',
      },
      {
        hostname: 'plus.unsplash.com',
        protocol: 'https',
      },
      {
        hostname: 'github.com',
        protocol: 'https',
      },
      {
        hostname: 'raw.githubusercontent.com',
        protocol: 'https',
      },
    ],
  },
  reactStrictMode: false,
<<<<<<< HEAD:apps/duck-iam-docs/next.config.ts
  // redirects: async () => {},
  transpilePackages: ['@gentleduck/docs'],
  typescript: {},
=======
  transpilePackages: ['@gentleduck/registry-ui', '@gentleduck/docs'],
>>>>>>> 68028f2b8f071c10853ff31e15c817d8fd06f964:apps/duck-gen-docs/next.config.ts
  // rewrites: async () => {
  //   return [
  //     {
  //       source: '/docs/:path*.md',
  //       destination: '/llm/:path*',
  //     },
  //   ]
  // },
}

export default nextConfig

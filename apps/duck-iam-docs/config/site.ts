import { absoluteUrl } from '@gentleduck/docs/lib'

export const siteConfig = {
  author: {
    name: 'Ahmed Ayob',
    url: 'https://x.com/wild_ducka',
    email: 'ahmedayobbusiness@gmail.com',
  },
  description:
<<<<<<< HEAD:apps/duck-iam-docs/config/site.ts
    'duck-iam is a type-safe RBAC + ABAC access control engine for TypeScript. Framework-agnostic core with integrations for Express, NestJS, Hono, Next.js, React, and Vue.',
  githubRepo: '',
  links: {
    github: 'https://github.com/gentleeduck/duck-iam',
    twitter: 'https://x.com/wild_ducka',
=======
    '@gentleduck/gen is a general-purpose compiler extension that generates type-safe API routes and message keys across frameworks. It is currently being tested with NestJS to validate the workflow.',
  links: {
    community: 'community@gentleduck.org',
    discord: process.env.NEXT_PUBLIC_DISCORD_URL ?? 'https://discord.gg/r93Qvam8',
>>>>>>> 68028f2b8f071c10853ff31e15c817d8fd06f964:apps/duck-gen-docs/config/site.ts
    email: 'support@gentleduck.org',
    github: 'https://github.com/gentleeduck/duck-gen',
    security: 'security@gentleduck.org',
    sponsor: process.env.NEXT_PUBLIC_SPONSOR_URL ?? 'https://opencollective.com/gentelduck',
    twitter: 'https://x.com/wild_ducka',
  },
  name: 'duck-iam',
  ogImage: absoluteUrl('/og/root.png'),
<<<<<<< HEAD:apps/duck-iam-docs/config/site.ts
  title: 'duck-iam -- type-safe access control for TypeScript',
=======
  title: 'duck gen -- general-purpose compiler extension',
>>>>>>> 68028f2b8f071c10853ff31e15c817d8fd06f964:apps/duck-gen-docs/config/site.ts
  url: absoluteUrl('/'),
}

export type SiteConfig = typeof siteConfig

export const META_THEME_COLORS = {
  dark: '#09090b',
  light: '#ffffff',
}

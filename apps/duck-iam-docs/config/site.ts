import { absoluteUrl } from '@gentleduck/docs/lib'

export const siteConfig = {
  author: {
    name: 'Ahmed Ayob',
    url: 'https://x.com/wild_ducka',
    email: 'ahmedayobbusiness@gmail.com',
  },
  description:
    'duck-iam is a type-safe RBAC + ABAC access control engine for TypeScript. Framework-agnostic core with integrations for Express, NestJS, Hono, Next.js, React, and Vue.',
  links: {
    community: 'community@gentleduck.org',
    discord: process.env.NEXT_PUBLIC_DISCORD_URL ?? 'https://discord.gg/r93Qvam8',
    email: 'support@gentleduck.org',
    github: 'https://github.com/gentleeduck/duck-iam',
    security: 'security@gentleduck.org',
    sponsor: process.env.NEXT_PUBLIC_SPONSOR_URL ?? 'https://opencollective.com/gentelduck',
    twitter: 'https://x.com/wild_ducka',
  },
  name: 'duck-iam',
  ogImage: absoluteUrl('/og/root.png'),
  title: 'duck-iam -- type-safe access control for TypeScript',
  url: absoluteUrl('/'),
}

export type SiteConfig = typeof siteConfig

export const META_THEME_COLORS = {
  dark: '#09090b',
  light: '#ffffff',
}

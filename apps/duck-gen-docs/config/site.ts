import { absoluteUrl } from '@gentleduck/docs/lib'

export const siteConfig = {
  author: {
    name: 'Ahmed Ayob',
    url: 'https://x.com/wild_ducka',
    email: 'ahmedayobbusiness@gmail.com',
  },
  description:
    '@gentleduck/gen is a general-purpose compiler extension that generates type-safe API routes and message keys across frameworks. It is currently being tested with NestJS to validate the workflow.',
  links: {
    community: 'community@gentleduck.org',
    discord: process.env.NEXT_PUBLIC_DISCORD_URL ?? 'https://discord.gg/r93Qvam8',
    email: 'support@gentleduck.org',
    github: 'https://github.com/gentleeduck/duck-gen',
    security: 'security@gentleduck.org',
    sponsor: process.env.NEXT_PUBLIC_SPONSOR_URL ?? 'https://opencollective.com/gentelduck',
    twitter: 'https://x.com/wild_ducka',
  },
  name: 'gentleduck/gen',
  ogImage: absoluteUrl('/og/root.png'),
  title: 'duck gen -- general-purpose compiler extension',
  url: absoluteUrl('/'),
}

export type SiteConfig = typeof siteConfig

export const META_THEME_COLORS = {
  dark: '#09090b',
  light: '#ffffff',
}

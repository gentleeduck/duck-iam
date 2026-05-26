import { baseExternal, createTsdownConfig } from '@gentleduck/tsdown-config'

export default createTsdownConfig({
  entry: {
    index: 'src/index.ts',
    'core/index': 'src/core/index.ts',
    'core/transport/index': 'src/core/transport/index.ts',
    'core/errors': 'src/core/errors.ts',
    'adapters/memory/index': 'src/adapters/memory/index.ts',
    'adapters/redis/index': 'src/adapters/redis/index.ts',
    'channels/console/index': 'src/channels/console/index.ts',
    'limiters/memory/index': 'src/limiters/memory/index.ts',
    'providers/password/index': 'src/providers/password/index.ts',
    'providers/magic-link/index': 'src/providers/magic-link/index.ts',
    'providers/oauth/google/index': 'src/providers/oauth/google/index.ts',
    'providers/oauth/github/index': 'src/providers/oauth/github/index.ts',
    'server/generic/index': 'src/server/generic/index.ts',
    'server/express/index': 'src/server/express/index.ts',
    'server/hono/index': 'src/server/hono/index.ts',
    'server/next/index': 'src/server/next/index.ts',
    'client/vanilla/index': 'src/client/vanilla/index.ts',
    'client/react/index': 'src/client/react/index.ts',
  },
  external: [...baseExternal, 'react'],
})

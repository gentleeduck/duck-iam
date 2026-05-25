import { baseExternal, createTsdownConfig } from '@gentleduck/tsdown-config'

export default createTsdownConfig({
  entry: {
    index: 'src/index.ts',
    'core/index': 'src/core/index.ts',
    'core/transport/index': 'src/core/transport/index.ts',
    'core/errors': 'src/core/errors.ts',
    'adapters/memory/index': 'src/adapters/memory/index.ts',
    'limiters/memory/index': 'src/limiters/memory/index.ts',
  },
  external: [...baseExternal],
})

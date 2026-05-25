import { baseExternal, createTsdownConfig } from '@gentleduck/tsdown-config'

export default createTsdownConfig({
  entry: {
    index: 'src/index.ts',
    'policies/index': 'src/policies/index.ts',
  },
  external: [...baseExternal, '@gentleduck/auth', '@gentleduck/iam'],
})

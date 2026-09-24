import { baseExternal, createTsdownConfig } from '@gentleduck/tsdown-config'

export default createTsdownConfig({
  entry: {
    index: 'src/index.ts',
  },
  external: [...baseExternal],
})

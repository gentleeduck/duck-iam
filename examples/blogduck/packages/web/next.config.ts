import path from 'node:path'
import type { NextConfig } from 'next'

const config: NextConfig = {
  turbopack: {
    root: path.resolve(process.cwd(), '../../../../../..'),
  },
}
export default config

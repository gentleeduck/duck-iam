import { env } from 'node:process'

/** The environment every production refusal keys on, read from `NODE_ENV` on each call. Only an exact
 *  `development` or `test` relaxes them, so an unset or unknown value is production. */
export function resolveEnv(): 'development' | 'production' | 'test' {
  const name = env.NODE_ENV
  return name === 'development' || name === 'test' ? name : 'production'
}

/** True unless `NODE_ENV` is `development` or `test`. */
export function isProduction(): boolean {
  return resolveEnv() === 'production'
}

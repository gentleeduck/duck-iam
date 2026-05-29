#!/usr/bin/env bun
/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 *
 * Second namespace-merge pass. Covers loose-type files that did not have a
 * primary class to merge against (factory functions, framework adapters,
 * config-only modules). Each gets a namespace alias block appended.
 */

import { appendFileSync, readFileSync } from 'node:fs'

interface Plan {
  file: string
  namespace: string
  aliases: Array<{ as: string; from: string }>
}

const plans: Plan[] = [
  {
    file: 'src/core/csrf.ts',
    namespace: 'Csrf',
    aliases: [{ as: 'IConfig', from: 'CsrfConfig' }],
  },
  {
    file: 'src/core/compliance.ts',
    namespace: 'Compliance',
    aliases: [
      { as: 'IPreset', from: 'CompliancePreset' },
      { as: 'IOverrides', from: 'ComplianceOverrides' },
    ],
  },
  {
    file: 'src/providers/password/index.ts',
    namespace: 'PasswordProvider',
    aliases: [
      { as: 'IOptions', from: 'PasswordProviderOptions' },
      { as: 'IBeginInput', from: 'PasswordBeginInput' },
      { as: 'ICompleteInput', from: 'PasswordCompleteInput' },
    ],
  },
  {
    file: 'src/providers/magic-link/index.ts',
    namespace: 'MagicLinkProvider',
    aliases: [
      { as: 'IOptions', from: 'MagicLinkProviderOptions' },
      { as: 'IBeginInput', from: 'MagicLinkBeginInput' },
      { as: 'ICompleteInput', from: 'MagicLinkCompleteInput' },
    ],
  },
  {
    file: 'src/server/express/index.ts',
    namespace: 'ExpressAdapter',
    aliases: [
      { as: 'IRequest', from: 'ExpressLikeRequest' },
      { as: 'IResponse', from: 'ExpressLikeResponse' },
      { as: 'IHandler', from: 'Handler' },
    ],
  },
  {
    file: 'src/server/hono/index.ts',
    namespace: 'HonoAdapter',
    aliases: [
      { as: 'IHandler', from: 'HonoHandler' },
      { as: 'IContext', from: 'HonoContextLike' },
    ],
  },
  {
    file: 'src/server/next/index.ts',
    namespace: 'NextAdapter',
    aliases: [{ as: 'IHandler', from: 'NextHandler' }],
  },
  {
    file: 'src/client/vanilla/index.ts',
    namespace: 'VanillaClient',
    aliases: [
      { as: 'IConfig', from: 'AuthClientConfig' },
      { as: 'ISignInOptions', from: 'SignInOptions' },
      { as: 'ISignInResult', from: 'SignInResult' },
      { as: 'ISessionResult', from: 'SessionResult' },
      { as: 'IClient', from: 'AuthClient' },
    ],
  },
  {
    file: 'src/client/react/index.ts',
    namespace: 'ReactClient',
    aliases: [
      { as: 'IProviderProps', from: 'AuthProviderProps' },
      { as: 'IUseSessionResult', from: 'UseSessionResult' },
      { as: 'IMutationResult', from: 'MutationResult' },
    ],
  },
  {
    file: 'src/core/mfa/totp.ts',
    namespace: 'Totp',
    aliases: [{ as: 'IParams', from: 'TotpParams' }],
  },
  {
    file: 'src/core/anomaly/impossible-travel.ts',
    namespace: 'ImpossibleTravel',
    aliases: [{ as: 'IConfig', from: 'ImpossibleTravelConfig' }],
  },
]

const repoRoot = `${import.meta.dirname}/..`
let touched = 0

for (const plan of plans) {
  const path = `${repoRoot}/${plan.file}`
  const src = readFileSync(path, 'utf-8')
  const marker = `export namespace ${plan.namespace} {`
  if (src.includes(marker)) continue
  if (plan.aliases.length === 0) continue

  const aliasLines = plan.aliases
    .map(({ as, from }) => {
      const sig = src.match(new RegExp(`export (?:interface|type) ${from}<([^>]+)>`))
      const generics = sig?.[1] ? `<${sig[1]}>` : ''
      return `  /** Alias for the flat \`${from}${generics}\` type. */\n  export type ${as}${generics} = ${from}${generics.replace(/= [^,>]+/g, '').replace(/extends [^,>]+/g, '')}`
    })
    .join('\n')

  const block = `
/**
 * Namespace merge for ${plan.namespace}. Co-locates the config + input +
 * output shapes via TS namespace declaration. Consumers can write either
 * the flat name (${plan.aliases[0]?.from}) or the namespaced form
 * (${plan.namespace}.${plan.aliases[0]?.as}); both resolve to the same type.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace ${plan.namespace} {
${aliasLines}
}
`
  appendFileSync(path, block)
  touched++
}

console.log(`Touched ${touched} files`)

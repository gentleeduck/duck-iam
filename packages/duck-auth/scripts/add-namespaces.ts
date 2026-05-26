#!/usr/bin/env bun
/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 *
 * Appends a namespace-merge block to every src file that has a primary class
 * + loose config / input / option interfaces. Idempotent: skips files whose
 * namespace block already exists.
 */

import { appendFileSync, readFileSync } from 'node:fs'

interface Plan {
  file: string
  className: string
  aliases: Array<{ as: string; from: string }>
}

const plans: Plan[] = [
  {
    file: 'src/core/facets/identities.ts',
    className: 'IdentitiesFacet',
    aliases: [
      { as: 'IConfig', from: 'IdentitiesFacetConfig' },
      { as: 'IExportBlob', from: 'ExportBlob' },
    ],
  },
  {
    file: 'src/core/facets/passwords.ts',
    className: 'PasswordsFacet',
    aliases: [{ as: 'IConfig', from: 'PasswordsFacetConfig' }],
  },
  {
    file: 'src/core/facets/providers.ts',
    className: 'ProvidersFacet',
    aliases: [],
  },
  {
    file: 'src/core/facets/mfa.ts',
    className: 'MfaFacet',
    aliases: [
      { as: 'IConfig', from: 'MfaFacetConfig' },
      { as: 'ITotpEnrollChallenge', from: 'TotpEnrollChallenge' },
    ],
  },
  {
    file: 'src/core/facets/flows.ts',
    className: 'FlowsFacet',
    aliases: [
      { as: 'IConfig', from: 'FlowsFacetConfig' },
      { as: 'ISignInOptions', from: 'SignInOptions' },
      { as: 'ISignInOutcome', from: 'SignInOutcome' },
      { as: 'IStepUpRequirement', from: 'StepUpRequirement' },
      { as: 'IStepUpOutcome', from: 'StepUpOutcome' },
      { as: 'IPasswordResetRequestInput', from: 'PasswordResetRequestInput' },
      { as: 'IPasswordResetCompleteInput', from: 'PasswordResetCompleteInput' },
      { as: 'ISignUpFlowState', from: 'SignUpFlowState' },
      { as: 'IImpersonateOptions', from: 'ImpersonateOptions' },
      { as: 'IImpersonateOutcome', from: 'ImpersonateOutcome' },
    ],
  },
  {
    file: 'src/core/facets/apikeys.ts',
    className: 'ApiKeysFacet',
    aliases: [
      { as: 'IConfig', from: 'ApiKeysFacetConfig' },
      { as: 'IApiKey', from: 'ApiKey' },
      { as: 'ICreatedApiKey', from: 'CreatedApiKey' },
    ],
  },
  {
    file: 'src/core/facets/orgs.ts',
    className: 'OrgsFacet',
    aliases: [],
  },
  {
    file: 'src/core/facets/operations.ts',
    className: 'OperationsFacet',
    aliases: [{ as: 'IState', from: 'OperationsState' }],
  },
  {
    file: 'src/core/facets/idempotency.ts',
    className: 'IdempotencyFacet',
    aliases: [{ as: 'IConfig', from: 'IdempotencyFacetConfig' }],
  },
  {
    file: 'src/core/facets/hijack.ts',
    className: 'HijackFacet',
    aliases: [
      { as: 'IPolicyConfig', from: 'HijackPolicyConfig' },
      { as: 'IReaction', from: 'HijackReaction' },
      { as: 'IEvaluation', from: 'HijackEvaluation' },
    ],
  },
  {
    file: 'src/core/transport/cookie.ts',
    className: 'CookieTransport',
    aliases: [{ as: 'IConfig', from: 'CookieTransportConfig' }],
  },
  {
    file: 'src/core/transport/bearer.ts',
    className: 'BearerTransport',
    aliases: [{ as: 'IConfig', from: 'BearerTransportConfig' }],
  },
  {
    file: 'src/core/transport/jwt.ts',
    className: 'JwtTransport',
    aliases: [
      { as: 'IConfig', from: 'JwtTransportConfig' },
      { as: 'IVerifyKey', from: 'JwtVerifyKey' },
    ],
  },
  {
    file: 'src/core/dataAtRest/aes-gcm.ts',
    className: 'AesGcmDataAtRest',
    aliases: [{ as: 'IConfig', from: 'AesGcmConfig' }],
  },
]

const repoRoot = `${import.meta.dirname}/..`
let touched = 0

for (const plan of plans) {
  const path = `${repoRoot}/${plan.file}`
  const src = readFileSync(path, 'utf-8')
  const marker = `export namespace ${plan.className} {`
  if (src.includes(marker)) continue

  const aliasLines = plan.aliases
    .map(({ as, from }) => `  /** Alias for the flat \`${from}\` type. */\n  export type ${as} = ${from}`)
    .join('\n')

  const block = `
/**
 * Namespace merge for ${plan.className}. Co-locates the config + input + output
 * shapes alongside the class via TS class+namespace merging. Consumers can
 * write either the flat name (e.g. ${plan.aliases[0]?.from ?? 'X'}) or the
 * namespaced form (${plan.className}.${plan.aliases[0]?.as ?? 'IFoo'}); both
 * resolve to the same type.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace ${plan.className} {
${aliasLines || '  // No flat type aliases for this facet (class-only public surface).'}
}
`
  appendFileSync(path, block)
  touched++
}

console.log(`Touched ${touched} files`)

/**
 * @packageDocumentation
 * i18n message catalogue for `@gentleduck/auth`. Maps error codes +
 * channel template ids to localised strings.
 *
 * Two integration shapes ship out the box:
 *   - `I18nMessageCatalog`: zero-dep nested-object catalogue (works
 *     anywhere; tests + simple apps)
 *   - `LinguiResolver`: adapter for `@lingui/core` so apps already on
 *     Lingui drop in their existing message catalogue + plural rules
 *
 * Apps wire a resolver into FlowsFacet template-resolver hooks (the
 * password-reset / email-verification / account-deletion / magic-link
 * flows all accept a `(templateId, vars) -> { subject, body }`
 * callback) so the same flow renders the user's preferred locale.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../core/errors'

/**
 * Locale -> messageId -> string catalogue. `messageId` typically maps
 * to an AuthError code (`'AUTH/INVALID_CREDENTIALS'`) or a channel
 * template id (`'magic-link'`, `'email-verification.subject'`).
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface I18nCatalogShape {
  [locale: string]: { [messageId: string]: string }
}

/**
 * Common resolver contract. Both the zero-dep catalogue + Lingui
 * adapter implement this shape so consumers can swap without
 * touching call sites.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface I18nResolver {
  /** Resolve a message id under the chosen locale; falls back to the default locale. */
  t(messageId: string, opts?: { locale?: string; vars?: Record<string, unknown> }): string
  /** List of locales the resolver knows. */
  readonly locales: string[]
}

/**
 * Config knobs for `I18nMessageCatalog`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface I18nMessageCatalogConfig {
  /** Catalogue keyed by locale -> messageId -> template. */
  messages: I18nCatalogShape
  /** Locale used when the requested one is missing. Default `'en'`. */
  defaultLocale?: string
}

/**
 * Zero-dep i18n catalogue. Templates may contain `{{var}}` placeholders;
 * `vars` substitution is a single regex pass (no escaping, no plural
 * rules, no nesting - those need a real library like Lingui).
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class I18nMessageCatalog implements I18nResolver {
  private readonly _messages: I18nCatalogShape
  private readonly _defaultLocale: string

  constructor(cfg: I18nMessageCatalogConfig) {
    if (!cfg.messages || Object.keys(cfg.messages).length === 0) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'I18nMessageCatalog requires a non-empty `messages` object',
      })
    }
    this._messages = cfg.messages
    this._defaultLocale = cfg.defaultLocale ?? 'en'
  }

  /**
   * Look up `messageId` under `locale`; falls back to defaultLocale;
   * finally to the messageId itself when nothing matches. Variable
   * substitution: `{{name}}` is replaced with `vars.name` (toString).
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  t(messageId: string, opts: { locale?: string; vars?: Record<string, unknown> } = {}): string {
    const locale = opts.locale ?? this._defaultLocale
    const template =
      this._messages[locale]?.[messageId] ?? this._messages[this._defaultLocale]?.[messageId] ?? messageId
    if (!opts.vars) return template
    return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) =>
      opts.vars && key in opts.vars ? String(opts.vars[key]) : `{{${key}}}`,
    )
  }

  /** Locales the catalogue knows. */
  get locales(): string[] {
    return Object.keys(this._messages)
  }
}

/**
 * Subset of `@lingui/core` `I18n` we depend on. Lingui's real surface
 * is huge; this captures the three methods we need so consumers pass
 * their pre-built `i18n` instance without the auth lib pulling in
 * lingui as a peer.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface LinguiI18nLike {
  _(id: string, values?: Record<string, unknown>): string
  activate(locale: string): void
  readonly locales?: string[]
  readonly locale?: string
}

/**
 * Lingui adapter. Forwards `t()` to Lingui's `i18n._()` which handles
 * ICU pluralisation + interpolation + locale-fallback chain via
 * Lingui's catalogue. Apps that already wire Lingui at app boot just
 * pass `i18n` straight in here.
 *
 * Locale management:
 *   - When `opts.locale` is passed, the resolver activates it on the
 *     underlying i18n then restores the prior locale. Lingui calls
 *     happening concurrently on the same i18n instance can race; for
 *     concurrent locale switches build one resolver per request.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class LinguiResolver implements I18nResolver {
  constructor(private readonly _i18n: LinguiI18nLike) {
    if (!_i18n || typeof _i18n._ !== 'function') {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'LinguiResolver requires a Lingui i18n instance with a `_` method',
      })
    }
  }

  /**
   * Resolve via Lingui's ICU MessageFormat path. `opts.locale` is
   * applied via `activate()` for the duration of the call; the prior
   * locale is restored on exit.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  t(messageId: string, opts: { locale?: string; vars?: Record<string, unknown> } = {}): string {
    if (opts.locale && this._i18n.locale !== opts.locale) {
      const prior = this._i18n.locale
      try {
        this._i18n.activate(opts.locale)
        return this._i18n._(messageId, opts.vars)
      } finally {
        if (prior) this._i18n.activate(prior)
      }
    }
    return this._i18n._(messageId, opts.vars)
  }

  /** Lingui's known locales. Empty when the catalogue has not loaded one. */
  get locales(): string[] {
    return this._i18n.locales ?? []
  }
}

/**
 * Default English seed for the AuthError + channel template strings.
 * Apps merge in their own catalogue; this gives the library a sane
 * fallback so an English-only deploy works without configuration.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export const DEFAULT_EN_MESSAGES: Record<string, string> = {
  'AUTH/UNAUTHENTICATED': 'Sign in to continue.',
  'AUTH/SESSION_EXPIRED': 'Your session expired. Sign in again.',
  'AUTH/SESSION_REVOKED': 'Your session was revoked. Sign in again.',
  'AUTH/INVALID_CREDENTIALS': 'Invalid email or password.',
  'AUTH/EMAIL_NOT_VERIFIED': 'Please verify your email before continuing.',
  'AUTH/RATE_LIMITED': 'Too many attempts. Try again later.',
  'AUTH/LOCKED': 'Your account is temporarily locked.',
  'AUTH/MFA_REQUIRED': 'Multi-factor authentication is required.',
  'AUTH/PASSKEY_MISMATCH': 'Passkey did not match. Try again.',
  'AUTH/RECOVERY_TOKEN_INVALID': 'This link is invalid.',
  'AUTH/RECOVERY_TOKEN_EXPIRED': 'This link has expired. Request a new one.',
  'magic-link.subject': 'Your sign-in link',
  'magic-link.body': 'Click {{url}} to sign in (expires in {{ttlMin}} minutes).',
  'email-verification.subject': 'Verify your email',
  'email-verification.body': 'Confirm your email: {{url}} (expires in {{ttlMin}} minutes).',
  'password-reset.subject': 'Reset your password',
  'password-reset.body': 'Reset link: {{url}} (expires in {{ttlMin}} minutes).',
  'account-deletion.subject': 'Confirm account deletion',
  'account-deletion.body': 'Confirm deletion: {{url}} (expires in {{ttlMin}} minutes).',
}

/**
 * Namespace merge for the i18n surface.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace I18n {
  /** Alias for `I18nResolver`. */
  export type IResolver = I18nResolver
  /** Alias for `I18nCatalogShape`. */
  export type ICatalogShape = I18nCatalogShape
  /** Alias for `I18nMessageCatalogConfig`. */
  export type IConfig = I18nMessageCatalogConfig
  /** Alias for `LinguiI18nLike`. */
  export type ILingui = LinguiI18nLike
}

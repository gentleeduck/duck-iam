/** i18n catalogue: zero-dep `AuthI18nMessageCatalog` and Lingui adapter. */

import { AuthErrorObject } from '../core/errors'

/** Zero-dep i18n catalogue. `{{var}}` placeholders only; no escaping / plural rules. */
export class AuthI18nMessageCatalog implements AuthI18n.IResolver {
  private readonly _messages: AuthI18n.ICatalogShape
  private readonly _defaultLocale: string

  constructor(cfg: AuthI18n.IConfig) {
    if (!cfg.messages || Object.keys(cfg.messages).length === 0) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'AuthI18nMessageCatalog requires a non-empty `messages` object',
      })
    }
    this._messages = cfg.messages
    this._defaultLocale = cfg.defaultLocale ?? 'en'
  }

  /**
   * Look up `messageId` under `locale`; falls back to defaultLocale;
   * finally to the messageId itself when nothing matches. Variable
   * substitution: `{{name}}` is replaced with `vars.name` (toString).
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

/** Lingui adapter. Forwards `t()` to `i18n._()`; concurrent locale switches need one resolver per request. */
export class AuthLinguiResolver implements AuthI18n.IResolver {
  constructor(private readonly _i18n: AuthI18n.ILingui) {
    if (!_i18n || typeof _i18n._ !== 'function') {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'AuthLinguiResolver requires a Lingui i18n instance with a `_` method',
      })
    }
  }

  /**
   * Resolve via Lingui's ICU MessageFormat path. `opts.locale` is
   * applied via `activate()` for the duration of the call; the prior
   * locale is restored on exit.
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
 */
export const AUTH_DEFAULT_EN_MESSAGES: Record<string, string> = {
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

export namespace AuthI18n {
  export interface IResolver {
    /** Resolve a message id under the chosen locale; falls back to the default locale. */
    t(messageId: string, opts?: { locale?: string; vars?: Record<string, unknown> }): string
    /** List of locales the resolver knows. */
    readonly locales: string[]
  }

  export interface ICatalogShape {
    [locale: string]: { [messageId: string]: string }
  }

  export interface IConfig {
    /** Catalogue keyed by locale -> messageId -> template. */
    messages: AuthI18n.ICatalogShape
    /** Locale used when the requested one is missing. Default `'en'`. */
    defaultLocale?: string
  }

  export interface ILingui {
    _(id: string, values?: Record<string, unknown>): string
    activate(locale: string): void
    readonly locales?: string[]
    readonly locale?: string
  }
}

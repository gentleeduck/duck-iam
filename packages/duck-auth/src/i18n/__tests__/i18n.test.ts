import { describe, expect, it } from 'vitest'
import { AUTH_DEFAULT_EN_MESSAGES, type AuthI18n, AuthI18nMessageCatalog, AuthLinguiResolver } from '../index'

describe('AuthI18nMessageCatalog', () => {
  it('refuses empty messages object', () => {
    expect(() => new AuthI18nMessageCatalog({ messages: {} })).toThrowError(
      expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }),
    )
  })

  it('returns translation for configured locale', () => {
    const cat = new AuthI18nMessageCatalog({
      messages: {
        en: { 'AUTH/INVALID_CREDENTIALS': 'Bad password.' },
        fr: { 'AUTH/INVALID_CREDENTIALS': 'Identifiants invalides.' },
      },
    })
    expect(cat.t('AUTH/INVALID_CREDENTIALS', { locale: 'fr' })).toBe('Identifiants invalides.')
  })

  it('falls back to defaultLocale when target locale missing', () => {
    const cat = new AuthI18nMessageCatalog({
      messages: { en: { hello: 'Hi' } },
      defaultLocale: 'en',
    })
    expect(cat.t('hello', { locale: 'jp' })).toBe('Hi')
  })

  it('falls back to messageId when neither locale has it', () => {
    const cat = new AuthI18nMessageCatalog({ messages: { en: {} } })
    expect(cat.t('AUTH/UNKNOWN')).toBe('AUTH/UNKNOWN')
  })

  it('substitutes {{var}} placeholders from vars', () => {
    const cat = new AuthI18nMessageCatalog({
      messages: { en: { greet: 'Hi {{name}}, you have {{n}} new.' } },
    })
    expect(cat.t('greet', { vars: { name: 'Ada', n: 3 } })).toBe('Hi Ada, you have 3 new.')
  })

  it('leaves unresolved placeholders intact', () => {
    const cat = new AuthI18nMessageCatalog({
      messages: { en: { greet: 'Hi {{name}}, you are {{role}}.' } },
    })
    expect(cat.t('greet', { vars: { name: 'Ada' } })).toBe('Hi Ada, you are {{role}}.')
  })

  it('locales accessor returns the keys of messages', () => {
    const cat = new AuthI18nMessageCatalog({
      messages: { en: {}, fr: {}, de: {} },
    })
    expect(cat.locales.sort()).toEqual(['de', 'en', 'fr'])
  })

  it('AUTH_DEFAULT_EN_MESSAGES covers every shipped flow + the common error codes', () => {
    const required = [
      'AUTH/UNAUTHENTICATED',
      'AUTH/INVALID_CREDENTIALS',
      'AUTH/RATE_LIMITED',
      'magic-link.subject',
      'magic-link.body',
      'email-verification.subject',
      'password-reset.subject',
      'account-deletion.subject',
    ]
    for (const id of required) expect(AUTH_DEFAULT_EN_MESSAGES[id]).toBeTruthy()
  })
})

describe('AuthLinguiResolver', () => {
  function makeLingui(overrides: Partial<AuthI18n.ILingui> = {}): AuthI18n.ILingui {
    let locale = overrides.locale ?? 'en'
    return {
      get locale() {
        return locale
      },
      get locales() {
        return overrides.locales ?? ['en', 'fr']
      },
      activate(l) {
        locale = l
      },
      _(id, values) {
        return values ? `${id}:${JSON.stringify(values)}@${locale}` : `${id}@${locale}`
      },
      ...overrides,
    }
  }

  it('refuses construction without a valid i18n', () => {
    expect(() => new AuthLinguiResolver({} as never)).toThrowError(expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }))
  })

  it('t forwards to i18n._ at the current locale', () => {
    const r = new AuthLinguiResolver(makeLingui())
    expect(r.t('AUTH/INVALID_CREDENTIALS')).toBe('AUTH/INVALID_CREDENTIALS@en')
  })

  it('opts.locale temporarily activates then restores the prior locale', () => {
    const lingui = makeLingui({ locale: 'en' })
    const r = new AuthLinguiResolver(lingui)
    expect(r.t('hello', { locale: 'fr' })).toBe('hello@fr')
    // Prior locale restored.
    expect(r.t('hello')).toBe('hello@en')
  })

  it('forwards vars to i18n._', () => {
    const r = new AuthLinguiResolver(makeLingui())
    expect(r.t('greet', { vars: { name: 'Ada' } })).toBe('greet:{"name":"Ada"}@en')
  })

  it('exposes Lingui.locales', () => {
    const r = new AuthLinguiResolver(makeLingui({ locales: ['en', 'de'] }))
    expect(r.locales).toEqual(['en', 'de'])
  })
})

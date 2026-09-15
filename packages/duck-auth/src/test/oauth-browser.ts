import type { Provider } from '../core/provider/provider.types'

/**
 * The browser's half of an oauth `begin`: keep the pre-auth cookie, follow the redirect.
 *
 * A test that only reads the redirect proves the IdP hop and nothing about which browser comes
 * back, which is the difference the state binding exists for.
 */
export function afterOAuthBegin(intents: Provider.Intent[]): { state: string; cookieHeader: string } {
  const redirect = intents.find((i) => i.type === 'redirect')
  const cookie = intents.find((i) => i.type === 'setCookie')
  const url = redirect && 'url' in redirect ? redirect.url : ''
  return {
    state: new URL(url).searchParams.get('state') ?? '',
    cookieHeader: cookie && 'value' in cookie ? `${cookie.name}=${cookie.value}` : '',
  }
}

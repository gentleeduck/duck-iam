/** `./client/react` is a published entry point that nothing else covers. React hooks cannot run outside
 *  a renderer, and react-dom is not a dependency here, so this pins what is checkable without one: that
 *  the module imports cleanly against the installed React and exports its whole surface. A broken barrel
 *  or a dropped export would otherwise only show up in someone's app. */

import { describe, expect, it } from 'vitest'
import * as reactClient from '../index'

describe('client/react module surface', () => {
  it('exports the provider and every hook', () => {
    expect(Object.keys(reactClient).sort()).toEqual([
      'Provider',
      'useAuthClient',
      'useBeginProvider',
      'useSession',
      'useSignIn',
      'useSignOut',
      'useSignUp',
    ])
  })

  it('exports them as callables, not as re-exported types erased at runtime', () => {
    for (const [name, value] of Object.entries(reactClient)) {
      expect(typeof value, name).toBe('function')
    }
  })
})

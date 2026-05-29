import type { Meta, StoryObj } from '@storybook/react'
import { withAuth } from '@gentleduck/auth/client/react/storybook'
import { MfaTotpChallenge } from './mfa-totp-challenge'

const meta: Meta<typeof MfaTotpChallenge> = {
  component: MfaTotpChallenge,
  decorators: [withAuth({})],
  title: 'Auth / MfaTotpChallenge',
}
export default meta

type Story = StoryObj<typeof MfaTotpChallenge>

export const HappyPath: Story = {
  args: {
    onSubmit: async (code) => {
      await new Promise((r) => setTimeout(r, 500))
      return code === '123456' ? { ok: true } : { message: 'Bad code (try 123456)', ok: false }
    },
  },
}

export const AlwaysReject: Story = {
  args: {
    onSubmit: async () => ({ message: 'Server rejected the code.', ok: false }),
  },
}

/**
 * Live backend — POSTs the code to /auth/mfa/totp/verify. Pass the
 * target identityId via `?identityId=…` in the Storybook URL.
 */
export const Live: Story = {
  args: {
    onSubmit: async (code) => {
      const identityId =
        new URLSearchParams(globalThis.location?.search ?? '').get('identityId') ?? 'replace-me'
      const res = await fetch('http://localhost:8787/auth/mfa/totp/verify', {
        body: JSON.stringify({ code, identityId }),
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      })
      const body = (await res.json()) as { ok: boolean }
      return body.ok ? { ok: true } : { message: 'Backend rejected the code.', ok: false }
    },
  },
}

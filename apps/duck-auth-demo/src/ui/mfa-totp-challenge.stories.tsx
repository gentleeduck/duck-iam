import type { Meta, StoryObj } from '@storybook/react'
import { MfaTotpChallenge } from './mfa-totp-challenge'

const meta: Meta<typeof MfaTotpChallenge> = {
  component: MfaTotpChallenge,
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

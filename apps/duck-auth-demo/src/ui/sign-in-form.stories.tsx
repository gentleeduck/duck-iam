import type { Meta, StoryObj } from '@storybook/react'
import { live } from './live'
import { SignInForm } from './sign-in-form'

const meta: Meta<typeof SignInForm> = {
  args: {
    onSubmit: async (_email, password) =>
      password === 'hunter2hunter2' ? { ok: true } : { message: 'Wrong password (try hunter2hunter2)', ok: false },
  },
  component: SignInForm,
  title: 'Auth / SignInForm',
}
export default meta
type Story = StoryObj<typeof SignInForm>

export const Default: Story = {}

export const WithDescription: Story = {
  args: {
    description: 'Use the credentials issued by your administrator.',
    title: 'Welcome back',
  },
}

/**
 * Hits the real demo backend at `http://localhost:8787`. Boot it first:
 * `cd apps/duck-auth-demo && bun run db:up && bun run db:migrate && bun run dev`.
 * Then sign up via `POST /auth/signup` (e.g. `alice@test`/`hunter2hunter2`)
 * before driving this story.
 */
export const Live: Story = {
  args: { description: 'Live backend — http://localhost:8787', onSubmit: live.signIn },
}

import type { Meta, StoryObj } from '@storybook/react'
import { AuthLayout } from './auth-layout'
import { live } from './live'
import { ProvidersList } from './providers-list'
import { SignInForm } from './sign-in-form'

const meta: Meta<typeof AuthLayout> = {
  component: AuthLayout,
  parameters: { layout: 'fullscreen' },
  title: 'Auth / AuthLayout',
}
export default meta

type Story = StoryObj<typeof AuthLayout>

const PROVIDERS = [
  { id: 'oauth:google', label: 'Continue with Google' },
  { id: 'oauth:github', label: 'Continue with GitHub' },
]

export const FullSignInPage: Story = {
  render: () => (
    <AuthLayout brand={<h1 className="font-semibold text-2xl">Duck Auth</h1>} footer="2026 GentleDuck">
      <SignInForm description="Use your work email." onSubmit={async () => ({ ok: true })} />
      <ProvidersList onSelect={async () => {}} providers={PROVIDERS} />
    </AuthLayout>
  ),
}

/**
 * Same composition wired to the live backend. SignInForm posts to
 * /auth/signin (password); the magic-link button fires a real begin
 * request whose link prints to the backend stdout. See
 * apps/duck-auth-demo/README.md.
 */
export const LiveSignInPage: Story = {
  render: () => (
    <AuthLayout brand={<h1 className="font-semibold text-2xl">Duck Auth (live)</h1>} footer="Backend on :8787">
      <SignInForm description="Real backend — try alice@test / hunter2hunter2 after signup." onSubmit={live.signIn} />
      <ProvidersList
        onSelect={live.begin}
        providers={[{ id: 'magic-link', input: { email: 'alice@test' }, label: 'Email me a magic link' }]}
      />
    </AuthLayout>
  ),
}

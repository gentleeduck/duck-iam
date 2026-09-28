import { Provider } from '@gentleduck/auth/client/react'
import type { ReactNode } from 'react'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { api } from './api'
import './index.css'
import { Dashboard } from './pages/dashboard'
import { ForgotPassword } from './pages/forgot-password'
import { MagicLink } from './pages/magic-link'
import { Mfa } from './pages/mfa'
import { ResetPassword } from './pages/reset-password'
import { SignIn } from './pages/sign-in'
import { SignUp } from './pages/sign-up'
import { VerifyEmail } from './pages/verify-email'

const PAGES: Record<string, () => ReactNode> = {
  '/': Dashboard,
  '/sign-in': SignIn,
  '/sign-up': SignUp,
  '/forgot-password': ForgotPassword,
  '/reset-password': ResetPassword,
  '/verify-email': VerifyEmail,
  '/magic-link': MagicLink,
  '/mfa': Mfa,
}

const Page = PAGES[location.pathname] ?? Dashboard
const root = document.getElementById('root')

if (root) {
  createRoot(root).render(
    <StrictMode>
      <Provider {...api.auth}>
        <Page />
      </Provider>
    </StrictMode>,
  )
}

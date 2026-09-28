import './index.css'
import { Dashboard } from './pages/dashboard'
import { ForgotPassword } from './pages/forgot-password'
import { MagicLink } from './pages/magic-link'
import { Mfa } from './pages/mfa'
import { ResetPassword } from './pages/reset-password'
import { SignIn } from './pages/sign-in'
import { SignUp } from './pages/sign-up'
import { VerifyEmail } from './pages/verify-email'

const PAGES: Record<string, () => HTMLElement> = {
  '/': Dashboard,
  '/sign-in': SignIn,
  '/sign-up': SignUp,
  '/forgot-password': ForgotPassword,
  '/reset-password': ResetPassword,
  '/verify-email': VerifyEmail,
  '/magic-link': MagicLink,
  '/mfa': Mfa,
}

document.getElementById('app')?.replaceChildren((PAGES[location.pathname] ?? Dashboard)())

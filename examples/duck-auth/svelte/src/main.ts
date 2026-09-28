import { type Component, mount } from 'svelte'
import './index.css'
import DashboardHome from './pages/DashboardHome.svelte'
import ForgotPassword from './pages/ForgotPassword.svelte'
import MagicLink from './pages/MagicLink.svelte'
import ResetPassword from './pages/ResetPassword.svelte'
import SignIn from './pages/SignIn.svelte'
import SignUp from './pages/SignUp.svelte'
import TwoFactorCheck from './pages/TwoFactorCheck.svelte'
import VerifyEmail from './pages/VerifyEmail.svelte'

const PAGES: Record<string, Component> = {
  '/': DashboardHome,
  '/sign-in': SignIn,
  '/sign-up': SignUp,
  '/forgot-password': ForgotPassword,
  '/reset-password': ResetPassword,
  '/verify-email': VerifyEmail,
  '/magic-link': MagicLink,
  '/mfa': TwoFactorCheck,
}

const target = document.getElementById('app')
if (target) mount(PAGES[location.pathname] ?? DashboardHome, { target })

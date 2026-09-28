import { createAuthVuePlugin } from '@gentleduck/auth/client/vue'
import { type Component, createApp } from 'vue'
import { api } from './api'
import './index.css'
import DashboardHome from './pages/DashboardHome.vue'
import ForgotPassword from './pages/ForgotPassword.vue'
import MagicLink from './pages/MagicLink.vue'
import ResetPassword from './pages/ResetPassword.vue'
import SignIn from './pages/SignIn.vue'
import SignUp from './pages/SignUp.vue'
import TwoFactorCheck from './pages/TwoFactorCheck.vue'
import VerifyEmail from './pages/VerifyEmail.vue'

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

createApp(PAGES[location.pathname] ?? DashboardHome)
  .use(createAuthVuePlugin(api.auth))
  .mount('#app')

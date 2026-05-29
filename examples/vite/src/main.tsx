import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

const rootEl = document.getElementById('root')
if (!rootEl) throw new Error('vite example: #root element not found in index.html')
createRoot(rootEl).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

import { type NextRequest, NextResponse } from 'next/server'

export function middleware(req: NextRequest) {
  const userId = req.cookies.get('session-user-id')?.value

  // Public routes - no auth needed
  const publicPaths = ['/', '/login']
  if (publicPaths.some((p) => req.nextUrl.pathname === p)) {
    return NextResponse.next()
  }

  // Everything else requires auth
  if (!userId) {
    return NextResponse.redirect(new URL('/login', req.url))
  }

  // Pass user ID to downstream server components via header
  const response = NextResponse.next()
  response.headers.set('x-user-id', userId)
  return response
}

export const config = {
  matcher: [
    // Match all page routes except static files
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}

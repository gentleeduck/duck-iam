import { type NextRequest, NextResponse } from 'next/server'

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Allow auth API routes and static files
  if (pathname.startsWith('/api/auth') || pathname.startsWith('/_next') || pathname.startsWith('/favicon')) {
    return NextResponse.next()
  }

  // Check for session cookie (better-auth uses "better-auth.session_token")
  const sessionToken =
    request.cookies.get('better-auth.session_token')?.value ??
    request.cookies.get('__Secure-better-auth.session_token')?.value

  const isAuthPage = pathname.startsWith('/auth/')

  if (!sessionToken && !isAuthPage) {
    return NextResponse.redirect(new URL('/auth/login', request.url))
  }

  if (sessionToken && isAuthPage) {
    return NextResponse.redirect(new URL('/workspaces', request.url))
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}

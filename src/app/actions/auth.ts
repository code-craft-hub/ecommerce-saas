'use server'

/**
 * Auth Server Actions.
 *
 * These run server-side only — secrets, cookies, and redirects are all safe here.
 * Each action calls the corresponding use case through the DI container,
 * sets cookies where needed, and redirects on success.
 *
 * Security: Server Actions are POST-only and Next.js validates Origin vs Host,
 * providing built-in CSRF protection (see data-security.md).
 */

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import { getContainer } from '@/infrastructure/container'

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

const REFRESH_TOKEN_COOKIE = 'refresh_token'
const ACCESS_TOKEN_COOKIE = 'access_token'
const IS_PRODUCTION = process.env.NODE_ENV === 'production'

async function setAuthCookies(accessToken: string, refreshToken: string, expiryDays = 30) {
  const cookieStore = await cookies()
  const expiresAt = new Date(Date.now() + expiryDays * 86_400_000)

  cookieStore.set(ACCESS_TOKEN_COOKIE, accessToken, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'strict',
    path: '/',
    expires: expiresAt,
  })

  cookieStore.set(REFRESH_TOKEN_COOKIE, refreshToken, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'strict',
    path: '/api/auth',
    expires: expiresAt,
  })
}

async function clearAuthCookies() {
  const cookieStore = await cookies()
  cookieStore.delete(ACCESS_TOKEN_COOKIE)
  cookieStore.delete(REFRESH_TOKEN_COOKIE)
}

// ---------------------------------------------------------------------------
// Form state type
// ---------------------------------------------------------------------------

export interface ActionState {
  error?: string
  fieldErrors?: Record<string, string>
  success?: string
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------

export async function loginAction(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const email = formData.get('email') as string
  const password = formData.get('password') as string

  if (!email || !password) {
    return { error: 'Email and password are required.' }
  }

  const { loginUseCase } = getContainer()
  const result = await loginUseCase.execute({ email, password })

  if (result.isErr()) {
    const code = result.error.code
    if (code === 'INVALID_CREDENTIALS') return { error: 'Invalid email or password.' }
    if (code === 'EMAIL_NOT_VERIFIED') return { error: 'Please verify your email before logging in.' }
    if (code === 'ACCOUNT_LOCKED') return { error: 'Account temporarily locked. Try again later.' }
    return { error: result.error.message }
  }

  const { accessToken, refreshToken } = result.value
  await setAuthCookies(accessToken, refreshToken)
  redirect('/dashboard')
}

// ---------------------------------------------------------------------------
// signup
// ---------------------------------------------------------------------------

export async function signupAction(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const name = (formData.get('name') as string)?.trim()
  const email = (formData.get('email') as string)?.trim()
  const password = formData.get('password') as string

  const fieldErrors: Record<string, string> = {}
  if (!name || name.length < 2) fieldErrors.name = 'Name must be at least 2 characters.'
  if (!email) fieldErrors.email = 'Email is required.'
  if (!password) fieldErrors.password = 'Password is required.'
  if (Object.keys(fieldErrors).length > 0) return { fieldErrors }

  const { signupUseCase } = getContainer()
  const result = await signupUseCase.execute({ name, email, password })

  if (result.isErr()) {
    const code = result.error.code
    if (code === 'USER_ALREADY_EXISTS') return { fieldErrors: { email: 'An account with this email already exists.' } }
    if (code === 'INVALID_EMAIL') return { fieldErrors: { email: 'Invalid email address.' } }
    if (code === 'WEAK_PASSWORD') return { fieldErrors: { password: 'Password is too weak. Use 12+ chars with uppercase, lowercase, number and special character.' } }
    return { error: result.error.message }
  }

  // Signup only issues an access token; refresh token is issued on first login
  const cookieStore = await cookies()
  cookieStore.set(ACCESS_TOKEN_COOKIE, result.value.accessToken, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'strict',
    path: '/',
    maxAge: 900, // 15 min — access token lifetime
  })
  redirect('/dashboard')
}

// ---------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------

export async function logoutAction(): Promise<void> {
  const cookieStore = await cookies()
  const refreshToken = cookieStore.get(REFRESH_TOKEN_COOKIE)?.value
  const accessToken = cookieStore.get(ACCESS_TOKEN_COOKIE)?.value

  if (accessToken) {
    try {
      const { logoutUseCase, tokenService } = getContainer()
      const claims = await tokenService.verifyAccessToken(accessToken)
      await logoutUseCase.execute({
        userId: claims.uid,
        refreshToken: refreshToken ?? null,
        accessTokenJti: claims.jti,
        accessTokenExp: claims.exp,
      })
    } catch {
      // Best-effort — always clear cookies
    }
  }

  await clearAuthCookies()
  redirect('/login')
}

// ---------------------------------------------------------------------------
// forgotPassword
// ---------------------------------------------------------------------------

export async function forgotPasswordAction(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const email = (formData.get('email') as string)?.trim()
  if (!email) return { fieldErrors: { email: 'Email is required.' } }

  const { forgotPasswordUseCase } = getContainer()
  // Always return success to prevent email enumeration
  await forgotPasswordUseCase.execute({ email })

  return { success: 'If that email is registered, a reset link has been sent.' }
}

// ---------------------------------------------------------------------------
// resetPassword
// ---------------------------------------------------------------------------

export async function resetPasswordAction(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const token = formData.get('token') as string
  const password = formData.get('password') as string
  const confirm = formData.get('confirm') as string

  if (!token) return { error: 'Reset token is missing.' }
  if (!password) return { fieldErrors: { password: 'Password is required.' } }
  if (password !== confirm) return { fieldErrors: { confirm: 'Passwords do not match.' } }

  const { resetPasswordUseCase } = getContainer()
  const result = await resetPasswordUseCase.execute({ token, newPassword: password })

  if (result.isErr()) {
    const code = result.error.code
    if (code === 'INVALID_TOKEN' || code === 'TOKEN_EXPIRED') {
      return { error: 'Reset link is invalid or has expired. Please request a new one.' }
    }
    if (code === 'WEAK_PASSWORD') {
      return { fieldErrors: { password: 'Password is too weak. Use 12+ chars with uppercase, lowercase, number and special character.' } }
    }
    return { error: result.error.message }
  }

  redirect('/login?reset=success')
}

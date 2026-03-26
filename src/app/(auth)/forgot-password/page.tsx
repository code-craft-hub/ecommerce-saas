import type { Metadata } from 'next'
import Link from 'next/link'
import { ForgotPasswordForm } from './ForgotPasswordForm'

export const metadata: Metadata = { title: 'Forgot password' }

export default function ForgotPasswordPage() {
  return (
    <>
      <h1 className="text-xl font-semibold text-zinc-900 dark:text-zinc-50 mb-1">
        Forgot password?
      </h1>
      <p className="text-sm text-zinc-500 dark:text-zinc-400 mb-6">
        Enter your email and we'll send a reset link if an account exists.
      </p>

      <ForgotPasswordForm />

      <p className="mt-6 text-center text-sm text-zinc-500 dark:text-zinc-400">
        <Link
          href="/login"
          className="font-medium text-zinc-900 dark:text-zinc-50 hover:underline"
        >
          Back to sign in
        </Link>
      </p>
    </>
  )
}

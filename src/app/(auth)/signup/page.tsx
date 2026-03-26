import type { Metadata } from 'next'
import Link from 'next/link'
import { SignupForm } from './SignupForm'

export const metadata: Metadata = { title: 'Create account' }

export default function SignupPage() {
  return (
    <>
      <h1 className="text-xl font-semibold text-zinc-900 dark:text-zinc-50 mb-1">
        Create an account
      </h1>
      <p className="text-sm text-zinc-500 dark:text-zinc-400 mb-6">
        Get started for free. No credit card required.
      </p>

      <SignupForm />

      <p className="mt-6 text-center text-sm text-zinc-500 dark:text-zinc-400">
        Already have an account?{' '}
        <Link
          href="/login"
          className="font-medium text-zinc-900 dark:text-zinc-50 hover:underline"
        >
          Sign in
        </Link>
      </p>
    </>
  )
}

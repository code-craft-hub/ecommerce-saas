'use client'

import { useActionState } from 'react'
import { forgotPasswordAction } from '@/app/actions/auth'
import type { ActionState } from '@/app/actions/auth'

const initialState: ActionState = {}

export function ForgotPasswordForm() {
  const [state, action, pending] = useActionState(forgotPasswordAction, initialState)

  if (state.success) {
    return (
      <div className="rounded-lg bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800 px-4 py-4 text-sm text-green-700 dark:text-green-400">
        {state.success}
      </div>
    )
  }

  return (
    <form action={action} className="flex flex-col gap-4">
      {state.error && (
        <p className="rounded-lg bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 px-4 py-3 text-sm text-red-700 dark:text-red-400">
          {state.error}
        </p>
      )}

      <div className="flex flex-col gap-1">
        <label htmlFor="email" className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
          Email
        </label>
        <input
          id="email"
          name="email"
          type="email"
          autoComplete="email"
          required
          placeholder="you@example.com"
          className={`rounded-lg border px-3 py-2 text-sm text-zinc-900 dark:text-zinc-50 placeholder-zinc-400 bg-white dark:bg-zinc-800 focus:outline-none focus:ring-2 focus:ring-zinc-900 dark:focus:ring-zinc-50 ${
            state.fieldErrors?.email
              ? 'border-red-400 dark:border-red-600'
              : 'border-zinc-300 dark:border-zinc-700'
          }`}
        />
        {state.fieldErrors?.email && (
          <p className="text-xs text-red-600 dark:text-red-400">{state.fieldErrors.email}</p>
        )}
      </div>

      <button
        type="submit"
        disabled={pending}
        className="mt-2 rounded-lg bg-zinc-900 dark:bg-zinc-50 px-4 py-2.5 text-sm font-semibold text-white dark:text-zinc-900 hover:bg-zinc-700 dark:hover:bg-zinc-200 disabled:opacity-50 transition-colors"
      >
        {pending ? 'Sending…' : 'Send reset link'}
      </button>
    </form>
  )
}

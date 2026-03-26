import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: { template: '%s — Auth', default: 'Auth' },
}

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-50 dark:bg-zinc-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <span className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
            MyApp
          </span>
        </div>
        <div className="bg-white dark:bg-zinc-900 rounded-2xl shadow-sm border border-zinc-200 dark:border-zinc-800 px-8 py-10">
          {children}
        </div>
      </div>
    </div>
  )
}

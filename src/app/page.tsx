import { redirect } from 'next/navigation'

/**
 * Root redirect — send unauthenticated users to /login.
 * The dashboard layout handles the reverse: redirect to /login if not authed.
 */
export default function RootPage() {
  redirect('/login')
}

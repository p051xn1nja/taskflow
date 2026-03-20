'use client'

import { SessionProvider } from 'next-auth/react'
import { AppSettingsProvider } from '@/lib/settings-context'

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SessionProvider>
      <AppSettingsProvider>{children}</AppSettingsProvider>
    </SessionProvider>
  )
}

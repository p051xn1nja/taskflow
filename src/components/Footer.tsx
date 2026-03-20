'use client'

import { useAppSettings } from '@/lib/settings-context'

export function Footer() {
  const { appName } = useAppSettings()
  return (
    <footer className="text-center py-4 text-[11px] text-surface-600 tracking-wide">
      {appName} build 20260320-21-stable by p051xn1nja
    </footer>
  )
}

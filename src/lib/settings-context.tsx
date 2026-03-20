'use client'

import { createContext, useContext, useState, useEffect, useCallback } from 'react'

interface AppSettings {
  appName: string
  refreshSettings: () => void
}

const AppSettingsContext = createContext<AppSettings>({ appName: 'TaskFlow', refreshSettings: () => {} })

export function AppSettingsProvider({ children }: { children: React.ReactNode }) {
  const [appName, setAppName] = useState('TaskFlow')

  const fetchSettings = useCallback(() => {
    fetch('/api/settings')
      .then(r => r.json())
      .then(data => {
        if (data.app_name) {
          setAppName(data.app_name)
          document.title = data.app_name
        }
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    fetchSettings()
  }, [fetchSettings])

  return (
    <AppSettingsContext.Provider value={{ appName, refreshSettings: fetchSettings }}>
      {children}
    </AppSettingsContext.Provider>
  )
}

export function useAppSettings() {
  return useContext(AppSettingsContext)
}

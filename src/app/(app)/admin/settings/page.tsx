'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { Save, Loader2, Settings, Info } from 'lucide-react'
import { useAppSettings } from '@/lib/settings-context'

export default function SettingsPage() {
  const { data: session } = useSession()
  const router = useRouter()
  const [settings, setSettings] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const { refreshSettings } = useAppSettings()

  useEffect(() => {
    if (session?.user?.role !== 'admin') { router.push('/'); return }
    fetchSettings()
  }, [session, router])

  const fetchSettings = async () => {
    const res = await fetch('/api/admin/settings')
    if (res.ok) setSettings(await res.json())
    setLoading(false)
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    await fetch('/api/admin/settings', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings),
    })
    setSaving(false)
    setSaved(true)
    refreshSettings()
    setTimeout(() => setSaved(false), 2000)
  }

  if (session?.user?.role !== 'admin') return null

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Platform Settings</h1>
        <p className="text-surface-700 text-sm mt-0.5">Configure platform-wide settings</p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      ) : (
        <form onSubmit={handleSave} className="space-y-4 max-w-2xl">
          <div className="card p-6 space-y-5">
            <div className="flex items-center gap-3 pb-3 border-b border-surface-300/20">
              <Settings className="w-5 h-5 text-brand-400" />
              <h2 className="font-semibold text-white">General</h2>
            </div>

            <div>
              <label className="block text-sm font-medium text-surface-800 mb-1.5">
                Application Name
              </label>
              <input
                type="text"
                className="input-base"
                value={settings.app_name || ''}
                onChange={e => setSettings({ ...settings, app_name: e.target.value })}
              />
            </div>

            <div className="flex items-center justify-between gap-4">
              <div>
                <label className="text-sm font-medium text-surface-800">Allow Registration</label>
                <p className="text-xs text-surface-700">Let new users register themselves</p>
              </div>
              <button
                type="button"
                onClick={() => setSettings({
                  ...settings,
                  allow_registration: settings.allow_registration === 'true' ? 'false' : 'true'
                })}
                className={`relative w-11 h-6 rounded-full transition-colors ${
                  settings.allow_registration === 'true' ? 'bg-accent-green' : 'bg-surface-400'
                }`}
              >
                <div className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform shadow ${
                  settings.allow_registration === 'true' ? 'translate-x-5' : ''
                }`} />
              </button>
            </div>

            <div className="flex items-center justify-between gap-4">
              <div>
                <label className="text-sm font-medium text-surface-800">Require Admin Approval</label>
                <p className="text-xs text-surface-700">New registrations must be approved by an admin before login</p>
              </div>
              <button
                type="button"
                onClick={() => setSettings({
                  ...settings,
                  require_admin_approval: settings.require_admin_approval === 'true' ? 'false' : 'true'
                })}
                className={`relative w-11 h-6 rounded-full transition-colors ${
                  settings.require_admin_approval === 'true' ? 'bg-accent-green' : 'bg-surface-400'
                }`}
              >
                <div className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform shadow ${
                  settings.require_admin_approval === 'true' ? 'translate-x-5' : ''
                }`} />
              </button>
            </div>
          </div>

          <div className="card p-6 space-y-5">
            <div className="flex items-center gap-3 pb-3 border-b border-surface-300/20">
              <Info className="w-5 h-5 text-accent-amber" />
              <h2 className="font-semibold text-white">Limits</h2>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">
                  Max Tasks Per User
                </label>
                <input
                  type="number"
                  className="input-base"
                  value={settings.max_tasks_per_user || ''}
                  onChange={e => setSettings({ ...settings, max_tasks_per_user: e.target.value })}
                  min="1"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">
                  Max Categories Per User
                </label>
                <input
                  type="number"
                  className="input-base"
                  value={settings.max_categories_per_user || ''}
                  onChange={e => setSettings({ ...settings, max_categories_per_user: e.target.value })}
                  min="1"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">
                  Max File Size (MB)
                </label>
                <input
                  type="number"
                  className="input-base"
                  value={settings.max_file_size_mb || ''}
                  onChange={e => setSettings({ ...settings, max_file_size_mb: e.target.value })}
                  min="1"
                />
              </div>
            </div>
          </div>

          <button
            type="submit"
            disabled={saving}
            className="btn-primary flex items-center gap-2"
          >
            {saving ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {saved ? 'Saved!' : 'Save Settings'}
          </button>
        </form>
      )}
    </div>
  )
}

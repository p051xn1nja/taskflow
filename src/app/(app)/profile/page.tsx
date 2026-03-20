'use client'

import { useState, useEffect, useRef } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import {
  ArrowLeft, Save, User, Mail, Lock, Camera, Trash2,
  Loader2, CheckCircle2, AlertCircle, Shield,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'

export default function ProfilePage() {
  const { data: session, update } = useSession()
  const router = useRouter()

  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [success, setSuccess] = useState('')
  const [error, setError] = useState('')

  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [role, setRole] = useState('')
  const [createdAt, setCreatedAt] = useState('')

  // Password change
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [changingPassword, setChangingPassword] = useState(false)

  // Profile photo
  const [photoUrl, setPhotoUrl] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const loadProfile = async () => {
      const res = await fetch('/api/profile')
      if (!res.ok) { router.push('/'); return }
      const data = await res.json()
      setDisplayName(data.display_name || '')
      setEmail(data.email || '')
      setUsername(data.username)
      setRole(data.role)
      setCreatedAt(data.created_at)
      if (data.profile_photo) {
        setPhotoUrl(`/api/profile-photo/${data.profile_photo}`)
      }
      setLoading(false)
    }
    loadProfile()
  }, [router])

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    setError('')
    setSuccess('')

    const res = await fetch('/api/profile', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ display_name: displayName, email }),
    })

    if (res.ok) {
      setSuccess('Profile updated')
      await update()
      setTimeout(() => setSuccess(''), 3000)
    } else {
      const data = await res.json()
      setError(data.error || 'Failed to save')
    }
    setSaving(false)
  }

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      return
    }
    setChangingPassword(true)
    setError('')
    setSuccess('')

    const res = await fetch('/api/profile', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    })

    if (res.ok) {
      setSuccess('Password changed')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setTimeout(() => setSuccess(''), 3000)
    } else {
      const data = await res.json()
      setError(data.error || 'Failed to change password')
    }
    setChangingPassword(false)
  }

  const handlePhotoUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const formData = new FormData()
    formData.append('file', file)
    const res = await fetch('/api/profile-photo', { method: 'POST', body: formData })
    if (res.ok) {
      const data = await res.json()
      setPhotoUrl(data.url)
      await update()
    } else {
      const data = await res.json()
      setError(data.error || 'Upload failed')
    }
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handlePhotoRemove = async () => {
    const res = await fetch('/api/profile-photo', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
    if (res.ok) {
      setPhotoUrl(null)
      await update()
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => router.back()}
          className="p-2 rounded-xl hover:bg-surface-300/30 text-surface-700 hover:text-surface-900 transition-colors flex-shrink-0"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div>
          <h1 className="text-2xl font-bold text-white">Profile</h1>
          <p className="text-surface-700 text-sm mt-0.5">Manage your account settings</p>
        </div>
      </div>

      {/* Status messages */}
      {success && (
        <div className="flex items-center gap-2 p-3 rounded-xl bg-accent-green/10 border border-accent-green/20 text-sm text-accent-green animate-fade-in">
          <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
          {success}
        </div>
      )}
      {error && (
        <div className="flex items-center gap-2 p-3 rounded-xl bg-accent-red/10 border border-accent-red/20 text-sm text-accent-red animate-fade-in">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* Profile Photo */}
      <div className="card p-6">
        <h2 className="text-sm font-semibold text-surface-900 mb-4">Profile Photo</h2>
        <div className="flex items-center gap-4">
          <div className="relative group/avatar">
            <div className="w-20 h-20 rounded-2xl overflow-hidden border-2 border-brand-500/30 flex items-center justify-center bg-brand-600/20">
              {photoUrl ? (
                <img src={photoUrl} alt="Profile" className="w-full h-full object-cover" />
              ) : (
                <span className="text-2xl font-bold text-brand-400">
                  {displayName?.[0]?.toUpperCase() || username?.[0]?.toUpperCase() || '?'}
                </span>
              )}
            </div>
            <button
              onClick={() => fileInputRef.current?.click()}
              className="absolute inset-0 rounded-2xl bg-black/40 opacity-0 group-hover/avatar:opacity-100 transition-opacity flex items-center justify-center"
            >
              <Camera className="w-6 h-6 text-white" />
            </button>
          </div>
          <div className="space-y-2">
            <button
              onClick={() => fileInputRef.current?.click()}
              className="btn-secondary text-sm"
            >
              {photoUrl ? 'Change Photo' : 'Upload Photo'}
            </button>
            {photoUrl && (
              <button
                onClick={handlePhotoRemove}
                className="btn-ghost text-sm text-accent-red hover:bg-accent-red/10 flex items-center gap-1.5"
              >
                <Trash2 className="w-3.5 h-3.5" />
                Remove
              </button>
            )}
            <p className="text-[11px] text-surface-700">PNG, JPG, GIF or WebP. Max 5 MB.</p>
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept="image/png,image/jpeg,image/gif,image/webp"
            className="hidden"
            onChange={handlePhotoUpload}
          />
        </div>
      </div>

      {/* Profile Info */}
      <form onSubmit={handleSaveProfile} className="card p-6 space-y-4">
        <h2 className="text-sm font-semibold text-surface-900">Account Details</h2>

        <div>
          <label className="block text-xs font-medium text-surface-800 mb-1.5">Username</label>
          <div className="input-base bg-surface-200/30 text-surface-700 cursor-not-allowed flex items-center gap-2">
            <User className="w-4 h-4 text-surface-600 flex-shrink-0" />
            {username}
          </div>
          <p className="text-[11px] text-surface-700 mt-1">Username cannot be changed</p>
        </div>

        <div>
          <label className="block text-xs font-medium text-surface-800 mb-1.5">Display Name</label>
          <input
            type="text"
            className="input-base"
            value={displayName}
            onChange={e => setDisplayName(e.target.value)}
            placeholder="Your display name"
            maxLength={100}
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-surface-800 mb-1.5">Email</label>
          <div className="relative">
            <Mail className="w-4 h-4 text-surface-600 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="email"
              className="input-base pl-10"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="your@email.com"
              required
            />
          </div>
        </div>

        <div className="flex items-center gap-3 pt-2">
          <div className="flex items-center gap-1.5 text-xs text-surface-700">
            <Shield className="w-3.5 h-3.5 text-accent-purple" />
            Role: <span className="text-surface-900 font-medium capitalize">{role}</span>
          </div>
          <span className="text-surface-600">·</span>
          <span className="text-xs text-surface-700">Joined {formatDate(createdAt)}</span>
        </div>

        <div className="pt-2">
          <button type="submit" disabled={saving} className="btn-primary flex items-center gap-2 text-sm">
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
            Save Changes
          </button>
        </div>
      </form>

      {/* Change Password */}
      <form onSubmit={handleChangePassword} className="card p-6 space-y-4">
        <h2 className="text-sm font-semibold text-surface-900">Change Password</h2>

        <div>
          <label className="block text-xs font-medium text-surface-800 mb-1.5">Current Password</label>
          <div className="relative">
            <Lock className="w-4 h-4 text-surface-600 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="password"
              className="input-base pl-10"
              value={currentPassword}
              onChange={e => setCurrentPassword(e.target.value)}
              placeholder="Enter current password"
              required
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-surface-800 mb-1.5">New Password</label>
          <div className="relative">
            <Lock className="w-4 h-4 text-surface-600 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="password"
              className="input-base pl-10"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              placeholder="Enter new password"
              minLength={6}
              required
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-surface-800 mb-1.5">Confirm New Password</label>
          <div className="relative">
            <Lock className="w-4 h-4 text-surface-600 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="password"
              className={cn(
                'input-base pl-10',
                confirmPassword && confirmPassword !== newPassword && 'border-accent-red/50 focus:border-accent-red'
              )}
              value={confirmPassword}
              onChange={e => setConfirmPassword(e.target.value)}
              placeholder="Confirm new password"
              minLength={6}
              required
            />
          </div>
          {confirmPassword && confirmPassword !== newPassword && (
            <p className="text-[11px] text-accent-red mt-1">Passwords do not match</p>
          )}
        </div>

        <div className="pt-2">
          <button
            type="submit"
            disabled={changingPassword || !currentPassword || !newPassword || newPassword !== confirmPassword}
            className="btn-primary flex items-center gap-2 text-sm"
          >
            {changingPassword ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Lock className="w-3.5 h-3.5" />}
            Change Password
          </button>
        </div>
      </form>
    </div>
  )
}

'use client'

import { useState, useEffect } from 'react'
import { signIn } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { LogIn, UserPlus, Zap } from 'lucide-react'

export default function LoginPage() {
  const router = useRouter()
  const [isSetup, setIsSetup] = useState(false)
  const [hasUsers, setHasUsers] = useState<boolean | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const [form, setForm] = useState({
    username: '',
    email: '',
    password: '',
    display_name: '',
  })

  useEffect(() => {
    fetch('/api/auth/setup')
      .then(r => r.json())
      .then(data => {
        setHasUsers(data.hasUsers)
        if (!data.hasUsers) setIsSetup(true)
      })
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    if (isSetup) {
      const res = await fetch('/api/auth/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error)
        setLoading(false)
        return
      }
      if (data.pending_approval) {
        setError('Your account is pending admin approval. Please check back later.')
        setLoading(false)
        return
      }
      // Auto-login after setup
      const signInResult = await signIn('credentials', {
        username: form.username,
        password: form.password,
        redirect: false,
      })
      if (signInResult?.ok) {
        router.push('/')
        return
      }
    }

    const result = await signIn('credentials', {
      username: form.username,
      password: form.password,
      redirect: false,
    })

    if (result?.error) {
      setError('Invalid username or password')
    } else {
      router.push('/')
    }
    setLoading(false)
  }

  if (hasUsers === null) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 relative overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-brand-600/10 rounded-full blur-[100px]" />
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-accent-purple/10 rounded-full blur-[100px]" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-brand-500/5 rounded-full blur-[120px]" />
      </div>

      <div className="w-full max-w-md relative z-10 animate-fade-in">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-brand-600/20 border border-brand-500/30 mb-4 glow-brand">
            <Zap className="w-8 h-8 text-brand-400" />
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">TaskFlow</h1>
          <p className="text-surface-800 mt-1">
            {isSetup && !hasUsers
              ? 'Create your admin account to get started'
              : 'Sign in to your account'}
          </p>
        </div>

        {/* Form */}
        <div className="card p-8">
          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div className="p-3 rounded-xl bg-accent-red/10 border border-accent-red/20 text-accent-red text-sm animate-slide-down">
                {error}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-surface-800 mb-1.5">
                Username
              </label>
              <input
                type="text"
                className="input-base"
                placeholder="Enter your username"
                value={form.username}
                onChange={e => setForm({ ...form, username: e.target.value })}
                required
                autoFocus
              />
            </div>

            {isSetup && !hasUsers && (
              <>
                <div>
                  <label className="block text-sm font-medium text-surface-800 mb-1.5">
                    Email
                  </label>
                  <input
                    type="email"
                    className="input-base"
                    placeholder="admin@example.com"
                    value={form.email}
                    onChange={e => setForm({ ...form, email: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-surface-800 mb-1.5">
                    Display Name
                  </label>
                  <input
                    type="text"
                    className="input-base"
                    placeholder="Your display name"
                    value={form.display_name}
                    onChange={e => setForm({ ...form, display_name: e.target.value })}
                  />
                </div>
              </>
            )}

            <div>
              <label className="block text-sm font-medium text-surface-800 mb-1.5">
                Password
              </label>
              <input
                type="password"
                className="input-base"
                placeholder={isSetup && !hasUsers ? 'Min 8 characters' : 'Enter your password'}
                value={form.password}
                onChange={e => setForm({ ...form, password: e.target.value })}
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full flex items-center justify-center gap-2 text-sm"
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : isSetup && !hasUsers ? (
                <>
                  <UserPlus className="w-4 h-4" />
                  Create Admin Account
                </>
              ) : (
                <>
                  <LogIn className="w-4 h-4" />
                  Sign In
                </>
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-surface-700 text-xs mt-6">
          TaskFlow v2.0 &mdash; Modern Task Management
        </p>
      </div>
    </div>
  )
}

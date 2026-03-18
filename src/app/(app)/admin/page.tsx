'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { Users, CheckSquare, Tag, Settings, Activity, Loader2 } from 'lucide-react'
import Link from 'next/link'

interface Stats {
  users: number
  tasks: number
  categories: number
}

export default function AdminDashboard() {
  const { data: session } = useSession()
  const router = useRouter()
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (session?.user?.role !== 'admin') {
      router.push('/')
      return
    }
    fetchStats()
  }, [session, router])

  const fetchStats = async () => {
    try {
      const usersRes = await fetch('/api/admin/users')
      if (usersRes.ok) {
        const users = await usersRes.json()
        setStats({
          users: users.length,
          tasks: users.reduce((s: number, u: { task_count: number }) => s + u.task_count, 0),
          categories: 0,
        })
      }
    } catch {}
    setLoading(false)
  }

  if (session?.user?.role !== 'admin') return null

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Admin Dashboard</h1>
        <p className="text-surface-700 text-sm mt-0.5">Platform overview and management</p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="card p-5">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-2xl bg-brand-600/15 flex items-center justify-center">
                  <Users className="w-6 h-6 text-brand-400" />
                </div>
                <div>
                  <p className="text-3xl font-bold text-white">{stats?.users || 0}</p>
                  <p className="text-sm text-surface-600">Users</p>
                </div>
              </div>
            </div>
            <div className="card p-5">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-2xl bg-accent-green/15 flex items-center justify-center">
                  <CheckSquare className="w-6 h-6 text-accent-green" />
                </div>
                <div>
                  <p className="text-3xl font-bold text-white">{stats?.tasks || 0}</p>
                  <p className="text-sm text-surface-600">Total Tasks</p>
                </div>
              </div>
            </div>
            <div className="card p-5">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-2xl bg-accent-purple/15 flex items-center justify-center">
                  <Activity className="w-6 h-6 text-accent-purple" />
                </div>
                <div>
                  <p className="text-3xl font-bold text-white">Active</p>
                  <p className="text-sm text-surface-600">Platform Status</p>
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Link href="/admin/users" className="card p-5 hover:border-surface-400/40 transition-all group">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-xl bg-brand-600/15 flex items-center justify-center group-hover:bg-brand-600/25 transition-colors">
                  <Users className="w-5 h-5 text-brand-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">User Management</h3>
                  <p className="text-sm text-surface-600">Create, edit, and manage user accounts</p>
                </div>
              </div>
            </Link>
            <Link href="/admin/settings" className="card p-5 hover:border-surface-400/40 transition-all group">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-xl bg-accent-amber/15 flex items-center justify-center group-hover:bg-accent-amber/25 transition-colors">
                  <Settings className="w-5 h-5 text-accent-amber" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">Platform Settings</h3>
                  <p className="text-sm text-surface-600">Configure platform-wide settings</p>
                </div>
              </div>
            </Link>
          </div>
        </>
      )}
    </div>
  )
}

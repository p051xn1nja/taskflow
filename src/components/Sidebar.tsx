'use client'

import { useSession, signOut } from 'next-auth/react'
import { usePathname } from 'next/navigation'
import Link from 'next/link'
import {
  LayoutDashboard,
  CheckSquare,
  Columns3,
  CalendarDays,
  Tag,
  Hash,
  FileText,
  CircleDot,
  Shield,
  Users,
  Settings,
  LogOut,
  Zap,
  ChevronLeft,
  Menu,
  Camera,
  X,
  Trash2,
} from 'lucide-react'
import { useState, useRef } from 'react'
import { cn } from '@/lib/utils'

const navItems = [
  { href: '/', icon: CheckSquare, label: 'Tasks' },
  { href: '/notes', icon: FileText, label: 'Notes' },
  { href: '/board', icon: Columns3, label: 'Board' },
  { href: '/calendar', icon: CalendarDays, label: 'Calendar' },
  { href: '/categories', icon: Tag, label: 'Categories' },
  { href: '/tags', icon: Hash, label: 'Tags' },
  { href: '/statuses', icon: CircleDot, label: 'Statuses' },
]

const adminItems = [
  { href: '/admin', icon: LayoutDashboard, label: 'Dashboard' },
  { href: '/admin/users', icon: Users, label: 'Users' },
  { href: '/admin/settings', icon: Settings, label: 'Settings' },
]

export function Sidebar() {
  const { data: session, update } = useSession()
  const pathname = usePathname()
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  const [showPhotoMenu, setShowPhotoMenu] = useState(false)
  const [photoUrl, setPhotoUrl] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const isAdmin = session?.user?.role === 'admin'

  // Derive photo URL from session
  const currentPhotoUrl = photoUrl !== null
    ? photoUrl
    : session?.user?.profile_photo
      ? `/api/profile-photo/${session.user.profile_photo}`
      : null

  const handlePhotoUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const formData = new FormData()
    formData.append('file', file)
    const res = await fetch('/api/profile-photo', { method: 'POST', body: formData })
    if (res.ok) {
      const data = await res.json()
      setPhotoUrl(data.url)
      // Refresh session so profile_photo is updated in the JWT
      await update()
    }
    setShowPhotoMenu(false)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handlePhotoRemove = async () => {
    const res = await fetch('/api/profile-photo', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
    if (res.ok) {
      setPhotoUrl('')
      await update()
    }
    setShowPhotoMenu(false)
  }

  return (
    <>
      {/* Mobile toggle */}
      <button
        onClick={() => setMobileOpen(true)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 rounded-xl glass"
      >
        <Menu className="w-5 h-5 text-surface-800" />
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="lg:hidden fixed inset-0 bg-black/60 backdrop-blur-sm z-40"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={cn(
          'fixed top-0 left-0 h-dvh z-50 flex flex-col transition-all duration-300 ease-in-out',
          'bg-surface-50/95 backdrop-blur-xl border-r border-surface-300/30',
          collapsed ? 'w-[72px]' : 'w-64',
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        )}
      >
        {/* Header */}
        <div className={cn('flex items-center h-16 px-4 border-b border-surface-300/20', collapsed ? 'justify-center' : 'justify-between')}>
          {!collapsed && (
            <Link href="/" className="flex items-center gap-2.5" onClick={() => setMobileOpen(false)}>
              <div className="w-8 h-8 rounded-lg bg-brand-600/20 border border-brand-500/30 flex items-center justify-center">
                <Zap className="w-4 h-4 text-brand-400" />
              </div>
              <span className="font-bold text-lg text-white tracking-tight">TaskFlow</span>
            </Link>
          )}
          <button
            onClick={() => { setCollapsed(!collapsed); setMobileOpen(false) }}
            className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700 transition-colors hidden lg:block"
          >
            <ChevronLeft className={cn('w-4 h-4 transition-transform', collapsed && 'rotate-180')} />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
          {!collapsed && (
            <p className="text-[10px] font-semibold uppercase tracking-wider text-surface-800 px-3 mb-2">
              Workspace
            </p>
          )}
          {navItems.map(item => {
            const active = item.href === '/'
              ? pathname === '/'
              : pathname.startsWith(item.href)
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileOpen(false)}
                className={cn(
                  'flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-200',
                  active
                    ? 'bg-brand-600/15 text-brand-400 shadow-sm'
                    : 'text-surface-700 hover:bg-surface-300/30 hover:text-surface-900'
                )}
                title={collapsed ? item.label : undefined}
              >
                <item.icon className={cn('w-[18px] h-[18px] flex-shrink-0', active && 'text-brand-400')} />
                {!collapsed && item.label}
              </Link>
            )
          })}

          {isAdmin && (
            <>
              {!collapsed && (
                <p className="text-[10px] font-semibold uppercase tracking-wider text-surface-800 px-3 mb-2 mt-6">
                  Administration
                </p>
              )}
              {collapsed && <div className="border-t border-surface-300/20 my-3" />}
              {adminItems.map(item => {
                const active = pathname === item.href
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setMobileOpen(false)}
                    className={cn(
                      'flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-200',
                      active
                        ? 'bg-accent-purple/15 text-accent-purple'
                        : 'text-surface-700 hover:bg-surface-300/30 hover:text-surface-900'
                    )}
                    title={collapsed ? item.label : undefined}
                  >
                    <item.icon className={cn('w-[18px] h-[18px] flex-shrink-0', active && 'text-accent-purple')} />
                    {!collapsed && item.label}
                  </Link>
                )
              })}
            </>
          )}
        </nav>

        {/* User */}
        <div className="border-t border-surface-300/20 p-3">
          <div className={cn('flex items-center', collapsed ? 'flex-col gap-2' : 'gap-3')}>
            <div className="relative flex-shrink-0">
              <button
                onClick={() => setShowPhotoMenu(!showPhotoMenu)}
                className="group/avatar relative w-9 h-9 rounded-xl overflow-hidden border border-brand-500/30 flex items-center justify-center bg-brand-600/20"
                title="Change profile photo"
              >
                {currentPhotoUrl ? (
                  <img src={currentPhotoUrl} alt="Profile" className="w-full h-full object-cover" />
                ) : (
                  <span className="text-sm font-semibold text-brand-400">
                    {session?.user?.display_name?.[0]?.toUpperCase() || session?.user?.username?.[0]?.toUpperCase() || '?'}
                  </span>
                )}
                <div className="absolute inset-0 bg-black/40 opacity-0 group-hover/avatar:opacity-100 transition-opacity flex items-center justify-center">
                  <Camera className="w-3.5 h-3.5 text-white" />
                </div>
              </button>
              {showPhotoMenu && (
                <div className="absolute bottom-full left-0 mb-2 w-44 rounded-xl bg-surface-100 border border-surface-300/40 shadow-xl z-50 overflow-hidden animate-slide-down">
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="w-full px-3 py-2 text-sm text-left text-surface-900 hover:bg-surface-300/30 flex items-center gap-2"
                  >
                    <Camera className="w-3.5 h-3.5" />
                    {currentPhotoUrl ? 'Change Photo' : 'Upload Photo'}
                  </button>
                  {currentPhotoUrl && (
                    <button
                      onClick={handlePhotoRemove}
                      className="w-full px-3 py-2 text-sm text-left text-accent-red hover:bg-accent-red/10 flex items-center gap-2"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Remove Photo
                    </button>
                  )}
                  <button
                    onClick={() => setShowPhotoMenu(false)}
                    className="w-full px-3 py-2 text-sm text-left text-surface-700 hover:bg-surface-300/30 flex items-center gap-2"
                  >
                    <X className="w-3.5 h-3.5" />
                    Cancel
                  </button>
                </div>
              )}
              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/gif,image/webp"
                className="hidden"
                onChange={handlePhotoUpload}
              />
            </div>
            {!collapsed && (
              <Link
                href="/profile"
                onClick={() => setMobileOpen(false)}
                className="flex-1 min-w-0 hover:opacity-80 transition-opacity"
                title="Edit profile"
              >
                <p className="text-sm font-medium text-surface-900 truncate">
                  {session?.user?.display_name || session?.user?.username}
                </p>
                <p className="text-xs text-surface-700 flex items-center gap-1">
                  {isAdmin && <Shield className="w-3 h-3 text-accent-purple" />}
                  {session?.user?.role}
                </p>
              </Link>
            )}
            <button
              onClick={() => signOut({ callbackUrl: '/login' })}
              className="p-2 rounded-lg hover:bg-surface-300/30 text-surface-700 hover:text-accent-red transition-colors"
              title="Sign out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>
    </>
  )
}

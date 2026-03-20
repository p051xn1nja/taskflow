'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import {
  Plus, Pencil, Trash2, Shield, User, X, Loader2,
  UserCheck, UserX, Lock, Camera,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { ConfirmModal } from '@/components/ConfirmModal'
import { useRef } from 'react'

interface UserData {
  id: string
  username: string
  email: string
  display_name: string
  role: 'admin' | 'user'
  is_active: number
  pending_approval: number
  profile_photo: string
  created_at: string
  task_count: number
}

export default function UsersPage() {
  const { data: session } = useSession()
  const router = useRouter()
  const [users, setUsers] = useState<UserData[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editing, setEditing] = useState<UserData | null>(null)
  const [form, setForm] = useState({ username: '', email: '', password: '', display_name: '', role: 'user' })
  const [photoFile, setPhotoFile] = useState<File | null>(null)
  const [photoPreview, setPhotoPreview] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (session?.user?.role !== 'admin') { router.push('/'); return }
    fetchUsers()
  }, [session, router])

  const fetchUsers = async () => {
    const res = await fetch('/api/admin/users')
    if (res.ok) setUsers(await res.json())
    setLoading(false)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    let userId = editing?.id
    if (editing) {
      const body: Record<string, string> = {}
      if (form.display_name !== editing.display_name) body.display_name = form.display_name
      if (form.email !== editing.email) body.email = form.email
      if (form.role !== editing.role) body.role = form.role
      if (form.password) body.password = form.password
      await fetch(`/api/admin/users/${editing.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
    } else {
      const res = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      if (res.ok) {
        const data = await res.json()
        userId = data.id
      }
    }
    // Upload profile photo if selected
    if (photoFile && userId) {
      const formData = new FormData()
      formData.append('file', photoFile)
      formData.append('user_id', userId)
      await fetch('/api/profile-photo', { method: 'POST', body: formData })
    }
    resetForm()
    fetchUsers()
  }

  const toggleActive = async (user: UserData) => {
    await fetch(`/api/admin/users/${user.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_active: !user.is_active }),
    })
    fetchUsers()
  }

  const approveUser = async (user: UserData) => {
    await fetch(`/api/admin/users/${user.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_active: true, pending_approval: false }),
    })
    fetchUsers()
  }

  const handleDelete = async (id: string) => {
    setConfirmDelete(id)
  }

  const executeDelete = async () => {
    if (!confirmDelete) return
    await fetch(`/api/admin/users/${confirmDelete}`, { method: 'DELETE' })
    setConfirmDelete(null)
    fetchUsers()
  }

  const startEdit = (user: UserData) => {
    setEditing(user)
    setForm({
      username: user.username,
      email: user.email,
      password: '',
      display_name: user.display_name,
      role: user.role,
    })
    setPhotoFile(null)
    setPhotoPreview(user.profile_photo ? `/api/profile-photo/${user.profile_photo}` : null)
    setShowForm(true)
  }

  const resetForm = () => {
    setShowForm(false)
    setEditing(null)
    setForm({ username: '', email: '', password: '', display_name: '', role: 'user' })
    setPhotoFile(null)
    setPhotoPreview(null)
  }

  if (session?.user?.role !== 'admin') return null

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Users</h1>
          <p className="text-surface-700 text-sm mt-0.5">Manage platform users</p>
        </div>
        <button onClick={() => setShowForm(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> Add User
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      ) : (
        <div className="space-y-2">
          {users.map(user => (
            <div key={user.id} className="card p-4 group hover:border-surface-400/40 transition-all">
              <div className="flex items-center gap-4">
                <div className={cn(
                  'w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 overflow-hidden',
                  user.role === 'admin' ? 'bg-accent-purple/15' : 'bg-brand-600/15'
                )}>
                  {user.profile_photo ? (
                    <img src={`/api/profile-photo/${user.profile_photo}`} alt={user.display_name} className="w-full h-full object-cover" />
                  ) : user.role === 'admin' ? (
                    <Shield className="w-5 h-5 text-accent-purple" />
                  ) : (
                    <User className="w-5 h-5 text-brand-400" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="font-medium text-white truncate">{user.display_name}</h3>
                    <span className={cn(
                      'badge text-[10px]',
                      user.role === 'admin'
                        ? 'bg-accent-purple/15 text-accent-purple border border-accent-purple/20'
                        : 'bg-brand-600/15 text-brand-400 border border-brand-500/20'
                    )}>
                      {user.role}
                    </span>
                    {user.pending_approval ? (
                      <span className="badge text-[10px] bg-accent-amber/15 text-accent-amber border border-accent-amber/20">
                        Pending Approval
                      </span>
                    ) : !user.is_active && (
                      <span className="badge text-[10px] bg-accent-red/15 text-accent-red border border-accent-red/20">
                        Inactive
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 text-xs text-surface-800 mt-0.5">
                    <span>@{user.username}</span>
                    <span>{user.email}</span>
                    <span>{user.task_count} tasks</span>
                    <span>Joined {formatDate(user.created_at)}</span>
                  </div>
                </div>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  {user.pending_approval && (
                    <button
                      onClick={() => approveUser(user)}
                      className="p-1.5 rounded-lg hover:bg-accent-green/10 text-surface-700 hover:text-accent-green transition-colors"
                      title="Approve"
                    >
                      <UserCheck className="w-4 h-4" />
                    </button>
                  )}
                  <button
                    onClick={() => toggleActive(user)}
                    className={cn(
                      'p-1.5 rounded-lg transition-colors',
                      user.is_active
                        ? 'hover:bg-accent-amber/10 text-surface-700 hover:text-accent-amber'
                        : 'hover:bg-accent-green/10 text-surface-700 hover:text-accent-green'
                    )}
                    title={user.is_active ? 'Deactivate' : 'Activate'}
                  >
                    {user.is_active ? <UserX className="w-4 h-4" /> : <UserCheck className="w-4 h-4" />}
                  </button>
                  <button
                    onClick={() => startEdit(user)}
                    className="p-1.5 rounded-lg hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                    title="Edit"
                  >
                    <Pencil className="w-3.5 h-3.5" />
                  </button>
                  {user.id !== session.user.id && (
                    <button
                      onClick={() => handleDelete(user.id)}
                      className="p-1.5 rounded-lg hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Form modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="card w-full max-w-md p-6 animate-scale-in">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-white">
                {editing ? 'Edit User' : 'Create User'}
              </h2>
              <button onClick={resetForm} className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">Username</label>
                <input
                  type="text"
                  className="input-base"
                  value={form.username}
                  onChange={e => setForm({ ...form, username: e.target.value })}
                  required
                  disabled={!!editing}
                  placeholder="username"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">Email</label>
                <input
                  type="email"
                  className="input-base"
                  value={form.email}
                  onChange={e => setForm({ ...form, email: e.target.value })}
                  required
                  placeholder="user@example.com"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">Display Name</label>
                <input
                  type="text"
                  className="input-base"
                  value={form.display_name}
                  onChange={e => setForm({ ...form, display_name: e.target.value })}
                  placeholder="Display name"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">Profile Photo</label>
                <div className="flex items-center gap-3">
                  <div className="relative w-14 h-14 rounded-xl overflow-hidden border border-surface-300/40 bg-surface-200/50 flex items-center justify-center flex-shrink-0">
                    {photoPreview ? (
                      <>
                        <img src={photoPreview} alt="Preview" className="w-full h-full object-cover" />
                        <button
                          type="button"
                          onClick={() => {
                            setPhotoFile(null)
                            setPhotoPreview(null)
                            if (fileInputRef.current) fileInputRef.current.value = ''
                            // Remove existing photo for editing user
                            if (editing?.profile_photo) {
                              fetch('/api/profile-photo', {
                                method: 'DELETE',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ user_id: editing.id }),
                              })
                            }
                          }}
                          className="absolute top-0 right-0 p-0.5 bg-black/60 rounded-bl-lg text-white hover:bg-black/80"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </>
                    ) : (
                      <Camera className="w-5 h-5 text-surface-700" />
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="btn-secondary text-sm py-1.5 px-3"
                  >
                    {photoPreview ? 'Change' : 'Choose Photo'}
                  </button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/png,image/jpeg,image/gif,image/webp"
                    className="hidden"
                    onChange={e => {
                      const file = e.target.files?.[0]
                      if (file) {
                        setPhotoFile(file)
                        setPhotoPreview(URL.createObjectURL(file))
                      }
                    }}
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">
                  Password {editing && <span className="text-surface-700 font-normal">(leave blank to keep)</span>}
                </label>
                <input
                  type="password"
                  className="input-base"
                  value={form.password}
                  onChange={e => setForm({ ...form, password: e.target.value })}
                  required={!editing}
                  placeholder={editing ? '••••••••' : 'Min 8 characters'}
                  minLength={editing ? 0 : 8}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">Role</label>
                <select
                  className="input-base"
                  value={form.role}
                  onChange={e => setForm({ ...form, role: e.target.value })}
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </div>

              <div className="flex gap-3 pt-2">
                <button type="button" onClick={resetForm} className="btn-secondary flex-1">Cancel</button>
                <button type="submit" className="btn-primary flex-1">
                  {editing ? 'Save Changes' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      <ConfirmModal
        open={!!confirmDelete}
        title="Delete User"
        message="This user and all their tasks, notes, and files will be permanently deleted."
        onConfirm={executeDelete}
        onCancel={() => setConfirmDelete(null)}
      />
    </div>
  )
}

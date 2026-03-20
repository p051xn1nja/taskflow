'use client'

import { useState, useEffect, useRef } from 'react'
import { Plus, Pencil, Trash2, Hash, X, Loader2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import { ConfirmModal } from '@/components/ConfirmModal'
import type { Tag } from '@/types'

const PRESET_COLORS = [
  '#ef4444', '#f97316', '#f59e0b', '#22c55e', '#14b8a6',
  '#06b6d4', '#3b82f6', '#6366f1', '#8b5cf6', '#ec4899',
  '#64748b', '#78716c',
]

export default function TagsPage() {
  const [tags, setTags] = useState<Tag[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editing, setEditing] = useState<Tag | null>(null)
  const [name, setName] = useState('')
  const [color, setColor] = useState('#3b82f6')
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)

  const formRef = useRef<HTMLDivElement>(null)

  // ESC to close + click outside to close
  useEffect(() => {
    if (!showForm) return
    const handleKey = (e: KeyboardEvent) => { if (e.key === 'Escape') resetForm() }
    const handleClick = (e: MouseEvent) => {
      if (formRef.current && !formRef.current.contains(e.target as Node)) resetForm()
    }
    window.addEventListener('keydown', handleKey)
    document.addEventListener('mousedown', handleClick)
    return () => { window.removeEventListener('keydown', handleKey); document.removeEventListener('mousedown', handleClick) }
  }, [showForm])

  const fetchTags = async () => {
    setLoading(true)
    const res = await fetch('/api/tags')
    setTags(await res.json())
    setLoading(false)
  }

  useEffect(() => { fetchTags() }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return

    if (editing) {
      await fetch(`/api/tags/${editing.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), color }),
      })
    } else {
      await fetch('/api/tags', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), color }),
      })
    }

    resetForm()
    fetchTags()
  }

  const handleDelete = async (id: string) => {
    setConfirmDelete(id)
  }

  const executeDelete = async () => {
    if (!confirmDelete) return
    await fetch(`/api/tags/${confirmDelete}`, { method: 'DELETE' })
    setConfirmDelete(null)
    fetchTags()
  }

  const startEdit = (tag: Tag) => {
    setEditing(tag)
    setName(tag.name)
    setColor(tag.color)
    setShowForm(true)
  }

  const resetForm = () => {
    setShowForm(false)
    setEditing(null)
    setName('')
    setColor('#3b82f6')
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Tags</h1>
          <p className="text-surface-700 text-sm mt-0.5">
            Manage tags for tasks and notes
          </p>
        </div>
        <button onClick={() => setShowForm(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Tag
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      ) : tags.length === 0 ? (
        <div className="text-center py-20">
          <div className="w-16 h-16 rounded-2xl bg-surface-200/40 flex items-center justify-center mx-auto mb-4">
            <Hash className="w-8 h-8 text-surface-700" />
          </div>
          <h3 className="text-lg font-medium text-surface-800">No tags yet</h3>
          <p className="text-surface-700 text-sm mt-1">Create tags to organize tasks and notes</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {tags.map(tag => (
            <div key={tag.id} className="card p-4 group hover:border-surface-400/40 transition-all">
              <div className="flex items-center gap-3">
                <div
                  className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                  style={{ backgroundColor: tag.color + '20', border: `1px solid ${tag.color}30` }}
                >
                  <Hash className="w-4 h-4" style={{ color: tag.color }} />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="font-medium text-surface-950 truncate">{tag.name}</h3>
                  <div className="flex items-center gap-2 text-xs text-surface-700">
                    {(tag.task_count || 0) > 0 && (
                      <span>{tag.task_count} task{tag.task_count !== 1 ? 's' : ''}</span>
                    )}
                    {(tag.note_count || 0) > 0 && (
                      <span>{tag.note_count} note{tag.note_count !== 1 ? 's' : ''}</span>
                    )}
                    {!tag.task_count && !tag.note_count && <span>Unused</span>}
                  </div>
                </div>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => startEdit(tag)}
                    className="p-1.5 rounded-lg hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                  >
                    <Pencil className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => handleDelete(tag.id)}
                    className="p-1.5 rounded-lg hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Form modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div ref={formRef} className="card w-full max-w-md p-6 animate-scale-in">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-white">
                {editing ? 'Edit Tag' : 'New Tag'}
              </h2>
              <button onClick={resetForm} className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">Name</label>
                <input
                  type="text"
                  className="input-base"
                  placeholder="Tag name"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  maxLength={30}
                  required
                  autoFocus
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">Color</label>
                <div className="grid grid-cols-6 gap-3">
                  {PRESET_COLORS.map(c => (
                    <button
                      key={c}
                      type="button"
                      onClick={() => setColor(c)}
                      className={cn(
                        'w-10 h-10 rounded-xl transition-all',
                        color === c ? 'ring-2 ring-white ring-offset-2 ring-offset-surface-100 scale-110' : 'hover:scale-110'
                      )}
                      style={{ backgroundColor: c }}
                    />
                  ))}
                </div>
                <div className="flex items-center gap-2 mt-2">
                  <input
                    type="color"
                    value={color}
                    onChange={e => setColor(e.target.value)}
                    className="w-8 h-8 rounded cursor-pointer"
                  />
                  <input
                    type="text"
                    className="input-base flex-1"
                    value={color}
                    onChange={e => setColor(e.target.value)}
                    pattern="^#[0-9a-fA-F]{6}$"
                  />
                </div>
              </div>

              {/* Preview */}
              <div className="p-3 rounded-xl bg-surface-200/40">
                <div className="flex items-center gap-2">
                  <span
                    className="badge gap-1"
                    style={{
                      backgroundColor: color + '20',
                      color: color,
                      border: `1px solid ${color}30`,
                    }}
                  >
                    <Hash className="w-3 h-3" />
                    {name || 'Preview'}
                  </span>
                </div>
              </div>

              <div className="flex gap-3 pt-2">
                <button type="button" onClick={resetForm} className="btn-secondary flex-1">
                  Cancel
                </button>
                <button type="submit" className="btn-primary flex-1">
                  {editing ? 'Save Changes' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      <ConfirmModal
        open={!!confirmDelete}
        title="Delete Tag"
        message="This tag will be removed from all tasks and notes."
        onConfirm={executeDelete}
        onCancel={() => setConfirmDelete(null)}
      />
    </div>
  )
}

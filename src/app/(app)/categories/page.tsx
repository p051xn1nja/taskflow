'use client'

import { useState, useEffect, useRef } from 'react'
import { Plus, Pencil, Trash2, Tag, X, Loader2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Category } from '@/types'

const PRESET_COLORS = [
  '#ef4444', '#f97316', '#f59e0b', '#22c55e', '#14b8a6',
  '#06b6d4', '#3b82f6', '#6366f1', '#8b5cf6', '#ec4899',
  '#64748b', '#78716c',
]

export default function CategoriesPage() {
  const [categories, setCategories] = useState<Category[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editing, setEditing] = useState<Category | null>(null)
  const [name, setName] = useState('')
  const [color, setColor] = useState('#3b82f6')

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

  const fetchCategories = async () => {
    setLoading(true)
    const res = await fetch('/api/categories')
    setCategories(await res.json())
    setLoading(false)
  }

  useEffect(() => { fetchCategories() }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return

    if (editing) {
      await fetch(`/api/categories/${editing.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), color }),
      })
    } else {
      await fetch('/api/categories', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), color }),
      })
    }

    resetForm()
    fetchCategories()
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this category? Tasks and notes will be uncategorized.')) return
    await fetch(`/api/categories/${id}`, { method: 'DELETE' })
    fetchCategories()
  }

  const startEdit = (cat: Category) => {
    setEditing(cat)
    setName(cat.name)
    setColor(cat.color)
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
          <h1 className="text-2xl font-bold text-white">Categories</h1>
          <p className="text-surface-700 text-sm mt-0.5">
            Organize your tasks and notes with categories
          </p>
        </div>
        <button onClick={() => setShowForm(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Category
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      ) : categories.length === 0 ? (
        <div className="text-center py-20">
          <div className="w-16 h-16 rounded-2xl bg-surface-200/40 flex items-center justify-center mx-auto mb-4">
            <Tag className="w-8 h-8 text-surface-700" />
          </div>
          <h3 className="text-lg font-medium text-surface-800">No categories yet</h3>
          <p className="text-surface-700 text-sm mt-1">Create categories to organize your tasks and notes</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {categories.map(cat => (
            <div key={cat.id} className="card p-4 group hover:border-surface-400/40 transition-all">
              <div className="flex items-center gap-3">
                <div
                  className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                  style={{ backgroundColor: cat.color + '20', border: `1px solid ${cat.color}30` }}
                >
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: cat.color }} />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="font-medium text-surface-950 truncate">{cat.name}</h3>
                  <p className="text-xs text-surface-700">{cat.task_count || 0} tasks &middot; {cat.note_count || 0} notes</p>
                </div>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => startEdit(cat)}
                    className="p-1.5 rounded-lg hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                  >
                    <Pencil className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => handleDelete(cat.id)}
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
                {editing ? 'Edit Category' : 'New Category'}
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
                  placeholder="Category name"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  maxLength={40}
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
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: color }}
                  />
                  <span className="text-sm font-medium text-surface-900">
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
    </div>
  )
}

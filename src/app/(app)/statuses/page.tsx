'use client'

import { useState, useEffect } from 'react'
import {
  Plus, Pencil, Trash2, GripVertical, X, Loader2,
  CircleDot, Check, Shield,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Status } from '@/types'

const PRESET_COLORS = [
  '#64748b', '#ef4444', '#f97316', '#f59e0b', '#22c55e', '#14b8a6',
  '#06b6d4', '#3b82f6', '#6366f1', '#8b5cf6', '#ec4899', '#78716c',
]

export default function StatusesPage() {
  const [statuses, setStatuses] = useState<Status[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editing, setEditing] = useState<Status | null>(null)
  const [name, setName] = useState('')
  const [color, setColor] = useState('#3b82f6')
  const [isCompleted, setIsCompleted] = useState(false)
  const [dragIdx, setDragIdx] = useState<number | null>(null)
  const [dragOverIdx, setDragOverIdx] = useState<number | null>(null)

  const fetchStatuses = async () => {
    setLoading(true)
    const res = await fetch('/api/statuses')
    setStatuses(await res.json())
    setLoading(false)
  }

  useEffect(() => { fetchStatuses() }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return

    if (editing) {
      await fetch(`/api/statuses/${editing.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), color, is_completed: isCompleted }),
      })
    } else {
      await fetch('/api/statuses', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), color, is_completed: isCompleted }),
      })
    }

    resetForm()
    fetchStatuses()
  }

  const handleDelete = async (id: string) => {
    const s = statuses.find(st => st.id === id)
    if (s?.is_default) { alert('Cannot delete the default status.'); return }
    if (!confirm('Delete this status? Tasks in this status will be moved to the default status.')) return
    await fetch(`/api/statuses/${id}`, { method: 'DELETE' })
    fetchStatuses()
  }

  const startEdit = (s: Status) => {
    setEditing(s)
    setName(s.name)
    setColor(s.color)
    setIsCompleted(s.is_completed)
    setShowForm(true)
  }

  const resetForm = () => {
    setShowForm(false)
    setEditing(null)
    setName('')
    setColor('#3b82f6')
    setIsCompleted(false)
  }

  // Drag reorder
  const handleDragStart = (idx: number) => setDragIdx(idx)
  const handleDragOver = (e: React.DragEvent, idx: number) => {
    e.preventDefault()
    setDragOverIdx(idx)
  }
  const handleDrop = async (targetIdx: number) => {
    if (dragIdx === null || dragIdx === targetIdx) { setDragIdx(null); setDragOverIdx(null); return }
    const reordered = [...statuses]
    const [moved] = reordered.splice(dragIdx, 1)
    reordered.splice(targetIdx, 0, moved)
    setStatuses(reordered)
    setDragIdx(null)
    setDragOverIdx(null)

    // Save new order
    await fetch(`/api/statuses/${moved.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ positions: reordered.map(s => s.id) }),
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Statuses</h1>
          <p className="text-surface-700 text-sm mt-0.5">
            Define workflow stages for your tasks. Drag to reorder columns on the board.
          </p>
        </div>
        <button onClick={() => setShowForm(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Status
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      ) : (
        <div className="space-y-2">
          {statuses.map((s, idx) => (
            <div
              key={s.id}
              draggable
              onDragStart={() => handleDragStart(idx)}
              onDragOver={e => handleDragOver(e, idx)}
              onDrop={() => handleDrop(idx)}
              onDragEnd={() => { setDragIdx(null); setDragOverIdx(null) }}
              className={cn(
                'card p-4 group hover:border-surface-400/40 transition-all cursor-grab active:cursor-grabbing',
                dragOverIdx === idx && 'ring-2 ring-brand-500/40',
              )}
            >
              <div className="flex items-center gap-3">
                <GripVertical className="w-4 h-4 text-surface-700 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                <div
                  className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                  style={{ backgroundColor: s.color + '20', border: `1px solid ${s.color}30` }}
                >
                  <CircleDot className="w-4 h-4" style={{ color: s.color }} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="font-medium text-surface-950">{s.name}</h3>
                    {s.is_default && (
                      <span className="text-[10px] font-medium text-brand-400 bg-brand-600/15 px-1.5 py-0.5 rounded">DEFAULT</span>
                    )}
                    {s.is_completed && (
                      <span className="text-[10px] font-medium text-accent-green bg-accent-green/15 px-1.5 py-0.5 rounded flex items-center gap-0.5">
                        <Check className="w-2.5 h-2.5" /> DONE
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-surface-700">
                    {s.task_count || 0} task{(s.task_count || 0) !== 1 ? 's' : ''}
                    <span className="text-surface-600 mx-1">&middot;</span>
                    Position {s.position + 1}
                  </p>
                </div>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => startEdit(s)}
                    className="p-1.5 rounded-lg hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                  >
                    <Pencil className="w-3.5 h-3.5" />
                  </button>
                  {!s.is_default && (
                    <button
                      onClick={() => handleDelete(s.id)}
                      className="p-1.5 rounded-lg hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors"
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
                {editing ? 'Edit Status' : 'New Status'}
              </h2>
              <button onClick={resetForm} className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">Name</label>
                <input type="text" className="input-base" placeholder="Status name"
                  value={name} onChange={e => setName(e.target.value)} maxLength={40} required autoFocus />
              </div>

              <div>
                <label className="block text-sm font-medium text-surface-800 mb-1.5">Color</label>
                <div className="grid grid-cols-6 gap-3">
                  {PRESET_COLORS.map(c => (
                    <button key={c} type="button" onClick={() => setColor(c)}
                      className={cn('w-10 h-10 rounded-xl transition-all', color === c ? 'ring-2 ring-white ring-offset-2 ring-offset-surface-100 scale-110' : 'hover:scale-110')}
                      style={{ backgroundColor: c }} />
                  ))}
                </div>
                <div className="flex items-center gap-2 mt-2">
                  <input type="color" value={color} onChange={e => setColor(e.target.value)} className="w-8 h-8 rounded cursor-pointer" />
                  <input type="text" className="input-base flex-1" value={color} onChange={e => setColor(e.target.value)} pattern="^#[0-9a-fA-F]{6}$" />
                </div>
              </div>

              <div>
                <label className="flex items-center gap-3 cursor-pointer">
                  <div className={cn(
                    'w-5 h-5 rounded-md border-2 flex items-center justify-center transition-all',
                    isCompleted ? 'bg-accent-green border-accent-green' : 'border-surface-500'
                  )}>
                    {isCompleted && <Check className="w-3 h-3 text-white" />}
                  </div>
                  <input type="checkbox" className="hidden" checked={isCompleted} onChange={e => setIsCompleted(e.target.checked)} />
                  <div>
                    <span className="text-sm font-medium text-surface-900">Marks task as completed</span>
                    <p className="text-xs text-surface-700">Tasks in this status will be treated as done</p>
                  </div>
                </label>
              </div>

              {/* Preview */}
              <div className="p-3 rounded-xl bg-surface-200/40">
                <div className="flex items-center gap-2">
                  <CircleDot className="w-4 h-4" style={{ color }} />
                  <span className="text-sm font-medium text-surface-900">{name || 'Preview'}</span>
                  {isCompleted && <Check className="w-3.5 h-3.5 text-accent-green" />}
                </div>
              </div>

              <div className="flex gap-3 pt-2">
                <button type="button" onClick={resetForm} className="btn-secondary flex-1">Cancel</button>
                <button type="submit" className="btn-primary flex-1">{editing ? 'Save Changes' : 'Create'}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

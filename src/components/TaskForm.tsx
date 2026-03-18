'use client'

import { useState, useEffect } from 'react'
import { X, Plus } from 'lucide-react'
import type { Task, Category } from '@/types'

interface TaskFormProps {
  task?: Task | null
  categories: Category[]
  onSubmit: (data: {
    title: string
    description: string
    category_id: string | null
    tags: string[]
    due_date: string | null
  }) => void
  onCancel: () => void
}

export function TaskForm({ task, categories, onSubmit, onCancel }: TaskFormProps) {
  const [title, setTitle] = useState(task?.title || '')
  const [description, setDescription] = useState(task?.description || '')
  const [categoryId, setCategoryId] = useState(task?.category_id || '')
  const [tags, setTags] = useState<string[]>(task?.tags || [])
  const [tagInput, setTagInput] = useState('')
  const [dueDate, setDueDate] = useState(task?.due_date || '')

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onCancel])

  const addTag = () => {
    const t = tagInput.trim()
    if (t && !tags.includes(t) && tags.length < 10) {
      setTags([...tags, t])
      setTagInput('')
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!title.trim()) return
    onSubmit({
      title: title.trim(),
      description: description.trim(),
      category_id: categoryId || null,
      tags,
      due_date: dueDate || null,
    })
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="card w-full max-w-lg p-6 animate-scale-in max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-semibold text-white">
            {task ? 'Edit Task' : 'New Task'}
          </h2>
          <button onClick={onCancel} className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-surface-800 mb-1.5">Title *</label>
            <input
              type="text"
              className="input-base"
              placeholder="What needs to be done?"
              value={title}
              onChange={e => setTitle(e.target.value)}
              maxLength={120}
              required
              autoFocus
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-surface-800 mb-1.5">Description</label>
            <textarea
              className="input-base min-h-[100px] resize-y"
              placeholder="Add details..."
              value={description}
              onChange={e => setDescription(e.target.value)}
              maxLength={1000}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-surface-800 mb-1.5">Category</label>
              <select
                className="input-base"
                value={categoryId}
                onChange={e => setCategoryId(e.target.value)}
              >
                <option value="">No category</option>
                {categories.map(c => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-surface-800 mb-1.5">Due Date</label>
              <input
                type="date"
                className="input-base"
                value={dueDate}
                onChange={e => setDueDate(e.target.value)}
              />
            </div>
          </div>

          {/* Tags */}
          <div>
            <label className="block text-sm font-medium text-surface-800 mb-1.5">
              Tags ({tags.length}/10)
            </label>
            {tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mb-2">
                {tags.map(tag => (
                  <span
                    key={tag}
                    className="badge bg-brand-600/10 text-brand-400 border border-brand-500/20 gap-1"
                  >
                    {tag}
                    <button
                      type="button"
                      onClick={() => setTags(tags.filter(t => t !== tag))}
                      className="hover:text-accent-red"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}
            <div className="flex gap-2">
              <input
                type="text"
                className="input-base flex-1"
                placeholder="Add a tag..."
                value={tagInput}
                onChange={e => setTagInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag() } }}
                maxLength={30}
              />
              <button
                type="button"
                onClick={addTag}
                disabled={!tagInput.trim() || tags.length >= 10}
                className="btn-secondary px-3"
              >
                <Plus className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onCancel} className="btn-secondary flex-1">
              Cancel
            </button>
            <button type="submit" className="btn-primary flex-1">
              {task ? 'Save Changes' : 'Create Task'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

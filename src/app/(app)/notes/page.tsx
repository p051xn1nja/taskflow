'use client'

import { useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import {
  Plus, Search, Filter, FileText, Hash, Calendar,
  Pencil, Trash2, Loader2, Link2, Paperclip,
} from 'lucide-react'
import { cn, formatDate, formatDateTime } from '@/lib/utils'
import { Pagination } from '@/components/Pagination'
import type { Note, Tag } from '@/types'

function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, '').replace(/&[^;]+;/g, ' ').trim()
}

export default function NotesPage() {
  const router = useRouter()
  const [notes, setNotes] = useState<Note[]>([])
  const [allTags, setAllTags] = useState<Tag[]>([])
  const [loading, setLoading] = useState(true)
  const [pagination, setPagination] = useState({ page: 1, per_page: 50, total: 0, total_pages: 0 })

  // Filters
  const [search, setSearch] = useState('')
  const [filterTag, setFilterTag] = useState('')
  const [showFilters, setShowFilters] = useState(false)

  const fetchNotes = useCallback(async (page = 1) => {
    setLoading(true)
    const params = new URLSearchParams()
    if (search) params.set('search', search)
    if (filterTag) params.set('tag', filterTag)
    params.set('page', String(page))
    params.set('per_page', '50')

    const res = await fetch(`/api/notes?${params}`)
    const data = await res.json()
    setNotes(data.notes)
    setPagination(data.pagination)
    setLoading(false)
  }, [search, filterTag])

  const fetchTags = async () => {
    const res = await fetch('/api/tags')
    setAllTags(await res.json())
  }

  useEffect(() => { fetchTags() }, [])

  useEffect(() => {
    const timer = setTimeout(() => fetchNotes(), 300)
    return () => clearTimeout(timer)
  }, [fetchNotes])

  const handleCreateNote = async () => {
    const res = await fetch('/api/notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'Untitled Note', content: '' }),
    })
    const { id } = await res.json()
    router.push(`/notes/${id}`)
  }

  const handleDeleteNote = async (id: string) => {
    if (!confirm('Delete this note?')) return
    await fetch(`/api/notes/${id}`, { method: 'DELETE' })
    fetchNotes(pagination.page)
  }

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Notes</h1>
          <p className="text-surface-700 text-sm mt-0.5">
            {pagination.total} note{pagination.total !== 1 ? 's' : ''} total
          </p>
        </div>
        <button onClick={handleCreateNote} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Note
        </button>
      </div>

      {/* Search & Filters */}
      <div className="card p-4 space-y-3">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-surface-700 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              className="input-base pl-10"
              placeholder="Search notes..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={cn('btn-secondary flex items-center gap-2', showFilters && 'bg-brand-600/15 text-brand-400 border-brand-500/30')}
          >
            <Filter className="w-4 h-4" /> Filters
          </button>
        </div>

        {showFilters && (
          <div className="pt-2 border-t border-surface-300/20 animate-slide-down">
            <select
              className="input-base text-sm"
              value={filterTag}
              onChange={e => setFilterTag(e.target.value)}
            >
              <option value="">All Tags</option>
              {allTags.map(t => (
                <option key={t.id} value={t.name}>{t.name}</option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Notes list */}
      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      ) : notes.length === 0 ? (
        <div className="text-center py-20">
          <div className="w-16 h-16 rounded-2xl bg-surface-200/40 flex items-center justify-center mx-auto mb-4">
            <FileText className="w-8 h-8 text-surface-700" />
          </div>
          <h3 className="text-lg font-medium text-surface-800">No notes found</h3>
          <p className="text-surface-700 text-sm mt-1">Create your first note to get started</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {notes.map(note => {
            const preview = stripHtml(note.content).slice(0, 150)
            return (
              <div
                key={note.id}
                onClick={() => router.push(`/notes/${note.id}`)}
                className="card p-4 group hover:border-surface-400/40 transition-all cursor-pointer"
              >
                <div className="flex items-start justify-between mb-2">
                  <h3 className="font-medium text-surface-950 truncate flex-1 pr-2">
                    {note.title}
                  </h3>
                  <div className="flex gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
                    <button
                      onClick={e => { e.stopPropagation(); router.push(`/notes/${note.id}`) }}
                      className="p-1.5 rounded-lg hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                      title="Edit"
                    >
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={e => { e.stopPropagation(); handleDeleteNote(note.id) }}
                      className="p-1.5 rounded-lg hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Content preview */}
                {preview && (
                  <p className="text-xs text-surface-800 line-clamp-3 leading-relaxed mb-3">
                    {preview}
                  </p>
                )}

                {/* Tags */}
                {note.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 mb-2">
                    {note.tags.map(tag => (
                      <span
                        key={tag.id}
                        className="inline-flex items-center gap-0.5 px-1.5 py-0 rounded-md text-[10px] font-medium"
                        style={{
                          backgroundColor: tag.color + '18',
                          color: tag.color,
                          border: `1px solid ${tag.color}20`,
                        }}
                      >
                        <Hash className="w-2.5 h-2.5" />
                        {tag.name}
                      </span>
                    ))}
                  </div>
                )}

                {/* Meta */}
                <div className="flex items-center gap-2 text-[10px] text-surface-700 flex-wrap">
                  <span className="flex items-center gap-1">
                    <Calendar className="w-3 h-3" />
                    {formatDate(note.updated_at)}
                  </span>
                  {note.linked_tasks.length > 0 && (
                    <span className="flex items-center gap-1">
                      <Link2 className="w-3 h-3" />
                      {note.linked_tasks.length} task{note.linked_tasks.length !== 1 ? 's' : ''}
                    </span>
                  )}
                  {note.attachments.length > 0 && (
                    <span className="flex items-center gap-1">
                      <Paperclip className="w-3 h-3" />
                      {note.attachments.length}
                    </span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Pagination */}
      <Pagination
        page={pagination.page}
        totalPages={pagination.total_pages}
        total={pagination.total}
        onPageChange={p => fetchNotes(p)}
      />
    </div>
  )
}

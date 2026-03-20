'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useRouter } from 'next/navigation'
import {
  Plus, Search, Filter, FileText, Hash, Calendar,
  Pencil, Trash2, Loader2, Link2, Paperclip, Palette, X, ChevronDown, ChevronRight,
  Download, CheckSquare, BookOpen, Tag as TagIcon, Clock,
} from 'lucide-react'
import { cn, formatDate, formatFileSize } from '@/lib/utils'
import { Pagination } from '@/components/Pagination'
import type { Note, Tag } from '@/types'

const NOTE_COLORS = [
  { name: 'None', value: '' },
  { name: 'Red', value: '#ef4444' },
  { name: 'Rose', value: '#f43f5e' },
  { name: 'Pink', value: '#ec4899' },
  { name: 'Fuchsia', value: '#d946ef' },
  { name: 'Purple', value: '#a855f7' },
  { name: 'Violet', value: '#8b5cf6' },
  { name: 'Indigo', value: '#6366f1' },
  { name: 'Blue', value: '#3b82f6' },
  { name: 'Sky', value: '#0ea5e9' },
  { name: 'Cyan', value: '#06b6d4' },
  { name: 'Teal', value: '#14b8a6' },
  { name: 'Emerald', value: '#10b981' },
  { name: 'Green', value: '#22c55e' },
  { name: 'Lime', value: '#84cc16' },
  { name: 'Yellow', value: '#eab308' },
  { name: 'Amber', value: '#f59e0b' },
  { name: 'Orange', value: '#f97316' },
]

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

  // Tag filter search
  const [tagFilterSearch, setTagFilterSearch] = useState('')
  const [showTagDropdown, setShowTagDropdown] = useState(false)
  const tagDropdownRef = useRef<HTMLDivElement>(null)

  // Color picker state
  const [colorPickerNoteId, setColorPickerNoteId] = useState<string | null>(null)
  const colorPickerRef = useRef<HTMLDivElement>(null)

  // Note detail modal
  const [noteDetail, setNoteDetail] = useState<Note | null>(null)
  const [noteDetailLoading, setNoteDetailLoading] = useState(false)
  const noteDetailRef = useRef<HTMLDivElement>(null)

  // Collapsed groups (years, months, days)
  const [collapsedYears, setCollapsedYears] = useState<Set<string>>(new Set())
  const [collapsedMonths, setCollapsedMonths] = useState<Set<string>>(new Set())
  const [collapsedDays, setCollapsedDays] = useState<Set<string>>(new Set())

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

  // Close color picker on outside click
  useEffect(() => {
    if (!colorPickerNoteId) return
    const handler = (e: MouseEvent) => {
      if (colorPickerRef.current && !colorPickerRef.current.contains(e.target as Node)) {
        setColorPickerNoteId(null)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [colorPickerNoteId])

  // Close tag dropdown on outside click
  useEffect(() => {
    if (!showTagDropdown) return
    const handler = (e: MouseEvent) => {
      if (tagDropdownRef.current && !tagDropdownRef.current.contains(e.target as Node)) {
        setShowTagDropdown(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showTagDropdown])

  // Close note detail on outside click
  useEffect(() => {
    if (!noteDetail) return
    const handler = (e: MouseEvent) => {
      if (noteDetailRef.current && !noteDetailRef.current.contains(e.target as Node)) setNoteDetail(null)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [noteDetail])

  // ESC to close popups
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (noteDetail) { setNoteDetail(null); return }
        if (colorPickerNoteId) { setColorPickerNoteId(null); return }
        if (showTagDropdown) { setShowTagDropdown(false); return }
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [noteDetail, colorPickerNoteId, showTagDropdown])

  const handleViewNote = async (noteId: string) => {
    setNoteDetailLoading(true)
    setNoteDetail(null)
    try {
      const res = await fetch(`/api/notes/${noteId}`)
      if (res.ok) {
        setNoteDetail(await res.json())
      }
    } catch {
      // ignore
    }
    setNoteDetailLoading(false)
  }

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

  const handleSetColor = async (noteId: string, color: string) => {
    await fetch(`/api/notes/${noteId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ color }),
    })
    setNotes(prev => prev.map(n => n.id === noteId ? { ...n, color } : n))
    setColorPickerNoteId(null)
  }

  const filteredDropdownTags = allTags.filter(t =>
    t.name.toLowerCase().includes(tagFilterSearch.toLowerCase())
  )

  const selectedTagObj = allTags.find(t => t.name === filterTag)

  const toggleYear = (key: string) => {
    setCollapsedYears(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n })
  }
  const toggleMonth = (key: string) => {
    setCollapsedMonths(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n })
  }
  const toggleDay = (key: string) => {
    setCollapsedDays(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n })
  }

  // Group notes by year > month > day (using updated_at like tasks use created_at)
  const todayDate = new Date()
  const todayStr = todayDate.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
  const todayMonth = todayDate.toLocaleDateString('en-US', { year: 'numeric', month: 'long' })
  const todayYear = String(todayDate.getFullYear())

  const groupedByYear: Record<string, Record<string, Record<string, Note[]>>> = {}
  for (const note of notes) {
    const d = new Date(note.updated_at)
    const yearKey = String(d.getFullYear())
    const monthKey = d.toLocaleDateString('en-US', { year: 'numeric', month: 'long' })
    const dayKey = d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
    if (!groupedByYear[yearKey]) groupedByYear[yearKey] = {}
    if (!groupedByYear[yearKey][monthKey]) groupedByYear[yearKey][monthKey] = {}
    if (!groupedByYear[yearKey][monthKey][dayKey]) groupedByYear[yearKey][monthKey][dayKey] = []
    groupedByYear[yearKey][monthKey][dayKey].push(note)
  }

  // Auto-collapse non-current groups
  useEffect(() => {
    const allYears = Object.keys(groupedByYear)
    const allMonths = Object.values(groupedByYear).flatMap(months => Object.keys(months))
    const allDays = Object.values(groupedByYear).flatMap(months =>
      Object.values(months).flatMap(days => Object.keys(days))
    )
    setCollapsedYears(new Set(allYears.filter(y => y !== todayYear)))
    setCollapsedMonths(new Set(allMonths.filter(m => m !== todayMonth)))
    setCollapsedDays(new Set(allDays.filter(d => d !== todayStr)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [notes])

  // Render a single note card (used inside day groups)
  const renderNoteCard = (note: Note) => {
    const preview = stripHtml(note.content).slice(0, 150)
    const noteColor = note.color || ''
    return (
      <div
        key={note.id}
        onClick={() => handleViewNote(note.id)}
        className={cn(
          'card group transition-all duration-200 hover:border-surface-400/40 cursor-pointer',
        )}
        style={noteColor ? { borderLeft: `3px solid ${noteColor}` } : undefined}
      >
        <div className="p-4">
          <div className="flex items-start gap-3">
            {/* Note icon */}
            <div className="mt-0.5 flex-shrink-0">
              <FileText className="w-5 h-5 text-accent-purple" />
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="font-medium text-surface-950 truncate">
                  {note.title}
                </h3>
              </div>

              {/* Content preview */}
              {preview && (
                <p className="text-xs text-surface-800 line-clamp-2 leading-relaxed mt-1">
                  {preview}
                </p>
              )}

              {/* Tags */}
              {note.tags.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1.5">
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

              {/* Meta row */}
              <div className="flex items-center gap-3 mt-1.5 text-xs text-surface-800 flex-wrap">
                <span>{formatDate(note.updated_at)}</span>
                {note.linked_tasks.length > 0 && (
                  <span className="flex items-center gap-1">
                    <Link2 className="w-3 h-3" /> {note.linked_tasks.length} task{note.linked_tasks.length !== 1 ? 's' : ''}
                  </span>
                )}
                {note.attachments.length > 0 && (
                  <span className="flex items-center gap-1">
                    <Paperclip className="w-3 h-3" /> {note.attachments.length}
                  </span>
                )}
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
              <div className="relative">
                <button
                  onClick={e => { e.stopPropagation(); setColorPickerNoteId(colorPickerNoteId === note.id ? null : note.id) }}
                  className="p-1.5 rounded-lg hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                  title="Note color"
                >
                  <Palette className="w-3.5 h-3.5" />
                </button>
                {colorPickerNoteId === note.id && (
                  <div
                    ref={colorPickerRef}
                    onClick={e => e.stopPropagation()}
                    className="absolute right-0 bottom-full mb-1 bg-surface-100 border border-surface-300/40 rounded-xl shadow-xl z-50 p-2.5 min-w-[200px] animate-scale-in"
                  >
                    <p className="text-[10px] font-semibold text-surface-700 uppercase tracking-wider mb-2 px-0.5">Card Color</p>
                    <div className="grid grid-cols-6 gap-2">
                      {NOTE_COLORS.map(c => (
                        <button
                          key={c.value || 'none'}
                          type="button"
                          onClick={() => handleSetColor(note.id, c.value)}
                          className={cn(
                            'w-7 h-7 rounded-full transition-all hover:scale-110 flex items-center justify-center',
                            noteColor === c.value && 'ring-2 ring-offset-1 ring-brand-400 ring-offset-surface-100',
                          )}
                          style={c.value ? { backgroundColor: c.value } : undefined}
                          title={c.name}
                        >
                          {!c.value && <X className="w-3 h-3 text-surface-700" />}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
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
        </div>
      </div>
    )
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

      {/* Stats cards */}
      <div className="flex gap-3 overflow-x-auto pb-1">
        {/* Total */}
        <div className="card p-4 min-w-[140px] flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-accent-purple/15 flex items-center justify-center">
              <BookOpen className="w-4 h-4 text-accent-purple" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{pagination.total}</p>
              <p className="text-xs text-surface-700">Total</p>
            </div>
          </div>
        </div>

        {/* Tagged */}
        <div className="card p-4 min-w-[140px] flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-brand-600/15 flex items-center justify-center">
              <TagIcon className="w-4 h-4 text-brand-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{notes.filter(n => n.tags.length > 0).length}</p>
              <p className="text-xs text-surface-700">Tagged</p>
            </div>
          </div>
        </div>

        {/* Linked to Tasks */}
        <div className="card p-4 min-w-[140px] flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-accent-green/15 flex items-center justify-center">
              <Link2 className="w-4 h-4 text-accent-green" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{notes.filter(n => n.linked_tasks.length > 0).length}</p>
              <p className="text-xs text-surface-700">Linked</p>
            </div>
          </div>
        </div>

        {/* Updated This Week */}
        <div className="card p-4 min-w-[140px] flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-accent-amber/15 flex items-center justify-center">
              <Clock className="w-4 h-4 text-accent-amber" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">
                {notes.filter(n => {
                  const d = new Date(n.updated_at)
                  const now = new Date()
                  return (now.getTime() - d.getTime()) < 7 * 24 * 60 * 60 * 1000
                }).length}
              </p>
              <p className="text-xs text-surface-700">This Week</p>
            </div>
          </div>
        </div>
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
            <div className="relative" ref={tagDropdownRef}>
              <button
                type="button"
                onClick={() => setShowTagDropdown(!showTagDropdown)}
                className="input-base text-sm w-full text-left flex items-center justify-between"
              >
                <span className="flex items-center gap-2 truncate">
                  {filterTag ? (
                    <>
                      {selectedTagObj && (
                        <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: selectedTagObj.color }} />
                      )}
                      <span className="text-surface-900">{filterTag}</span>
                    </>
                  ) : (
                    <span className="text-surface-700">All Tags</span>
                  )}
                </span>
                <div className="flex items-center gap-1 flex-shrink-0">
                  {filterTag && (
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); setFilterTag(''); setTagFilterSearch('') }}
                      className="p-0.5 rounded hover:bg-surface-300/40 text-surface-700 hover:text-surface-900"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                  <ChevronDown className={cn('w-4 h-4 text-surface-700 transition-transform', showTagDropdown && 'rotate-180')} />
                </div>
              </button>
              {showTagDropdown && (
                <div className="absolute left-0 right-0 top-full mt-1 bg-surface-100 border border-surface-300/40 rounded-xl shadow-xl z-50 overflow-hidden">
                  <div className="p-2 border-b border-surface-300/20">
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 text-surface-700 absolute left-2.5 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        className="input-base pl-8 text-sm py-1.5"
                        placeholder="Search tags..."
                        value={tagFilterSearch}
                        onChange={e => setTagFilterSearch(e.target.value)}
                        autoFocus
                      />
                    </div>
                  </div>
                  <div className="max-h-52 overflow-y-auto">
                    <button
                      type="button"
                      className={cn(
                        'flex items-center gap-2 w-full px-3 py-2 text-sm text-left hover:bg-surface-300/30 transition-colors',
                        !filterTag && 'bg-brand-600/10 text-brand-400',
                      )}
                      onClick={() => { setFilterTag(''); setTagFilterSearch(''); setShowTagDropdown(false) }}
                    >
                      <span className="text-surface-900">All Tags</span>
                    </button>
                    {filteredDropdownTags.map(tag => (
                      <button
                        key={tag.id}
                        type="button"
                        className={cn(
                          'flex items-center gap-2 w-full px-3 py-2 text-sm text-left hover:bg-surface-300/30 transition-colors',
                          filterTag === tag.name && 'bg-brand-600/10 text-brand-400',
                        )}
                        onClick={() => { setFilterTag(tag.name); setTagFilterSearch(''); setShowTagDropdown(false) }}
                      >
                        <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: tag.color }} />
                        <span className="text-surface-900">{tag.name}</span>
                      </button>
                    ))}
                    {filteredDropdownTags.length === 0 && (
                      <p className="text-xs text-surface-700 text-center py-3">No tags found</p>
                    )}
                  </div>
                </div>
              )}
            </div>
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
        <div className="space-y-4">
          {Object.entries(groupedByYear).map(([year, months]) => {
            const yearNoteCount = Object.values(months).reduce((s, days) =>
              s + Object.values(days).reduce((s2, d) => s2 + d.length, 0), 0
            )
            const isYearCollapsed = collapsedYears.has(year)
            return (
              <div key={year} className="space-y-3">
                {/* Year header */}
                <button
                  onClick={() => toggleYear(year)}
                  className="w-full flex items-center gap-2.5 px-1 py-1 text-sm font-bold text-surface-900 hover:text-white transition-colors"
                >
                  {isYearCollapsed ? (
                    <ChevronRight className="w-4 h-4 text-surface-600" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-surface-600" />
                  )}
                  <Calendar className="w-4 h-4 text-accent-purple" />
                  {year}
                  <span className="text-surface-600 font-normal text-xs ml-auto">
                    {yearNoteCount} note{yearNoteCount !== 1 ? 's' : ''}
                  </span>
                </button>

                {!isYearCollapsed && (
                  <div className="space-y-3 animate-fade-in">
                    {Object.entries(months).map(([month, days]) => {
                      const monthNoteCount = Object.values(days).reduce((s, d) => s + d.length, 0)
                      const isMonthCollapsed = collapsedMonths.has(month)
                      const monthLabel = month.replace(/\s*\d{4}$/, '')
                      return (
                        <div key={month} className="card">
                          {/* Month header */}
                          <button
                            onClick={() => toggleMonth(month)}
                            className="w-full flex items-center gap-2.5 px-4 py-3 text-sm font-semibold text-surface-900 hover:bg-surface-200/40 transition-colors"
                          >
                            {isMonthCollapsed ? (
                              <ChevronRight className="w-4 h-4 text-surface-600" />
                            ) : (
                              <ChevronDown className="w-4 h-4 text-surface-600" />
                            )}
                            <Calendar className="w-3.5 h-3.5 text-accent-purple" />
                            {monthLabel}
                            <span className="text-surface-600 font-normal text-xs ml-auto">
                              {monthNoteCount} note{monthNoteCount !== 1 ? 's' : ''}
                            </span>
                          </button>

                          {/* Days within month */}
                          {!isMonthCollapsed && (
                            <div className="border-t border-surface-300/20 animate-fade-in">
                              {Object.entries(days).map(([day, dayNotes]) => {
                                const isDayCollapsed = collapsedDays.has(day)
                                const dayPart = new Date(dayNotes[0].updated_at).toLocaleDateString('en-US', { weekday: 'short', day: 'numeric' })
                                const isToday = day === todayStr
                                return (
                                  <div key={day}>
                                    <button
                                      onClick={() => toggleDay(day)}
                                      className={cn(
                                        'w-full flex items-center gap-2 px-4 py-2 text-xs font-medium transition-colors',
                                        isToday
                                          ? 'text-accent-purple bg-accent-purple/5 hover:bg-accent-purple/10'
                                          : 'text-surface-700 hover:bg-surface-200/30'
                                      )}
                                    >
                                      {isDayCollapsed ? (
                                        <ChevronRight className="w-3.5 h-3.5" />
                                      ) : (
                                        <ChevronDown className="w-3.5 h-3.5" />
                                      )}
                                      {dayPart}
                                      {isToday && (
                                        <span className="px-1.5 py-0.5 rounded-md bg-accent-purple/15 text-accent-purple text-[10px] font-semibold">
                                          Today
                                        </span>
                                      )}
                                      <span className="font-normal ml-auto opacity-60">
                                        {dayNotes.length}
                                      </span>
                                    </button>

                                    {!isDayCollapsed && (
                                      <div className="space-y-2 px-4 pb-3 pt-1 animate-fade-in">
                                        {dayNotes.map(note => renderNoteCard(note))}
                                      </div>
                                    )}
                                  </div>
                                )
                              })}
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                )}
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

      {/* Note detail modal */}
      {(noteDetail || noteDetailLoading) && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          {noteDetailLoading ? (
            <div className="card p-8 animate-scale-in">
              <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
            </div>
          ) : noteDetail && (
            <div ref={noteDetailRef} className="card w-full max-w-lg p-6 animate-scale-in max-h-[85vh] overflow-y-auto"
              style={noteDetail.color ? { borderTop: `3px solid ${noteDetail.color}` } : undefined}
            >
              {/* Header */}
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1 min-w-0">
                  <h2 className="text-lg font-semibold text-white">{noteDetail.title}</h2>
                </div>
                <div className="flex items-center gap-1 flex-shrink-0">
                  <button
                    onClick={() => { setNoteDetail(null); router.push(`/notes/${noteDetail.id}`) }}
                    className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700 hover:text-brand-400 transition-colors"
                    title="Edit note"
                  >
                    <Pencil className="w-4 h-4" />
                  </button>
                  <button onClick={() => setNoteDetail(null)} className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700 transition-colors">
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>

              {/* Tags */}
              {noteDetail.tags.length > 0 && (
                <div className="mb-4">
                  <div className="flex flex-wrap gap-1.5">
                    {noteDetail.tags.map(tag => (
                      <span key={tag.id} className="badge gap-1" style={{
                        backgroundColor: tag.color + '18',
                        color: tag.color,
                        border: `1px solid ${tag.color}25`,
                      }}>
                        <Hash className="w-3 h-3" />
                        {tag.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Content */}
              {noteDetail.content && (
                <div className="mb-4">
                  <div
                    className="text-sm text-surface-800 bg-surface-200/40 rounded-xl p-3 rich-editor-content prose-sm"
                    dangerouslySetInnerHTML={{ __html: noteDetail.content }}
                  />
                </div>
              )}

              {/* Linked Tasks */}
              {noteDetail.linked_tasks.length > 0 && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-surface-800 mb-1.5 block">
                    <Link2 className="w-3 h-3 inline mr-1" />
                    Linked Tasks ({noteDetail.linked_tasks.length})
                  </label>
                  <div className="space-y-1.5">
                    {noteDetail.linked_tasks.map(task => (
                      <div key={task.id} className="flex items-center gap-2 bg-surface-200/40 rounded-lg p-2 text-sm">
                        <CheckSquare className={cn(
                          'w-4 h-4 flex-shrink-0',
                          task.status === 'completed' ? 'text-accent-green' : 'text-surface-700'
                        )} />
                        <span className={cn(
                          'flex-1 truncate',
                          task.status === 'completed' ? 'text-surface-700 line-through' : 'text-surface-900'
                        )}>
                          {task.title}
                        </span>
                        {task.progress > 0 && task.status !== 'completed' && (
                          <span className="text-[10px] text-surface-700 tabular-nums">{task.progress}%</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Attachments */}
              {noteDetail.attachments.length > 0 && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-surface-800 mb-1.5 block">
                    <Paperclip className="w-3 h-3 inline mr-1" />
                    Attachments ({noteDetail.attachments.length})
                  </label>
                  <div className="space-y-1.5">
                    {noteDetail.attachments.map(att => (
                      <div key={att.id} className="flex items-center gap-2 bg-surface-200/40 rounded-lg p-2 text-sm">
                        <FileText className="w-4 h-4 text-surface-700 flex-shrink-0" />
                        <span className="flex-1 truncate text-surface-800">{att.original_name}</span>
                        <span className="text-xs text-surface-700">{formatFileSize(att.size)}</span>
                        <a href={`/api/note-uploads/${att.id}`}
                          className="p-1 rounded hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                          title="Download">
                          <Download className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Meta */}
              <div className="text-[11px] text-surface-700 pt-2 border-t border-surface-300/20">
                Created {formatDate(noteDetail.created_at)}
                {noteDetail.updated_at && noteDetail.updated_at !== noteDetail.created_at && (
                  <span> &middot; Updated {formatDate(noteDetail.updated_at)}</span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

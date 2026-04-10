'use client'

import { useState, useEffect, useCallback, useRef, Suspense } from 'react'
import { useSession } from 'next-auth/react'
import { useSearchParams } from 'next/navigation'
import {
  Plus, Search, Filter, ChevronDown, ChevronRight, X,
  Calendar, Tag, BarChart3, CheckCircle2, Clock, Loader2, CircleDot, Bookmark, Trash2, AlertTriangle,
} from 'lucide-react'
import { TaskCard } from '@/components/TaskCard'
import { TaskForm } from '@/components/TaskForm'
import { Pagination } from '@/components/Pagination'
import { ConfirmModal } from '@/components/ConfirmModal'
import { cn, groupBy, parseQuickTaskInput } from '@/lib/utils'
import type { Task, Category, Status, Tag as TagType } from '@/types'

export default function TasksPage() {
  return (
    <Suspense fallback={null}>
      <TasksPageInner />
    </Suspense>
  )
}

function TasksPageInner() {
  const { data: session } = useSession()
  const searchParams = useSearchParams()
  const [tasks, setTasks] = useState<Task[]>([])
  const [categories, setCategories] = useState<Category[]>([])
  const [statuses, setStatuses] = useState<Status[]>([])
  const [allTags, setAllTags] = useState<TagType[]>([])
  const [loading, setLoading] = useState(true)
  const [pagination, setPagination] = useState({ page: 1, per_page: 50, total: 0, total_pages: 0 })

  // Filters
  const [search, setSearch] = useState('')
  const [filterCategory, setFilterCategory] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterTag, setFilterTag] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [showFilters, setShowFilters] = useState(false)
  const [focusView, setFocusView] = useState<'all' | 'inbox' | 'today' | 'upcoming'>('all')
  const [savedViews, setSavedViews] = useState<{ id: string; name: string; filters_json: string }[]>([])
  const [reminders, setReminders] = useState<{ overdue: number; due_today: number; next_7_days: number }>({ overdue: 0, due_today: 0, next_7_days: 0 })
  const [templates, setTemplates] = useState<Array<{ id: string; name: string; title: string; description: string; category_id: string | null; tags: string[]; recurrence: 'none' | 'daily' | 'weekly' | 'monthly' }>>([])
  const [selectedTemplateId, setSelectedTemplateId] = useState('')
  const [showTemplateModal, setShowTemplateModal] = useState(false)
  const [templateName, setTemplateName] = useState('')
  const [templateTitle, setTemplateTitle] = useState('')
  const [templateRecurrence, setTemplateRecurrence] = useState<'none' | 'daily' | 'weekly' | 'monthly'>('none')

  // Tag filter search
  const [tagFilterSearch, setTagFilterSearch] = useState('')
  const [showTagDropdown, setShowTagDropdown] = useState(false)
  const tagDropdownRef = useRef<HTMLDivElement>(null)

  // Form state
  const [showForm, setShowForm] = useState(false)
  const [editingTask, setEditingTask] = useState<Task | null>(null)
  const [defaultStartDate, setDefaultStartDate] = useState('')
  const [defaultDueDate, setDefaultDueDate] = useState('')
  const [showQuickAdd, setShowQuickAdd] = useState(false)
  const [quickTitle, setQuickTitle] = useState('')
  const [quickDueDate, setQuickDueDate] = useState('')

  // Auto-open task form from calendar
  useEffect(() => {
    if (searchParams.get('new_task') === '1') {
      setDefaultStartDate(searchParams.get('start_date') || searchParams.get('date') || '')
      setDefaultDueDate(searchParams.get('date') || '')
      setShowForm(true)
      // Clean up URL
      window.history.replaceState({}, '', '/')
    }
  }, [searchParams])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setShowQuickAdd(true)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  // Collapsed groups (years, months, days)
  const [collapsedYears, setCollapsedYears] = useState<Set<string>>(new Set())
  const [collapsedMonths, setCollapsedMonths] = useState<Set<string>>(new Set())
  const [collapsedDays, setCollapsedDays] = useState<Set<string>>(new Set())

  // Confirm delete modal
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)

  const fetchTasks = useCallback(async (page = 1) => {
    setLoading(true)
    const params = new URLSearchParams()
    if (search) params.set('search', search)
    if (filterCategory) params.set('category_id', filterCategory)
    if (filterStatus) params.set('status_id', filterStatus)
    if (filterTag) params.set('tag', filterTag)
    if (focusView !== 'all') params.set('view', focusView)
    if (dateFrom) params.set('date_from', dateFrom)
    if (dateTo) params.set('date_to', dateTo)
    params.set('page', String(page))
    params.set('per_page', String(pagination.per_page))

    const res = await fetch(`/api/tasks?${params}`)
    const data = await res.json()
    setTasks(data.tasks)
    setPagination(data.pagination)
    fetchReminders()
    setLoading(false)
  }, [search, filterCategory, filterStatus, filterTag, dateFrom, dateTo, focusView, pagination.per_page])

  const fetchCategories = async () => {
    const res = await fetch('/api/categories')
    setCategories(await res.json())
  }

  const fetchStatuses = async () => {
    const res = await fetch('/api/statuses')
    setStatuses(await res.json())
  }

  const fetchTags = async () => {
    const res = await fetch('/api/tags')
    setAllTags(await res.json())
  }
  const fetchSavedViews = async () => {
    const res = await fetch('/api/task-views')
    setSavedViews(await res.json())
  }
  const fetchReminders = async () => {
    const res = await fetch('/api/tasks/reminders')
    if (!res.ok) return
    const data = await res.json()
    setReminders(data.counts)
  }
  const fetchTemplates = async () => {
    const res = await fetch('/api/task-templates')
    if (!res.ok) return
    setTemplates(await res.json())
  }

  useEffect(() => {
    fetchCategories()
    fetchStatuses()
    fetchTags()
    fetchSavedViews()
    fetchReminders()
    fetchTemplates()
  }, [])

  useEffect(() => {
    const timer = setTimeout(() => fetchTasks(), 300)
    return () => clearTimeout(timer)
  }, [fetchTasks])

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

  // ESC to close tag dropdown
  useEffect(() => {
    if (!showTagDropdown) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setShowTagDropdown(false)
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [showTagDropdown])

  const handleCreateTask = async (data: { title: string; description: string; category_id: string | null; tags: string[]; start_date: string | null; due_date: string | null; location: string; recurrence?: 'none' | 'daily' | 'weekly' | 'monthly' }) => {
    const res = await fetch('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    const { id } = await res.json()
    setShowForm(false)
    fetchTasks(pagination.page)
    return id as string
  }

  const handleUpdateTask = async (id: string, data: Partial<Task>) => {
    await fetch(`/api/tasks/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    fetchTasks(pagination.page)
  }

  const handleEditSubmit = async (data: { title: string; description: string; category_id: string | null; tags: string[]; start_date: string | null; due_date: string | null; location: string; recurrence?: 'none' | 'daily' | 'weekly' | 'monthly'; progress?: number }) => {
    if (!editingTask) return
    await fetch(`/api/tasks/${editingTask.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    setEditingTask(null)
    fetchTasks(pagination.page)
  }

  const handleDeleteTask = async (id: string) => {
    setConfirmDelete(id)
  }

  const executeDeleteTask = async () => {
    if (!confirmDelete) return
    await fetch(`/api/tasks/${confirmDelete}`, { method: 'DELETE' })
    setConfirmDelete(null)
    fetchTasks(pagination.page)
  }

  const handleDeleteAttachment = async (attachmentId: string) => {
    await fetch(`/api/uploads/${attachmentId}`, { method: 'DELETE' })
  }

  const handleQuickAdd = async () => {
    const parsed = parseQuickTaskInput(quickTitle, quickDueDate)
    const title = parsed.title
    if (!title) return
    await fetch('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        due_date: parsed.due_date,
      }),
    })
    setShowQuickAdd(false)
    setQuickTitle('')
    setQuickDueDate('')
    fetchTasks(1)
  }

  const handleSaveCurrentView = async () => {
    const name = window.prompt('Save current view as:')
    if (!name?.trim()) return
    await fetch('/api/task-views', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name.trim(),
        filters: {
          search,
          category_id: filterCategory,
          status_id: filterStatus,
          tag: filterTag,
          date_from: dateFrom,
          date_to: dateTo,
          view: focusView,
        },
      }),
    })
    fetchSavedViews()
  }

  const applySavedView = (filtersJson: string) => {
    const f = JSON.parse(filtersJson) as {
      search?: string
      category_id?: string
      status_id?: string
      tag?: string
      date_from?: string
      date_to?: string
      view?: 'all' | 'inbox' | 'today' | 'upcoming'
    }
    setSearch(f.search || '')
    setFilterCategory(f.category_id || '')
    setFilterStatus(f.status_id || '')
    setFilterTag(f.tag || '')
    setDateFrom(f.date_from || '')
    setDateTo(f.date_to || '')
    setFocusView(f.view || 'all')
  }

  const deleteSavedView = async (id: string) => {
    await fetch(`/api/task-views/${id}`, { method: 'DELETE' })
    fetchSavedViews()
  }

  const handleBulkCompleteVisible = async () => {
    if (tasks.length === 0) return
    await fetch('/api/tasks/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ task_ids: tasks.map(t => t.id), action: 'complete' }),
    })
    fetchTasks(pagination.page)
  }

  const handleBulkDeleteCompletedVisible = async () => {
    const completedIds = tasks.filter(t => t.status === 'completed').map(t => t.id)
    if (completedIds.length === 0) return
    if (!window.confirm(`Delete ${completedIds.length} completed visible task(s)?`)) return
    await fetch('/api/tasks/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ task_ids: completedIds, action: 'delete' }),
    })
    fetchTasks(pagination.page)
  }

  const applyTemplate = async () => {
    const tpl = templates.find(t => t.id === selectedTemplateId)
    if (!tpl) return
    await fetch('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: tpl.title,
        description: tpl.description,
        category_id: tpl.category_id,
        tags: tpl.tags,
        recurrence: tpl.recurrence,
      }),
    })
    fetchTasks(1)
  }

  const createStarterSetup = async () => {
    const res = await fetch('/api/tasks/bootstrap', { method: 'POST' })
    if (!res.ok) return
    fetchTasks(1)
  }

  const createTemplate = async () => {
    const name = templateName.trim()
    const title = templateTitle.trim()
    if (!name || !title) return
    await fetch('/api/task-templates', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name,
        title,
        recurrence: templateRecurrence,
      }),
    })
    setShowTemplateModal(false)
    setTemplateName('')
    setTemplateTitle('')
    setTemplateRecurrence('none')
    fetchTemplates()
  }

  const deleteSelectedTemplate = async () => {
    if (!selectedTemplateId) return
    if (!window.confirm('Delete selected template?')) return
    await fetch(`/api/task-templates/${selectedTemplateId}`, { method: 'DELETE' })
    setSelectedTemplateId('')
    fetchTemplates()
  }

  const toggleYear = (key: string) => {
    setCollapsedYears(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  const toggleMonth = (key: string) => {
    setCollapsedMonths(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  const toggleDay = (key: string) => {
    setCollapsedDays(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  // Group tasks by year, then month, then day
  const todayDate = new Date()
  const todayStr = todayDate.toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' })
  const todayMonth = todayDate.toLocaleDateString('en-GB', { year: 'numeric', month: 'long' })
  const todayYear = String(todayDate.getFullYear())

  const groupedByYear: Record<string, Record<string, Record<string, Task[]>>> = {}
  for (const task of tasks) {
    const d = new Date(task.created_at)
    const yearKey = String(d.getFullYear())
    const monthKey = d.toLocaleDateString('en-GB', { year: 'numeric', month: 'long' })
    const dayKey = d.toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' })
    if (!groupedByYear[yearKey]) groupedByYear[yearKey] = {}
    if (!groupedByYear[yearKey][monthKey]) groupedByYear[yearKey][monthKey] = {}
    if (!groupedByYear[yearKey][monthKey][dayKey]) groupedByYear[yearKey][monthKey][dayKey] = []
    groupedByYear[yearKey][monthKey][dayKey].push(task)
  }

  // On initial load / data change, collapse everything except current day's year+month+day
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
  }, [tasks])

  // Stats — dynamic per-status counts
  const statusCounts: Record<string, number> = {}
  for (const task of tasks) {
    const sid = task.status_id || ''
    statusCounts[sid] = (statusCounts[sid] || 0) + 1
  }
  const avgProgress = tasks.length > 0 ? Math.round(tasks.reduce((s, t) => s + t.progress, 0) / tasks.length) : 0

  // Tag filter helpers
  const filteredDropdownTags = allTags.filter(t =>
    t.name.toLowerCase().includes(tagFilterSearch.toLowerCase())
  )
  const selectedTagObj = allTags.find(t => t.name === filterTag)

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold text-white">Tasks</h1>
          <p className="text-surface-700 text-sm mt-0.5">
            {pagination.total} task{pagination.total !== 1 ? 's' : ''} total
          </p>
        </div>
        <button onClick={() => setShowForm(true)} className="btn-primary flex items-center gap-2 flex-shrink-0">
          <Plus className="w-4 h-4" /> <span className="hidden sm:inline">New Task</span><span className="sm:hidden">New</span>
        </button>
      </div>
      <div className="card p-3 flex flex-wrap items-center gap-2">
        <span className="text-xs text-surface-700">Template:</span>
        <select
          className="input-base text-sm max-w-[240px]"
          value={selectedTemplateId}
          onChange={e => setSelectedTemplateId(e.target.value)}
        >
          <option value="">Select template</option>
          {templates.map(t => (
            <option key={t.id} value={t.id}>{t.name}</option>
          ))}
        </select>
        <button
          type="button"
          onClick={applyTemplate}
          disabled={!selectedTemplateId}
          className="btn-secondary text-xs px-3 py-1.5 disabled:opacity-50"
        >
          Use template
        </button>
        <button
          type="button"
          onClick={() => setShowTemplateModal(true)}
          className="btn-secondary text-xs px-3 py-1.5"
        >
          New template
        </button>
        <button
          type="button"
          onClick={deleteSelectedTemplate}
          disabled={!selectedTemplateId}
          className="btn-secondary text-xs px-3 py-1.5 text-accent-red border-accent-red/40 disabled:opacity-50"
        >
          Delete template
        </button>
      </div>

      {/* Reminder summary */}
      {(reminders.overdue > 0 || reminders.due_today > 0 || reminders.next_7_days > 0) && (
        <div className="card p-3 border border-accent-amber/25 bg-accent-amber/10 flex flex-wrap items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-accent-amber" />
          <p className="text-sm text-surface-900">
            {reminders.overdue > 0 && <span className="font-semibold">{reminders.overdue} overdue</span>}
            {reminders.overdue > 0 && reminders.due_today > 0 && <span> · </span>}
            {reminders.due_today > 0 && <span className="font-semibold">{reminders.due_today} due today</span>}
            {(reminders.overdue > 0 || reminders.due_today > 0) && reminders.next_7_days > 0 && <span> · </span>}
            {reminders.next_7_days > 0 && <span>{reminders.next_7_days} due in next 7 days</span>}
          </p>
        </div>
      )}

      {/* Stats cards */}
      <div className="flex gap-3 overflow-x-auto pb-1">
        {/* Total */}
        <div className="card p-4 min-w-[140px] flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-brand-600/15 flex items-center justify-center">
              <BarChart3 className="w-4 h-4 text-brand-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{pagination.total}</p>
              <p className="text-xs text-surface-700">Total</p>
            </div>
          </div>
        </div>

        {/* Dynamic per-status */}
        {statuses.map(s => (
          <div key={s.id} className="card p-4 min-w-[140px] flex-shrink-0">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ backgroundColor: s.color + '20' }}>
                {s.is_completed
                  ? <CheckCircle2 className="w-4 h-4" style={{ color: s.color }} />
                  : <CircleDot className="w-4 h-4" style={{ color: s.color }} />
                }
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{statusCounts[s.id] || 0}</p>
                <p className="text-xs text-surface-700 truncate max-w-[80px]">{s.name}</p>
              </div>
            </div>
          </div>
        ))}

        {/* Avg Progress */}
        <div className="card p-4 min-w-[140px] flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-accent-purple/15 flex items-center justify-center">
              <BarChart3 className="w-4 h-4 text-accent-purple" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{avgProgress}%</p>
              <p className="text-xs text-surface-700">Avg Progress</p>
            </div>
          </div>
        </div>
      </div>

      {/* Search & Filters */}
      <div className="card p-4 space-y-3 relative z-10">
        <div className="flex flex-wrap gap-2">
          {[
            { id: 'all', label: 'All' },
            { id: 'inbox', label: 'Inbox' },
            { id: 'today', label: 'Today' },
            { id: 'upcoming', label: 'Upcoming' },
          ].map(view => (
            <button
              key={view.id}
              type="button"
              className={cn(
                'px-3 py-1.5 rounded-lg text-xs border transition-colors',
                focusView === view.id
                  ? 'bg-brand-600/15 text-brand-300 border-brand-500/40'
                  : 'bg-surface-200/20 text-surface-700 border-surface-300/30 hover:bg-surface-200/35',
              )}
              onClick={() => setFocusView(view.id as 'all' | 'inbox' | 'today' | 'upcoming')}
            >
              {view.label}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleSaveCurrentView}
            className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5"
          >
            <Bookmark className="w-3.5 h-3.5" />
            Save view
          </button>
          {savedViews.map(v => (
            <div key={v.id} className="inline-flex items-center rounded-lg border border-surface-300/30 bg-surface-200/20">
              <button
                type="button"
                onClick={() => applySavedView(v.filters_json)}
                className="px-2.5 py-1.5 text-xs text-surface-800 hover:text-white"
                title="Apply saved view"
              >
                {v.name}
              </button>
              <button
                type="button"
                onClick={() => deleteSavedView(v.id)}
                className="px-2 py-1.5 text-surface-700 hover:text-accent-red"
                title="Delete saved view"
              >
                <Trash2 className="w-3 h-3" />
              </button>
            </div>
          ))}
          {tasks.length > 0 && (
            <>
              <button
                type="button"
                onClick={handleBulkCompleteVisible}
                className="btn-secondary text-xs px-3 py-1.5"
              >
                Complete visible
              </button>
              <button
                type="button"
                onClick={handleBulkDeleteCompletedVisible}
                className="btn-secondary text-xs px-3 py-1.5 text-accent-red border-accent-red/40"
              >
                Delete completed
              </button>
            </>
          )}
        </div>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-surface-700 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              className="input-base pl-10"
              placeholder="Search tasks..."
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
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2 border-t border-surface-300/20 animate-slide-down">
            <select
              className="input-base text-sm"
              value={filterCategory}
              onChange={e => setFilterCategory(e.target.value)}
            >
              <option value="">All Categories</option>
              {categories.map(c => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
            <select
              className="input-base text-sm"
              value={filterStatus}
              onChange={e => setFilterStatus(e.target.value)}
            >
              <option value="">All Statuses</option>
              {statuses.map(s => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </select>
            <input
              type="date"
              className="input-base text-sm"
              value={dateFrom}
              onChange={e => setDateFrom(e.target.value)}
              placeholder="From date"
            />
            <input
              type="date"
              className="input-base text-sm"
              value={dateTo}
              onChange={e => setDateTo(e.target.value)}
              placeholder="To date"
            />
            <div className="relative sm:col-span-2" ref={tagDropdownRef}>
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

      {/* Task list */}
      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      ) : tasks.length === 0 ? (
        <div className="text-center py-20">
          <div className="w-16 h-16 rounded-2xl bg-surface-200/40 flex items-center justify-center mx-auto mb-4">
            <CheckCircle2 className="w-8 h-8 text-surface-700" />
          </div>
          <h3 className="text-lg font-medium text-surface-800">No tasks found</h3>
          <p className="text-surface-700 text-sm mt-1">Create your first task to get started</p>
          <div className="mt-4 flex items-center justify-center gap-2">
            <button onClick={() => setShowForm(true)} className="btn-primary text-sm px-4 py-2">New Task</button>
            <button onClick={createStarterSetup} className="btn-secondary text-sm px-4 py-2">Starter Setup</button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {Object.entries(groupedByYear).map(([year, months]) => {
            const yearTaskCount = Object.values(months).reduce((s, days) =>
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
                  <Calendar className="w-4 h-4 text-brand-400" />
                  {year}
                  <span className="text-surface-600 font-normal text-xs ml-auto">
                    {yearTaskCount} task{yearTaskCount !== 1 ? 's' : ''}
                  </span>
                </button>

                {!isYearCollapsed && (
                  <div className="space-y-3 animate-fade-in">
                    {Object.entries(months).map(([month, days]) => {
                      const monthTaskCount = Object.values(days).reduce((s, d) => s + d.length, 0)
                      const isMonthCollapsed = collapsedMonths.has(month)
                      const monthLabel = month.replace(/\s*\d{4}$/, '') // Show just "March" etc since year is parent
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
                            <Calendar className="w-3.5 h-3.5 text-brand-400" />
                            {monthLabel}
                            <span className="text-surface-600 font-normal text-xs ml-auto">
                              {monthTaskCount} task{monthTaskCount !== 1 ? 's' : ''}
                            </span>
                          </button>

                          {/* Days within month */}
                          {!isMonthCollapsed && (
                            <div className="border-t border-surface-300/20 animate-fade-in">
                              {Object.entries(days).map(([day, dayTasks]) => {
                                const isDayCollapsed = collapsedDays.has(day)
                                const dayPart = new Date(dayTasks[0].created_at).toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric' })
                                const isToday = day === todayStr
                                return (
                                  <div key={day}>
                                    <button
                                      onClick={() => toggleDay(day)}
                                      className={cn(
                                        'w-full flex items-center gap-2 px-4 py-2 text-xs font-medium transition-colors',
                                        isToday
                                          ? 'text-brand-400 bg-brand-600/5 hover:bg-brand-600/10'
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
                                        <span className="px-1.5 py-0.5 rounded-md bg-brand-600/15 text-brand-400 text-[10px] font-semibold">
                                          Today
                                        </span>
                                      )}
                                      <span className="font-normal ml-auto opacity-60">
                                        {dayTasks.length}
                                      </span>
                                    </button>

                                    {!isDayCollapsed && (
                                      <div className="space-y-2 px-4 pb-3 pt-1 animate-fade-in">
                                        {dayTasks.map(task => (
                                          <TaskCard
                                            key={task.id}
                                            task={task}
                                            onUpdate={handleUpdateTask}
                                            onDelete={handleDeleteTask}
                                            onEdit={t => setEditingTask(t)}
                                          />
                                        ))}
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
        onPageChange={p => fetchTasks(p)}
      />

      {/* Modals */}
      {showForm && (
        <TaskForm
          categories={categories}
          defaultStartDate={defaultStartDate}
          defaultDueDate={defaultDueDate}
          onSubmit={handleCreateTask}
          onCancel={() => { setShowForm(false); setDefaultStartDate(''); setDefaultDueDate('') }}
          onFilesUploaded={() => fetchTasks(pagination.page)}
        />
      )}
      {editingTask && (
        <TaskForm
          task={editingTask}
          categories={categories}
          onSubmit={handleEditSubmit}
          onCancel={() => setEditingTask(null)}
          onDeleteAttachment={handleDeleteAttachment}
          onFilesUploaded={() => fetchTasks(pagination.page)}
        />
      )}
      <ConfirmModal
        open={!!confirmDelete}
        title="Delete Task"
        message="This task and all its attachments will be permanently deleted."
        onConfirm={executeDeleteTask}
        onCancel={() => setConfirmDelete(null)}
      />

      {showQuickAdd && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card w-full max-w-md p-5 space-y-3 animate-scale-in">
            <div className="flex items-center justify-between">
              <h3 className="text-white font-semibold">Quick Add Task</h3>
              <button onClick={() => setShowQuickAdd(false)} className="p-1 rounded hover:bg-surface-300/30 text-surface-700">
                <X className="w-4 h-4" />
              </button>
            </div>
            <input
              type="text"
              className="input-base"
              placeholder="Task title... (supports: today, tomorrow, next week)"
              value={quickTitle}
              onChange={e => setQuickTitle(e.target.value)}
              autoFocus
            />
            <input
              type="date"
              className="input-base"
              value={quickDueDate}
              onChange={e => setQuickDueDate(e.target.value)}
            />
            <div className="flex justify-end gap-2">
              <button onClick={() => setShowQuickAdd(false)} className="btn-secondary">Cancel</button>
              <button onClick={handleQuickAdd} className="btn-primary">Create</button>
            </div>
          </div>
        </div>
      )}

      {showTemplateModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card w-full max-w-md p-5 space-y-3 animate-scale-in">
            <div className="flex items-center justify-between">
              <h3 className="text-white font-semibold">New Template</h3>
              <button onClick={() => setShowTemplateModal(false)} className="p-1 rounded hover:bg-surface-300/30 text-surface-700">
                <X className="w-4 h-4" />
              </button>
            </div>
            <input
              type="text"
              className="input-base"
              placeholder="Template name..."
              value={templateName}
              onChange={e => setTemplateName(e.target.value)}
            />
            <input
              type="text"
              className="input-base"
              placeholder="Default task title..."
              value={templateTitle}
              onChange={e => setTemplateTitle(e.target.value)}
            />
            <select
              className="input-base"
              value={templateRecurrence}
              onChange={e => setTemplateRecurrence(e.target.value as 'none' | 'daily' | 'weekly' | 'monthly')}
            >
              <option value="none">Does not repeat</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
            <div className="flex justify-end gap-2">
              <button onClick={() => setShowTemplateModal(false)} className="btn-secondary">Cancel</button>
              <button onClick={createTemplate} className="btn-primary">Save template</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

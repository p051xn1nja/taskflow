'use client'

import { useState, useEffect, useCallback, Suspense } from 'react'
import { useSession } from 'next-auth/react'
import { useSearchParams } from 'next/navigation'
import {
  Plus, Search, Filter, ChevronDown, ChevronRight, X,
  Calendar, Tag, BarChart3, CheckCircle2, Clock, Loader2, CircleDot,
} from 'lucide-react'
import { TaskCard } from '@/components/TaskCard'
import { TaskForm } from '@/components/TaskForm'
import { Pagination } from '@/components/Pagination'
import { cn, groupBy } from '@/lib/utils'
import type { Task, Category, Status } from '@/types'

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

  // Form state
  const [showForm, setShowForm] = useState(false)
  const [editingTask, setEditingTask] = useState<Task | null>(null)
  const [defaultStartDate, setDefaultStartDate] = useState('')
  const [defaultDueDate, setDefaultDueDate] = useState('')

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

  // Collapsed groups (months and days)
  const [collapsedMonths, setCollapsedMonths] = useState<Set<string>>(new Set())
  const [collapsedDays, setCollapsedDays] = useState<Set<string>>(new Set())

  const fetchTasks = useCallback(async (page = 1) => {
    setLoading(true)
    const params = new URLSearchParams()
    if (search) params.set('search', search)
    if (filterCategory) params.set('category_id', filterCategory)
    if (filterStatus) params.set('status_id', filterStatus)
    if (filterTag) params.set('tag', filterTag)
    if (dateFrom) params.set('date_from', dateFrom)
    if (dateTo) params.set('date_to', dateTo)
    params.set('page', String(page))
    params.set('per_page', String(pagination.per_page))

    const res = await fetch(`/api/tasks?${params}`)
    const data = await res.json()
    setTasks(data.tasks)
    setPagination(data.pagination)
    setLoading(false)
  }, [search, filterCategory, filterStatus, filterTag, dateFrom, dateTo, pagination.per_page])

  const fetchCategories = async () => {
    const res = await fetch('/api/categories')
    setCategories(await res.json())
  }

  const fetchStatuses = async () => {
    const res = await fetch('/api/statuses')
    setStatuses(await res.json())
  }

  useEffect(() => {
    fetchCategories()
    fetchStatuses()
  }, [])

  useEffect(() => {
    const timer = setTimeout(() => fetchTasks(), 300)
    return () => clearTimeout(timer)
  }, [fetchTasks])

  const handleCreateTask = async (data: { title: string; description: string; category_id: string | null; tags: string[]; start_date: string | null; due_date: string | null; location: string }) => {
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

  const handleEditSubmit = async (data: { title: string; description: string; category_id: string | null; tags: string[]; start_date: string | null; due_date: string | null; location: string; progress?: number }) => {
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
    if (!confirm('Delete this task?')) return
    await fetch(`/api/tasks/${id}`, { method: 'DELETE' })
    fetchTasks(pagination.page)
  }

  const handleDeleteAttachment = async (attachmentId: string) => {
    await fetch(`/api/uploads/${attachmentId}`, { method: 'DELETE' })
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

  // Group tasks by month, then by day
  const todayStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
  const todayMonth = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long' })

  const groupedByMonth: Record<string, Record<string, Task[]>> = {}
  for (const task of tasks) {
    const d = new Date(task.created_at)
    const monthKey = d.toLocaleDateString('en-US', { year: 'numeric', month: 'long' })
    const dayKey = d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
    if (!groupedByMonth[monthKey]) groupedByMonth[monthKey] = {}
    if (!groupedByMonth[monthKey][dayKey]) groupedByMonth[monthKey][dayKey] = []
    groupedByMonth[monthKey][dayKey].push(task)
  }

  // On initial load / data change, collapse everything except current day's month+day
  useEffect(() => {
    const allMonths = Object.keys(groupedByMonth)
    const allDays = Object.values(groupedByMonth).flatMap(days => Object.keys(days))
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

  // Get all unique tags from tasks (tags are now objects with id, name, color)
  const allTags = tasks.flatMap(t => t.tags).filter((tag, i, arr) =>
    arr.findIndex(t => t.name === tag.name) === i
  )

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Tasks</h1>
          <p className="text-surface-700 text-sm mt-0.5">
            {pagination.total} task{pagination.total !== 1 ? 's' : ''} total
          </p>
        </div>
        <button onClick={() => setShowForm(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Task
        </button>
      </div>

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
      <div className="card p-4 space-y-3">
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
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 border-t border-surface-300/20 animate-slide-down">
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
            {allTags.length > 0 && (
              <select
                className="input-base text-sm col-span-2"
                value={filterTag}
                onChange={e => setFilterTag(e.target.value)}
              >
                <option value="">All Tags</option>
                {allTags.map(t => (
                  <option key={t.name} value={t.name}>{t.name}</option>
                ))}
              </select>
            )}
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
        </div>
      ) : (
        <div className="space-y-4">
          {Object.entries(groupedByMonth).map(([month, days]) => {
            const monthTaskCount = Object.values(days).reduce((s, d) => s + d.length, 0)
            const isMonthCollapsed = collapsedMonths.has(month)
            return (
              <div key={month} className="card overflow-hidden">
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
                  {month}
                  <span className="text-surface-600 font-normal text-xs ml-auto">
                    {monthTaskCount} task{monthTaskCount !== 1 ? 's' : ''}
                  </span>
                </button>

                {/* Days within month */}
                {!isMonthCollapsed && (
                  <div className="border-t border-surface-300/20 animate-fade-in">
                    {Object.entries(days).map(([day, dayTasks]) => {
                      const isDayCollapsed = collapsedDays.has(day)
                      const dayPart = new Date(dayTasks[0].created_at).toLocaleDateString('en-US', { weekday: 'short', day: 'numeric' })
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
    </div>
  )
}

'use client'

import { useState, useEffect, useCallback } from 'react'
import { useSession } from 'next-auth/react'
import {
  Plus, Search, Filter, ChevronDown, ChevronRight, X,
  Calendar, Tag, BarChart3, CheckCircle2, Clock, Loader2,
} from 'lucide-react'
import { TaskCard } from '@/components/TaskCard'
import { TaskForm } from '@/components/TaskForm'
import { cn, groupBy } from '@/lib/utils'
import type { Task, Category } from '@/types'

export default function TasksPage() {
  const { data: session } = useSession()
  const [tasks, setTasks] = useState<Task[]>([])
  const [categories, setCategories] = useState<Category[]>([])
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

  // Collapsed groups
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set())

  const fetchTasks = useCallback(async (page = 1) => {
    setLoading(true)
    const params = new URLSearchParams()
    if (search) params.set('search', search)
    if (filterCategory) params.set('category_id', filterCategory)
    if (filterStatus) params.set('status', filterStatus)
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

  useEffect(() => {
    fetchCategories()
  }, [])

  useEffect(() => {
    const timer = setTimeout(() => fetchTasks(), 300)
    return () => clearTimeout(timer)
  }, [fetchTasks])

  const handleCreateTask = async (data: { title: string; description: string; category_id: string | null; tags: string[]; due_date: string | null }) => {
    await fetch('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    setShowForm(false)
    fetchTasks(pagination.page)
  }

  const handleUpdateTask = async (id: string, data: Partial<Task>) => {
    await fetch(`/api/tasks/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    fetchTasks(pagination.page)
  }

  const handleEditSubmit = async (data: { title: string; description: string; category_id: string | null; tags: string[]; due_date: string | null; progress?: number }) => {
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

  const toggleGroup = (key: string) => {
    setCollapsedGroups(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  // Group tasks by date
  const grouped = groupBy(tasks, task => {
    const d = new Date(task.created_at)
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
  })

  // Stats
  const completedCount = tasks.filter(t => t.status === 'completed').length
  const inProgressCount = tasks.filter(t => t.status === 'in_progress').length
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
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="card p-4">
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
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-accent-green/15 flex items-center justify-center">
              <CheckCircle2 className="w-4 h-4 text-accent-green" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{completedCount}</p>
              <p className="text-xs text-surface-700">Completed</p>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-accent-amber/15 flex items-center justify-center">
              <Clock className="w-4 h-4 text-accent-amber" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{inProgressCount}</p>
              <p className="text-xs text-surface-700">In Progress</p>
            </div>
          </div>
        </div>
        <div className="card p-4">
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
              <option value="">All Status</option>
              <option value="in_progress">In Progress</option>
              <option value="completed">Completed</option>
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
        <div className="space-y-6">
          {Object.entries(grouped).map(([date, dateTasks]) => (
            <div key={date}>
              <button
                onClick={() => toggleGroup(date)}
                className="flex items-center gap-2 mb-3 text-sm font-semibold text-surface-700 hover:text-surface-900 transition-colors"
              >
                {collapsedGroups.has(date) ? (
                  <ChevronRight className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
                <Calendar className="w-3.5 h-3.5" />
                {date}
                <span className="text-surface-700 font-normal">({dateTasks.length})</span>
              </button>
              {!collapsedGroups.has(date) && (
                <div className="space-y-2 animate-fade-in">
                  {dateTasks.map(task => (
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
          ))}
        </div>
      )}

      {/* Pagination */}
      {pagination.total_pages > 1 && (
        <div className="flex items-center justify-center gap-2 pt-4">
          <button
            onClick={() => fetchTasks(pagination.page - 1)}
            disabled={pagination.page <= 1}
            className="btn-secondary text-sm"
          >
            Previous
          </button>
          <span className="text-sm text-surface-800 px-3">
            Page {pagination.page} of {pagination.total_pages}
          </span>
          <button
            onClick={() => fetchTasks(pagination.page + 1)}
            disabled={pagination.page >= pagination.total_pages}
            className="btn-secondary text-sm"
          >
            Next
          </button>
        </div>
      )}

      {/* Modals */}
      {showForm && (
        <TaskForm
          categories={categories}
          onSubmit={handleCreateTask}
          onCancel={() => setShowForm(false)}
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

'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useSession } from 'next-auth/react'
import {
  Plus, Loader2, Calendar, Paperclip, Hash, GripVertical,
  CircleDot, CheckCircle2, Pencil, Trash2, X, Check, MoreVertical,
  ArrowUpDown, MapPin,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { TaskForm } from '@/components/TaskForm'
import type { Task, Category, Status } from '@/types'

function KanbanCard({
  task,
  onEdit,
  onDelete,
  onDragStart,
  onDragOver,
  onTouchDragStart,
  dropIndicator,
}: {
  task: Task
  onEdit: (task: Task) => void
  onDelete: (id: string) => void
  onDragStart: (e: React.DragEvent, task: Task) => void
  onDragOver: (e: React.DragEvent, taskId: string) => void
  onTouchDragStart: (task: Task) => void
  dropIndicator: 'above' | 'below' | null
}) {
  const isDone = task.task_status?.is_completed ?? task.status === 'completed'
  const isOverdue = task.due_date && new Date(task.due_date) < new Date() && !isDone
  const touchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const hasMoved = useRef(false)

  const handleTouchStart = (e: React.TouchEvent) => {
    hasMoved.current = false
    touchTimerRef.current = setTimeout(() => {
      if (!hasMoved.current) {
        onTouchDragStart(task)
        // Vibrate if available
        if (navigator.vibrate) navigator.vibrate(50)
      }
    }, 300)
  }

  const handleTouchMove = () => {
    hasMoved.current = true
    if (touchTimerRef.current) {
      clearTimeout(touchTimerRef.current)
      touchTimerRef.current = null
    }
  }

  const handleTouchEnd = () => {
    if (touchTimerRef.current) {
      clearTimeout(touchTimerRef.current)
      touchTimerRef.current = null
    }
  }

  return (
    <div className="relative">
      {dropIndicator === 'above' && (
        <div className="absolute -top-1.5 left-1 right-1 h-0.5 bg-brand-400 rounded-full z-10" />
      )}
      <div
        draggable
        onDragStart={e => onDragStart(e, task)}
        onDragOver={e => onDragOver(e, task.id)}
        onTouchStart={handleTouchStart}
        onTouchMove={handleTouchMove}
        onTouchEnd={handleTouchEnd}
        className={cn(
          'group relative rounded-xl border bg-surface-100/80 backdrop-blur-sm p-3.5',
          'cursor-grab active:cursor-grabbing',
          'hover:border-surface-500/40 hover:shadow-lg hover:shadow-black/10',
          'transition-all duration-150 touch-manipulation',
          'border-surface-300/25',
          isDone && 'opacity-60',
        )}
      >
      <div className="absolute top-3 right-2 opacity-100 lg:opacity-0 group-hover:opacity-100 transition-opacity">
        <GripVertical className="w-4 h-4 text-surface-700" />
      </div>

      {task.category && (
        <div className="mb-2">
          <span
            className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-semibold"
            style={{
              backgroundColor: task.category.color + '18',
              color: task.category.color,
              border: `1px solid ${task.category.color}25`,
            }}
          >
            {task.category.name}
          </span>
        </div>
      )}

      <h4 className={cn(
        'text-sm font-medium text-surface-950 leading-snug pr-6',
        isDone && 'line-through text-surface-700',
      )}>
        {task.title}
      </h4>

      {task.description && (
        <p className="text-xs text-surface-800 mt-1.5 line-clamp-2 leading-relaxed">
          {task.description}
        </p>
      )}

      {task.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {task.tags.map(tag => (
            <span key={tag.id} className="inline-flex items-center gap-0.5 px-1.5 py-0 rounded-md text-[10px] font-medium"
              style={{ backgroundColor: tag.color + '15', color: tag.color, border: `1px solid ${tag.color}20` }}>
              <Hash className="w-2.5 h-2.5" />{tag.name}
            </span>
          ))}
        </div>
      )}

      {task.location && (
        <div className="flex items-center gap-1 mt-2 text-[10px] text-surface-800">
          <MapPin className="w-3 h-3 text-surface-700 flex-shrink-0" />
          <span className="truncate">{task.location}</span>
        </div>
      )}

      {!isDone && task.progress > 0 && (
        <div className="mt-3 flex items-center gap-2">
          <div className="flex-1 h-1 bg-surface-300/40 rounded-full overflow-hidden">
            <div
              className={cn('h-full rounded-full transition-all',
                task.progress >= 75 ? 'bg-accent-green' : task.progress >= 40 ? 'bg-brand-500' : 'bg-accent-amber'
              )}
              style={{ width: `${task.progress}%` }}
            />
          </div>
          <span className="text-[10px] font-medium text-surface-800 tabular-nums">{task.progress}%</span>
        </div>
      )}

      <div className="flex items-center gap-2 mt-3 flex-wrap">
        {task.start_date && (
          <span className="inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded-md bg-surface-300/30 text-surface-800">
            <Calendar className="w-3 h-3" />{formatDate(task.start_date)}
          </span>
        )}
        {task.due_date && (
          <span className={cn('inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded-md',
            isOverdue ? 'bg-accent-red/12 text-accent-red' : 'bg-surface-300/30 text-surface-800'
          )}>
            <Calendar className="w-3 h-3" />{formatDate(task.due_date)}
          </span>
        )}
        {task.attachments.length > 0 && (
          <span className="inline-flex items-center gap-1 text-[10px] font-medium text-surface-800 bg-surface-300/30 px-1.5 py-0.5 rounded-md">
            <Paperclip className="w-3 h-3" />{task.attachments.length}
          </span>
        )}
        <div className="flex-1" />
        <div className="flex gap-0.5 opacity-100 lg:opacity-0 group-hover:opacity-100 transition-opacity">
          <button onClick={e => { e.stopPropagation(); onEdit(task) }}
            className="p-1.5 rounded-md hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors" title="Edit">
            <Pencil className="w-3.5 h-3.5" />
          </button>
          <button onClick={e => { e.stopPropagation(); onDelete(task.id) }}
            className="p-1.5 rounded-md hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors" title="Delete">
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
      {dropIndicator === 'below' && (
        <div className="absolute -bottom-1.5 left-1 right-1 h-0.5 bg-brand-400 rounded-full z-10" />
      )}
    </div>
    </div>
  )
}

export default function BoardPage() {
  const { data: session } = useSession()
  const [tasks, setTasks] = useState<Task[]>([])
  const [statuses, setStatuses] = useState<Status[]>([])
  const [categories, setCategories] = useState<Category[]>([])
  const [loading, setLoading] = useState(true)
  const [editingTask, setEditingTask] = useState<Task | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [dragOverColumn, setDragOverColumn] = useState<string | null>(null)
  const draggedTaskRef = useRef<Task | null>(null)

  // Intra-column drop indicator: which card and above/below
  const [dropTarget, setDropTarget] = useState<{ taskId: string; position: 'above' | 'below' } | null>(null)

  // Mobile touch drag state
  const [touchDragTask, setTouchDragTask] = useState<Task | null>(null)

  // Sort state
  const [sortBy, setSortBy] = useState<string>('created_desc')

  // Column menu state
  const [columnMenu, setColumnMenu] = useState<string | null>(null)
  const [renamingColumn, setRenamingColumn] = useState<string | null>(null)
  const [renameValue, setRenameValue] = useState('')
  const columnMenuRef = useRef<HTMLDivElement>(null)

  // Close column menu on outside click / ESC
  useEffect(() => {
    if (!columnMenu) return
    const handleClick = (e: MouseEvent) => {
      if (columnMenuRef.current && !columnMenuRef.current.contains(e.target as Node)) setColumnMenu(null)
    }
    const handleKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setColumnMenu(null) }
    document.addEventListener('mousedown', handleClick)
    window.addEventListener('keydown', handleKey)
    return () => { document.removeEventListener('mousedown', handleClick); window.removeEventListener('keydown', handleKey) }
  }, [columnMenu])

  const handleRenameColumn = async (statusId: string) => {
    const trimmed = renameValue.trim()
    if (!trimmed) return
    await fetch(`/api/statuses/${statusId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: trimmed }),
    })
    setRenamingColumn(null)
    setRenameValue('')
    fetchAll()
  }

  const handleDeleteColumn = async (statusId: string) => {
    const s = statuses.find(st => st.id === statusId)
    if (s?.is_default) { alert('Cannot delete the default status.'); return }
    if (!confirm('Delete this status? Tasks will be moved to the default status.')) return
    await fetch(`/api/statuses/${statusId}`, { method: 'DELETE' })
    setColumnMenu(null)
    fetchAll()
  }

  const fetchAll = useCallback(async () => {
    const [tasksRes, statusesRes, categoriesRes] = await Promise.all([
      fetch('/api/tasks?per_page=200'),
      fetch('/api/statuses'),
      fetch('/api/categories'),
    ])
    const tasksData = await tasksRes.json()
    setTasks(tasksData.tasks)
    setStatuses(await statusesRes.json())
    setCategories(await categoriesRes.json())
    setLoading(false)
  }, [])

  useEffect(() => { fetchAll() }, [fetchAll])

  const handleUpdateTask = async (id: string, data: Partial<Task>) => {
    await fetch(`/api/tasks/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    fetchAll()
  }

  const handleDeleteTask = async (id: string) => {
    if (!confirm('Delete this task?')) return
    await fetch(`/api/tasks/${id}`, { method: 'DELETE' })
    fetchAll()
  }

  const handleCreateTask = async (data: { title: string; description: string; category_id: string | null; tags: string[]; start_date: string | null; due_date: string | null; location: string }) => {
    const res = await fetch('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    const { id } = await res.json()
    setShowForm(false)
    fetchAll()
    return id as string
  }

  const handleEditSubmit = async (data: { title: string; description: string; category_id: string | null; tags: string[]; start_date: string | null; due_date: string | null; location: string; progress?: number }) => {
    if (!editingTask) return
    await fetch(`/api/tasks/${editingTask.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    setEditingTask(null)
    fetchAll()
  }

  const handleDeleteAttachment = async (attachmentId: string) => {
    await fetch(`/api/uploads/${attachmentId}`, { method: 'DELETE' })
  }

  // Desktop drag and drop
  const handleDragStart = (e: React.DragEvent, task: Task) => {
    draggedTaskRef.current = task
    e.dataTransfer.effectAllowed = 'move'
    e.dataTransfer.setData('text/plain', task.id)
    const target = e.currentTarget as HTMLElement
    requestAnimationFrame(() => { target.style.opacity = '0.4' })
  }

  const handleColumnDragOver = (e: React.DragEvent, columnId: string) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
    setDragOverColumn(columnId)
  }

  const handleCardDragOver = (e: React.DragEvent, taskId: string) => {
    e.preventDefault()
    e.stopPropagation()
    if (draggedTaskRef.current?.id === taskId) {
      setDropTarget(null)
      return
    }
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    const midY = rect.top + rect.height / 2
    const position = e.clientY < midY ? 'above' : 'below'
    setDropTarget({ taskId, position })
  }

  const handleDragEnd = () => {
    setDragOverColumn(null)
    setDropTarget(null)
    draggedTaskRef.current = null
    document.querySelectorAll('[draggable="true"]').forEach(el => {
      (el as HTMLElement).style.opacity = '1'
    })
  }

  const saveColumnOrder = async (columnId: string, orderedTasks: Task[]) => {
    const items = orderedTasks.map((t, i) => ({ id: t.id, board_position: i }))
    // Optimistic: update local state
    setTasks(prev => {
      const next = [...prev]
      for (const item of items) {
        const idx = next.findIndex(t => t.id === item.id)
        if (idx >= 0) next[idx] = { ...next[idx], board_position: item.board_position }
      }
      return next
    })
    await fetch('/api/tasks/reorder', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items }),
    })
  }

  const moveTaskToStatus = async (task: Task, targetStatusId: string, insertIndex?: number) => {
    const targetStatus = statuses.find(s => s.id === targetStatusId)
    const sameColumn = task.status_id === targetStatusId

    if (sameColumn && insertIndex == null) return

    // Handle intra-column reorder
    if (sameColumn && insertIndex != null) {
      const colTasks = [...(columnTasks[targetStatusId] || [])]
      const fromIdx = colTasks.findIndex(t => t.id === task.id)
      if (fromIdx === -1 || fromIdx === insertIndex) return
      colTasks.splice(fromIdx, 1)
      const adjustedIdx = insertIndex > fromIdx ? insertIndex - 1 : insertIndex
      colTasks.splice(adjustedIdx, 0, task)
      if (sortBy !== 'manual') setSortBy('manual')
      await saveColumnOrder(targetStatusId, colTasks)
      return
    }

    // Cross-column move
    const update: Record<string, string | number> = { status_id: targetStatusId }
    if (targetStatus?.is_completed) {
      update.progress = 100
      update.status = 'completed'
    } else if (targetStatus?.is_default) {
      update.progress = 0
      update.status = 'in_progress'
    } else {
      update.status = 'in_progress'
    }

    // If inserting at a position, set board_position
    if (insertIndex != null) {
      update.board_position = insertIndex
    }

    // Optimistic
    setTasks(prev => prev.map(t =>
      t.id === task.id ? {
        ...t,
        status_id: targetStatusId,
        task_status: targetStatus ? { ...targetStatus } : null,
        progress: update.progress as number ?? t.progress,
        board_position: insertIndex ?? t.board_position,
      } : t
    ))

    await handleUpdateTask(task.id, update)

    // After cross-column move with position, reorder the target column
    if (insertIndex != null) {
      if (sortBy !== 'manual') setSortBy('manual')
      // Re-fetch to get correct state then reorder
      const res = await fetch('/api/tasks?per_page=200')
      const data = await res.json()
      const allTasks = data.tasks as Task[]
      const targetTasks = allTasks
        .filter((t: Task) => t.status_id === targetStatusId)
        .sort((a: Task, b: Task) => a.board_position - b.board_position)
      // Move the dropped task to the insert position
      const movedIdx = targetTasks.findIndex((t: Task) => t.id === task.id)
      if (movedIdx >= 0) {
        targetTasks.splice(movedIdx, 1)
        targetTasks.splice(Math.min(insertIndex, targetTasks.length), 0, allTasks.find((t: Task) => t.id === task.id)!)
        await saveColumnOrder(targetStatusId, targetTasks)
      }
      fetchAll()
    }
  }

  const handleDrop = async (e: React.DragEvent, targetStatusId: string) => {
    e.preventDefault()
    const task = draggedTaskRef.current
    const drop = dropTarget
    setDragOverColumn(null)
    setDropTarget(null)
    if (!task) return
    draggedTaskRef.current = null

    if (drop) {
      // Dropped on a specific card — compute insert index
      const colTasks = columnTasks[targetStatusId] || []
      const targetIdx = colTasks.findIndex(t => t.id === drop.taskId)
      if (targetIdx >= 0) {
        const insertIdx = drop.position === 'below' ? targetIdx + 1 : targetIdx
        await moveTaskToStatus(task, targetStatusId, insertIdx)
        return
      }
    }

    // Dropped on column background (no specific card) — move to end or just change column
    if (task.status_id !== targetStatusId) {
      await moveTaskToStatus(task, targetStatusId)
    }
  }

  // Mobile touch drag - tap column to move
  const handleTouchDropToColumn = async (targetStatusId: string) => {
    if (!touchDragTask) return
    await moveTaskToStatus(touchDragTask, targetStatusId)
    setTouchDragTask(null)
  }

  useEffect(() => {
    const handler = () => handleDragEnd()
    document.addEventListener('dragend', handler)
    return () => document.removeEventListener('dragend', handler)
  }, [])

  // Sort comparator
  const sortTasks = useCallback((a: Task, b: Task): number => {
    switch (sortBy) {
      case 'manual':
        return a.board_position - b.board_position
      case 'created_asc':
        return a.created_at.localeCompare(b.created_at)
      case 'created_desc':
        return b.created_at.localeCompare(a.created_at)
      case 'due_asc':
        if (!a.due_date && !b.due_date) return 0
        if (!a.due_date) return 1
        if (!b.due_date) return -1
        return a.due_date.localeCompare(b.due_date)
      case 'due_desc':
        if (!a.due_date && !b.due_date) return 0
        if (!a.due_date) return 1
        if (!b.due_date) return -1
        return b.due_date.localeCompare(a.due_date)
      case 'progress_asc':
        return a.progress - b.progress
      case 'progress_desc':
        return b.progress - a.progress
      case 'title_asc':
        return a.title.localeCompare(b.title)
      case 'title_desc':
        return b.title.localeCompare(a.title)
      default:
        return 0
    }
  }, [sortBy])

  // Group tasks by status
  const columnTasks: Record<string, Task[]> = {}
  statuses.forEach(s => { columnTasks[s.id] = [] })
  tasks.forEach(task => {
    const sid = task.status_id || ''
    if (columnTasks[sid]) columnTasks[sid].push(task)
    else if (statuses.length > 0) {
      const defaultS = statuses.find(s => s.is_default) || statuses[0]
      if (defaultS) columnTasks[defaultS.id]?.push(task)
    }
  })

  // Sort cards within each column
  for (const id of Object.keys(columnTasks)) {
    columnTasks[id].sort(sortTasks)
  }

  const totalTasks = tasks.length
  const doneCount = tasks.filter(t => t.task_status?.is_completed).length
  const completionRate = totalTasks > 0 ? Math.round((doneCount / totalTasks) * 100) : 0

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Board</h1>
          <p className="text-surface-800 text-sm mt-0.5">
            {totalTasks} task{totalTasks !== 1 ? 's' : ''}
            {totalTasks > 0 && <span className="text-surface-700"> &middot; {completionRate}% complete</span>}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="relative">
            <ArrowUpDown className="w-3.5 h-3.5 text-surface-700 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <select
              className="input-base text-xs pl-8 pr-3 py-1.5 min-w-[160px]"
              value={sortBy}
              onChange={e => setSortBy(e.target.value)}
            >
              <option value="manual">Manual (drag to reorder)</option>
              <option value="created_desc">Newest first</option>
              <option value="created_asc">Oldest first</option>
              <option value="due_asc">Due date (earliest)</option>
              <option value="due_desc">Due date (latest)</option>
              <option value="progress_desc">Progress (high → low)</option>
              <option value="progress_asc">Progress (low → high)</option>
              <option value="title_asc">Title (A → Z)</option>
              <option value="title_desc">Title (Z → A)</option>
            </select>
          </div>
          <button onClick={() => setShowForm(true)} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" /> New Task
          </button>
        </div>
      </div>

      {/* Mobile touch drag banner */}
      {touchDragTask && (
        <div className="lg:hidden card p-3 border-brand-500/40 bg-brand-600/10 animate-slide-down">
          <div className="flex items-center justify-between mb-2">
            <p className="text-sm font-medium text-brand-400">
              Moving: <span className="text-white">{touchDragTask.title}</span>
            </p>
            <button
              onClick={() => setTouchDragTask(null)}
              className="p-1 rounded-lg hover:bg-surface-300/30 text-surface-700"
            >
              <span className="text-xs text-surface-700">Cancel</span>
            </button>
          </div>
          <div className="flex gap-2 overflow-x-auto pb-1">
            {statuses.map(s => (
              <button
                key={s.id}
                onClick={() => handleTouchDropToColumn(s.id)}
                disabled={s.id === touchDragTask.status_id}
                className={cn(
                  'flex-shrink-0 px-4 py-2.5 rounded-xl text-xs font-semibold transition-all border',
                  s.id === touchDragTask.status_id
                    ? 'opacity-40 cursor-not-allowed border-surface-300/20'
                    : 'active:scale-95 border-transparent',
                )}
                style={{
                  backgroundColor: s.id === touchDragTask.status_id ? undefined : s.color + '20',
                  color: s.color,
                  borderColor: s.id !== touchDragTask.status_id ? s.color + '40' : undefined,
                }}
              >
                {s.name}
              </button>
            ))}
          </div>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-32">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      ) : (
        <div className="flex gap-4 overflow-x-auto pb-4" style={{ minHeight: 'calc(100vh - 12rem)' }}>
          {statuses.map(col => {
            const colTasks = columnTasks[col.id] || []
            const isDragOver = dragOverColumn === col.id
            return (
              <div
                key={col.id}
                className={cn(
                  'flex flex-col rounded-2xl border min-w-[280px] w-[280px] flex-shrink-0 transition-all duration-200 group/col',
                  isDragOver && 'ring-2 ring-brand-500/40 border-brand-500/30 bg-brand-600/10',
                )}
                style={{
                  backgroundColor: isDragOver ? undefined : col.color + '08',
                  borderColor: isDragOver ? undefined : col.color + '20',
                }}
                onDragOver={e => handleColumnDragOver(e, col.id)}
                onDragLeave={e => {
                  // Only clear if leaving the column entirely (not entering a child)
                  if (!e.currentTarget.contains(e.relatedTarget as Node)) {
                    setDragOverColumn(null)
                    setDropTarget(null)
                  }
                }}
                onDrop={e => handleDrop(e, col.id)}
              >
                <div className="flex items-center gap-2.5 px-4 py-3.5 border-b" style={{ borderColor: col.color + '20' }}>
                  <CircleDot className="w-4 h-4 flex-shrink-0" style={{ color: col.color }} />
                  {renamingColumn === col.id ? (
                    <form
                      className="flex items-center gap-1.5 flex-1 min-w-0"
                      onSubmit={e => { e.preventDefault(); handleRenameColumn(col.id) }}
                    >
                      <input
                        type="text"
                        value={renameValue}
                        onChange={e => setRenameValue(e.target.value)}
                        className="input-base text-sm py-1 px-2 flex-1 min-w-0"
                        autoFocus
                        maxLength={40}
                        onKeyDown={e => { if (e.key === 'Escape') { setRenamingColumn(null); setRenameValue('') } }}
                      />
                      <button type="submit" className="p-1 rounded-md hover:bg-accent-green/15 text-accent-green transition-colors">
                        <Check className="w-3.5 h-3.5" />
                      </button>
                      <button type="button" onClick={() => { setRenamingColumn(null); setRenameValue('') }} className="p-1 rounded-md hover:bg-surface-300/40 text-surface-700 transition-colors">
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </form>
                  ) : (
                    <>
                      <h3 className="text-sm font-semibold flex-1 min-w-0 truncate" style={{ color: col.color }}>{col.name}</h3>
                      <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0" style={{
                        backgroundColor: col.color + '20', color: col.color
                      }}>
                        {colTasks.length}
                      </span>
                      <div className="relative flex-shrink-0">
                        <button
                          onClick={e => { e.stopPropagation(); setColumnMenu(columnMenu === col.id ? null : col.id) }}
                          className="p-1 rounded-md hover:bg-surface-300/40 text-surface-700 hover:text-surface-900 transition-colors opacity-0 group-hover/col:opacity-100"
                        >
                          <MoreVertical className="w-3.5 h-3.5" />
                        </button>
                        {columnMenu === col.id && (
                          <div ref={columnMenuRef} className="absolute right-0 top-full mt-1 bg-surface-100 border border-surface-300/40 rounded-xl shadow-xl z-50 overflow-hidden min-w-[140px]">
                            <button
                              onClick={() => {
                                setRenameValue(col.name)
                                setRenamingColumn(col.id)
                                setColumnMenu(null)
                              }}
                              className="flex items-center gap-2 w-full px-3 py-2.5 text-sm hover:bg-surface-300/30 transition-colors text-surface-900"
                            >
                              <Pencil className="w-3.5 h-3.5 text-brand-400" /> Rename
                            </button>
                            {!col.is_default && (
                              <button
                                onClick={() => handleDeleteColumn(col.id)}
                                className="flex items-center gap-2 w-full px-3 py-2.5 text-sm hover:bg-accent-red/10 transition-colors text-accent-red"
                              >
                                <Trash2 className="w-3.5 h-3.5" /> Delete
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </div>
                <div className="flex-1 p-2.5 space-y-2 overflow-y-auto">
                  {colTasks.map(task => (
                    <KanbanCard
                      key={task.id}
                      task={task}
                      onEdit={setEditingTask}
                      onDelete={handleDeleteTask}
                      onDragStart={handleDragStart}
                      onDragOver={handleCardDragOver}
                      onTouchDragStart={setTouchDragTask}
                      dropIndicator={dropTarget?.taskId === task.id ? dropTarget.position : null}
                    />
                  ))}
                  {colTasks.length === 0 && (
                    <div className="flex flex-col items-center justify-center py-12 text-surface-700">
                      <CircleDot className="w-4 h-4 mb-2" style={{ color: col.color }} />
                      <p className="text-xs">No tasks</p>
                    </div>
                  )}
                  {isDragOver && (
                    <div className="border-2 border-dashed border-brand-500/30 rounded-xl h-16 flex items-center justify-center">
                      <p className="text-xs text-brand-400 font-medium">Drop here</p>
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {showForm && (
        <TaskForm categories={categories} onSubmit={handleCreateTask} onCancel={() => setShowForm(false)} onFilesUploaded={() => fetchAll()} />
      )}
      {editingTask && (
        <TaskForm task={editingTask} categories={categories} onSubmit={handleEditSubmit}
          onCancel={() => setEditingTask(null)} onDeleteAttachment={handleDeleteAttachment}
          onFilesUploaded={() => fetchAll()} />
      )}
    </div>
  )
}

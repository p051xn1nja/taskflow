'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useSession } from 'next-auth/react'
import {
  Plus, Loader2, Calendar, Paperclip, Hash, GripVertical,
  CircleDot, CheckCircle2, Pencil, Trash2,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { TaskForm } from '@/components/TaskForm'
import type { Task, Category, Status } from '@/types'

function KanbanCard({
  task,
  onEdit,
  onDelete,
  onDragStart,
  onTouchDragStart,
}: {
  task: Task
  onEdit: (task: Task) => void
  onDelete: (id: string) => void
  onDragStart: (e: React.DragEvent, task: Task) => void
  onTouchDragStart: (task: Task) => void
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
    <div
      draggable
      onDragStart={e => onDragStart(e, task)}
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

  // Mobile touch drag state
  const [touchDragTask, setTouchDragTask] = useState<Task | null>(null)

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

  const handleCreateTask = async (data: { title: string; description: string; category_id: string | null; tags: string[]; start_date: string | null; due_date: string | null }) => {
    await fetch('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    setShowForm(false)
    fetchAll()
  }

  const handleEditSubmit = async (data: { title: string; description: string; category_id: string | null; tags: string[]; start_date: string | null; due_date: string | null; progress?: number }) => {
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

  const handleDragOver = (e: React.DragEvent, columnId: string) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
    setDragOverColumn(columnId)
  }

  const handleDragEnd = () => {
    setDragOverColumn(null)
    draggedTaskRef.current = null
    document.querySelectorAll('[draggable="true"]').forEach(el => {
      (el as HTMLElement).style.opacity = '1'
    })
  }

  const moveTaskToStatus = async (task: Task, targetStatusId: string) => {
    if (task.status_id === targetStatusId) return

    const targetStatus = statuses.find(s => s.id === targetStatusId)
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

    // Optimistic
    setTasks(prev => prev.map(t =>
      t.id === task.id ? {
        ...t,
        status_id: targetStatusId,
        task_status: targetStatus ? { ...targetStatus } : null,
        progress: update.progress as number ?? t.progress,
      } : t
    ))

    await handleUpdateTask(task.id, update)
  }

  const handleDrop = async (e: React.DragEvent, targetStatusId: string) => {
    e.preventDefault()
    setDragOverColumn(null)
    const task = draggedTaskRef.current
    if (!task) return
    draggedTaskRef.current = null
    await moveTaskToStatus(task, targetStatusId)
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
        <button onClick={() => setShowForm(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Task
        </button>
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
                  'flex flex-col rounded-2xl border min-w-[280px] w-[280px] flex-shrink-0 transition-all duration-200',
                  isDragOver && 'ring-2 ring-brand-500/40 border-brand-500/30 bg-brand-600/10',
                )}
                style={{
                  backgroundColor: col.color + '08',
                  borderColor: col.color + '20',
                }}
                onDragOver={e => handleDragOver(e, col.id)}
                onDrop={e => handleDrop(e, col.id)}
              >
                <div className="flex items-center gap-2.5 px-4 py-3.5 border-b" style={{ borderColor: col.color + '20' }}>
                  <CircleDot className="w-4 h-4" style={{ color: col.color }} />
                  <h3 className="text-sm font-semibold" style={{ color: col.color }}>{col.name}</h3>
                  <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full" style={{
                    backgroundColor: col.color + '20', color: col.color
                  }}>
                    {colTasks.length}
                  </span>
                </div>
                <div className="flex-1 p-2.5 space-y-2 overflow-y-auto">
                  {colTasks.map(task => (
                    <KanbanCard
                      key={task.id}
                      task={task}
                      onEdit={setEditingTask}
                      onDelete={handleDeleteTask}
                      onDragStart={handleDragStart}
                      onTouchDragStart={setTouchDragTask}
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
        <TaskForm categories={categories} onSubmit={handleCreateTask} onCancel={() => setShowForm(false)} />
      )}
      {editingTask && (
        <TaskForm task={editingTask} categories={categories} onSubmit={handleEditSubmit}
          onCancel={() => setEditingTask(null)} onDeleteAttachment={handleDeleteAttachment}
          onFilesUploaded={() => fetchAll()} />
      )}
    </div>
  )
}

'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useSession } from 'next-auth/react'
import {
  Plus, Loader2, Calendar, Paperclip, Hash, GripVertical,
  Circle, ArrowRight, CheckCircle2, Pencil, Trash2,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { TaskForm } from '@/components/TaskForm'
import type { Task, Category } from '@/types'

type KanbanColumn = 'todo' | 'in_progress' | 'done'

interface ColumnConfig {
  id: KanbanColumn
  title: string
  icon: React.ReactNode
  color: string
  bgColor: string
  borderColor: string
  countBg: string
}

const COLUMNS: ColumnConfig[] = [
  {
    id: 'todo',
    title: 'To Do',
    icon: <Circle className="w-4 h-4" />,
    color: 'text-surface-800',
    bgColor: 'bg-surface-300/15',
    borderColor: 'border-surface-400/30',
    countBg: 'bg-surface-400/30 text-surface-900',
  },
  {
    id: 'in_progress',
    title: 'In Progress',
    icon: <ArrowRight className="w-4 h-4" />,
    color: 'text-brand-400',
    bgColor: 'bg-brand-600/8',
    borderColor: 'border-brand-500/20',
    countBg: 'bg-brand-600/20 text-brand-400',
  },
  {
    id: 'done',
    title: 'Done',
    icon: <CheckCircle2 className="w-4 h-4" />,
    color: 'text-accent-green',
    bgColor: 'bg-accent-green/8',
    borderColor: 'border-accent-green/20',
    countBg: 'bg-accent-green/20 text-accent-green',
  },
]

function getTaskColumn(task: Task): KanbanColumn {
  if (task.status === 'completed') return 'done'
  if (task.progress > 0) return 'in_progress'
  return 'todo'
}

function getColumnUpdate(column: KanbanColumn): Partial<Task> {
  switch (column) {
    case 'todo':
      return { status: 'in_progress', progress: 0 }
    case 'in_progress':
      return { status: 'in_progress', progress: 50 }
    case 'done':
      return { status: 'completed', progress: 100 }
  }
}

function KanbanCard({
  task,
  onEdit,
  onDelete,
  onDragStart,
}: {
  task: Task
  onEdit: (task: Task) => void
  onDelete: (id: string) => void
  onDragStart: (e: React.DragEvent, task: Task) => void
}) {
  const isDone = task.status === 'completed'
  const isOverdue = task.due_date && new Date(task.due_date) < new Date() && !isDone

  return (
    <div
      draggable
      onDragStart={e => onDragStart(e, task)}
      className={cn(
        'group relative rounded-xl border bg-surface-100/80 backdrop-blur-sm p-3.5',
        'cursor-grab active:cursor-grabbing',
        'hover:border-surface-500/40 hover:shadow-lg hover:shadow-black/10',
        'transition-all duration-150',
        'border-surface-300/25',
        isDone && 'opacity-60',
      )}
    >
      {/* Drag handle */}
      <div className="absolute top-3 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <GripVertical className="w-4 h-4 text-surface-700" />
      </div>

      {/* Category badge */}
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

      {/* Title */}
      <h4 className={cn(
        'text-sm font-medium text-surface-950 leading-snug pr-6',
        isDone && 'line-through text-surface-700',
      )}>
        {task.title}
      </h4>

      {/* Description preview */}
      {task.description && (
        <p className="text-xs text-surface-800 mt-1.5 line-clamp-2 leading-relaxed">
          {task.description}
        </p>
      )}

      {/* Tag badges */}
      {task.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {task.tags.map(tag => (
            <span
              key={tag.id}
              className="inline-flex items-center gap-0.5 px-1.5 py-0 rounded-md text-[10px] font-medium"
              style={{
                backgroundColor: tag.color + '15',
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

      {/* Progress bar (only for in-progress) */}
      {!isDone && task.progress > 0 && (
        <div className="mt-3 flex items-center gap-2">
          <div className="flex-1 h-1 bg-surface-300/40 rounded-full overflow-hidden">
            <div
              className={cn(
                'h-full rounded-full transition-all',
                task.progress >= 75 ? 'bg-accent-green' :
                task.progress >= 40 ? 'bg-brand-500' : 'bg-accent-amber'
              )}
              style={{ width: `${task.progress}%` }}
            />
          </div>
          <span className="text-[10px] font-medium text-surface-800 tabular-nums">{task.progress}%</span>
        </div>
      )}

      {/* Meta row */}
      <div className="flex items-center gap-2 mt-3 flex-wrap">
        {task.due_date && (
          <span className={cn(
            'inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded-md',
            isOverdue
              ? 'bg-accent-red/12 text-accent-red'
              : 'bg-surface-300/30 text-surface-800'
          )}>
            <Calendar className="w-3 h-3" />
            {formatDate(task.due_date)}
          </span>
        )}
        {task.attachments.length > 0 && (
          <span className="inline-flex items-center gap-1 text-[10px] font-medium text-surface-800 bg-surface-300/30 px-1.5 py-0.5 rounded-md">
            <Paperclip className="w-3 h-3" />
            {task.attachments.length}
          </span>
        )}

        {/* Spacer pushes actions to the right */}
        <div className="flex-1" />

        {/* Inline actions */}
        <div className="flex gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
          <button
            onClick={e => { e.stopPropagation(); onEdit(task) }}
            className="p-1 rounded-md hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
            title="Edit"
          >
            <Pencil className="w-3 h-3" />
          </button>
          <button
            onClick={e => { e.stopPropagation(); onDelete(task.id) }}
            className="p-1 rounded-md hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors"
            title="Delete"
          >
            <Trash2 className="w-3 h-3" />
          </button>
        </div>
      </div>
    </div>
  )
}

function KanbanColumnComponent({
  config,
  tasks,
  onEdit,
  onDelete,
  onDragStart,
  onDragOver,
  onDrop,
  isDragOver,
}: {
  config: ColumnConfig
  tasks: Task[]
  onEdit: (task: Task) => void
  onDelete: (id: string) => void
  onDragStart: (e: React.DragEvent, task: Task) => void
  onDragOver: (e: React.DragEvent) => void
  onDrop: (e: React.DragEvent, column: KanbanColumn) => void
  isDragOver: boolean
}) {
  return (
    <div
      className={cn(
        'flex flex-col rounded-2xl border min-h-[calc(100vh-12rem)] transition-all duration-200',
        config.bgColor,
        config.borderColor,
        isDragOver && 'ring-2 ring-brand-500/40 border-brand-500/30 bg-brand-600/10',
      )}
      onDragOver={onDragOver}
      onDrop={e => onDrop(e, config.id)}
    >
      {/* Column header */}
      <div className="flex items-center gap-2.5 px-4 py-3.5 border-b border-inherit">
        <span className={config.color}>{config.icon}</span>
        <h3 className={cn('text-sm font-semibold', config.color)}>{config.title}</h3>
        <span className={cn('text-[11px] font-semibold px-2 py-0.5 rounded-full', config.countBg)}>
          {tasks.length}
        </span>
      </div>

      {/* Cards */}
      <div className="flex-1 p-2.5 space-y-2 overflow-y-auto">
        {tasks.map(task => (
          <KanbanCard
            key={task.id}
            task={task}
            onEdit={onEdit}
            onDelete={onDelete}
            onDragStart={onDragStart}
          />
        ))}

        {/* Empty state */}
        {tasks.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12 text-surface-700">
            <span className={cn('mb-2', config.color)}>{config.icon}</span>
            <p className="text-xs">No tasks</p>
          </div>
        )}

        {/* Drop target indicator */}
        {isDragOver && (
          <div className="border-2 border-dashed border-brand-500/30 rounded-xl h-16 flex items-center justify-center">
            <p className="text-xs text-brand-400 font-medium">Drop here</p>
          </div>
        )}
      </div>
    </div>
  )
}

export default function BoardPage() {
  const { data: session } = useSession()
  const [tasks, setTasks] = useState<Task[]>([])
  const [categories, setCategories] = useState<Category[]>([])
  const [loading, setLoading] = useState(true)
  const [editingTask, setEditingTask] = useState<Task | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [dragOverColumn, setDragOverColumn] = useState<KanbanColumn | null>(null)
  const draggedTaskRef = useRef<Task | null>(null)

  const fetchTasks = useCallback(async () => {
    const res = await fetch('/api/tasks?per_page=200')
    const data = await res.json()
    setTasks(data.tasks)
    setLoading(false)
  }, [])

  const fetchCategories = async () => {
    const res = await fetch('/api/categories')
    setCategories(await res.json())
  }

  useEffect(() => {
    fetchTasks()
    fetchCategories()
  }, [fetchTasks])

  const handleUpdateTask = async (id: string, data: Partial<Task>) => {
    await fetch(`/api/tasks/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    fetchTasks()
  }

  const handleDeleteTask = async (id: string) => {
    if (!confirm('Delete this task?')) return
    await fetch(`/api/tasks/${id}`, { method: 'DELETE' })
    fetchTasks()
  }

  const handleCreateTask = async (data: { title: string; description: string; category_id: string | null; tags: string[]; due_date: string | null }) => {
    await fetch('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    setShowForm(false)
    fetchTasks()
  }

  const handleEditSubmit = async (data: { title: string; description: string; category_id: string | null; tags: string[]; due_date: string | null; progress?: number }) => {
    if (!editingTask) return
    await fetch(`/api/tasks/${editingTask.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    setEditingTask(null)
    fetchTasks()
  }

  const handleDeleteAttachment = async (attachmentId: string) => {
    await fetch(`/api/uploads/${attachmentId}`, { method: 'DELETE' })
  }

  // Drag and drop handlers
  const handleDragStart = (e: React.DragEvent, task: Task) => {
    draggedTaskRef.current = task
    e.dataTransfer.effectAllowed = 'move'
    e.dataTransfer.setData('text/plain', task.id)
    const target = e.currentTarget as HTMLElement
    requestAnimationFrame(() => {
      target.style.opacity = '0.4'
    })
  }

  const handleDragOver = (e: React.DragEvent, column: KanbanColumn) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
    setDragOverColumn(column)
  }

  const handleDragEnd = () => {
    setDragOverColumn(null)
    draggedTaskRef.current = null
    document.querySelectorAll('[draggable="true"]').forEach(el => {
      (el as HTMLElement).style.opacity = '1'
    })
  }

  const handleDrop = async (e: React.DragEvent, targetColumn: KanbanColumn) => {
    e.preventDefault()
    setDragOverColumn(null)

    const task = draggedTaskRef.current
    if (!task) return

    const currentColumn = getTaskColumn(task)
    if (currentColumn === targetColumn) {
      draggedTaskRef.current = null
      return
    }

    const update = getColumnUpdate(targetColumn)

    // Optimistic update
    setTasks(prev => prev.map(t =>
      t.id === task.id ? { ...t, ...update } : t
    ))

    draggedTaskRef.current = null
    await handleUpdateTask(task.id, update)
  }

  // Group tasks by column
  const columnTasks: Record<KanbanColumn, Task[]> = {
    todo: [],
    in_progress: [],
    done: [],
  }
  tasks.forEach(task => {
    columnTasks[getTaskColumn(task)].push(task)
  })

  // Stats
  const totalTasks = tasks.length
  const completionRate = totalTasks > 0
    ? Math.round((columnTasks.done.length / totalTasks) * 100)
    : 0

  // Register global dragend listener
  useEffect(() => {
    const handler = () => handleDragEnd()
    document.addEventListener('dragend', handler)
    return () => document.removeEventListener('dragend', handler)
  }, [])

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Board</h1>
          <p className="text-surface-800 text-sm mt-0.5">
            {totalTasks} task{totalTasks !== 1 ? 's' : ''}
            {totalTasks > 0 && (
              <span className="text-surface-700"> &middot; {completionRate}% complete</span>
            )}
          </p>
        </div>
        <button onClick={() => setShowForm(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Task
        </button>
      </div>

      {/* Board */}
      {loading ? (
        <div className="flex items-center justify-center py-32">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {COLUMNS.map(col => (
            <KanbanColumnComponent
              key={col.id}
              config={col}
              tasks={columnTasks[col.id]}
              onEdit={setEditingTask}
              onDelete={handleDeleteTask}
              onDragStart={handleDragStart}
              onDragOver={e => handleDragOver(e, col.id)}
              onDrop={handleDrop}
              isDragOver={dragOverColumn === col.id}
            />
          ))}
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
          onFilesUploaded={() => fetchTasks()}
        />
      )}
    </div>
  )
}

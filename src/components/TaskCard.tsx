'use client'

import { useState } from 'react'
import {
  ChevronDown, ChevronRight, Pencil, Trash2, Check,
  Paperclip, Calendar, Download, FileText, Hash,
} from 'lucide-react'
import { cn, formatDate, formatFileSize } from '@/lib/utils'
import type { Task } from '@/types'

interface TaskCardProps {
  task: Task
  onUpdate: (id: string, data: Partial<Task>) => void
  onDelete: (id: string) => void
  onEdit: (task: Task) => void
}

export function TaskCard({ task, onUpdate, onDelete, onEdit }: TaskCardProps) {
  const [expanded, setExpanded] = useState(false)

  const isCompleted = task.task_status?.is_completed ?? task.status === 'completed'

  return (
    <div className={cn(
      'card group transition-all duration-200 hover:border-surface-400/40',
      isCompleted && 'opacity-70'
    )}>
      <div className="p-4">
        {/* Header row */}
        <div className="flex items-start gap-3">
          {/* Toggle expand */}
          <button
            onClick={() => setExpanded(!expanded)}
            className="mt-0.5 p-1 rounded-lg hover:bg-surface-300/30 text-surface-700 transition-colors flex-shrink-0"
          >
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>

          {/* Checkbox */}
          <button
            onClick={() => onUpdate(task.id, {
              status: isCompleted ? 'in_progress' : 'completed',
              progress: isCompleted ? task.progress : 100,
            })}
            className={cn(
              'mt-0.5 w-5 h-5 rounded-md border-2 flex items-center justify-center flex-shrink-0 transition-all',
              isCompleted
                ? 'bg-accent-green border-accent-green'
                : 'border-surface-500 hover:border-brand-400'
            )}
          >
            {isCompleted && <Check className="w-3 h-3 text-white" />}
          </button>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className={cn(
                'font-medium text-surface-950 truncate',
                isCompleted && 'line-through text-surface-700'
              )}>
                {task.title}
              </h3>
              {task.category && (
                <span
                  className="badge text-[10px]"
                  style={{
                    backgroundColor: task.category.color + '20',
                    color: task.category.color,
                    border: `1px solid ${task.category.color}30`,
                  }}
                >
                  {task.category.name}
                </span>
              )}
              {task.task_status && (
                <span
                  className="badge text-[10px] gap-0.5"
                  style={{
                    backgroundColor: task.task_status.color + '15',
                    color: task.task_status.color,
                    border: `1px solid ${task.task_status.color}25`,
                  }}
                >
                  {task.task_status.name}
                </span>
              )}
            </div>

            {/* Tag badges inline */}
            {task.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1.5">
                {task.tags.map(tag => (
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
              <span>{formatDate(task.created_at)}</span>
              {task.start_date && (
                <span className="flex items-center gap-1">
                  <Calendar className="w-3 h-3" /> Start {formatDate(task.start_date)}
                </span>
              )}
              {task.due_date && (
                <span className="flex items-center gap-1">
                  <Calendar className="w-3 h-3" /> Due {formatDate(task.due_date)}
                </span>
              )}
              {task.attachments.length > 0 && (
                <span className="flex items-center gap-1">
                  <Paperclip className="w-3 h-3" /> {task.attachments.length}
                </span>
              )}
            </div>

            {/* Progress bar */}
            <div className="mt-2.5 flex items-center gap-3">
              <div className="flex-1 h-1.5 bg-surface-300/40 rounded-full overflow-hidden">
                <div
                  className={cn(
                    'h-full rounded-full transition-all duration-500',
                    task.progress >= 100 ? 'bg-accent-green' :
                    task.progress >= 50 ? 'bg-brand-500' : 'bg-accent-amber'
                  )}
                  style={{ width: `${task.progress}%` }}
                />
              </div>
              <span className="text-xs font-medium text-surface-800 w-8 text-right">{task.progress}%</span>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <button
              onClick={() => onEdit(task)}
              className="p-1.5 rounded-lg hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
              title="Edit"
            >
              <Pencil className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => onDelete(task.id)}
              className="p-1.5 rounded-lg hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors"
              title="Delete"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Expanded content (read-only) */}
        {expanded && (
          <div className="mt-4 ml-14 space-y-4 animate-slide-down">
            {/* Description */}
            {task.description && (
              <div>
                <label className="text-xs font-medium text-surface-800 mb-1 block">Description</label>
                <div className="text-sm text-surface-800 bg-surface-200/40 rounded-xl p-3 whitespace-pre-wrap">
                  {task.description}
                </div>
              </div>
            )}

            {/* Attachments (download only) */}
            {task.attachments.length > 0 && (
              <div>
                <label className="text-xs font-medium text-surface-800 mb-1.5 block">Attachments</label>
                <div className="space-y-1.5">
                  {task.attachments.map(att => (
                    <div
                      key={att.id}
                      className="flex items-center gap-2 bg-surface-200/40 rounded-lg p-2 text-sm"
                    >
                      <FileText className="w-4 h-4 text-surface-700 flex-shrink-0" />
                      <span className="flex-1 truncate text-surface-800">{att.original_name}</span>
                      <span className="text-xs text-surface-700">{formatFileSize(att.size)}</span>
                      <a
                        href={`/api/uploads/${att.id}`}
                        className="p-1 rounded hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                        title="Download"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

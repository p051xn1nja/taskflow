'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import {
  X, Plus, Upload, FileText, Download, Trash2, AlertCircle,
  Image as ImageIcon, FileArchive, FileSpreadsheet, Hash,
} from 'lucide-react'
import { cn, formatFileSize } from '@/lib/utils'
import type { Task, Category, Attachment, Tag } from '@/types'

const ALLOWED_EXTENSIONS = new Set([
  'pdf', 'txt', 'md', 'docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt',
  'csv', 'json', 'rtf', 'odt',
  'zip', 'rar', '7z', 'tar', 'gz',
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp',
])

const IMAGE_EXTENSIONS = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp'])
const ARCHIVE_EXTENSIONS = new Set(['zip', 'rar', '7z', 'tar', 'gz'])
const SPREADSHEET_EXTENSIONS = new Set(['xlsx', 'xls', 'csv'])

const MAX_FILES = 10
const MAX_TOTAL_SIZE = 50 * 1024 * 1024 // 50MB

function getFileIcon(filename: string) {
  const ext = filename.split('.').pop()?.toLowerCase() || ''
  if (IMAGE_EXTENSIONS.has(ext)) return <ImageIcon className="w-4 h-4 text-accent-purple" />
  if (ARCHIVE_EXTENSIONS.has(ext)) return <FileArchive className="w-4 h-4 text-accent-amber" />
  if (SPREADSHEET_EXTENSIONS.has(ext)) return <FileSpreadsheet className="w-4 h-4 text-accent-green" />
  return <FileText className="w-4 h-4 text-brand-400" />
}

interface TaskFormProps {
  task?: Task | null
  categories: Category[]
  onSubmit: (data: {
    title: string
    description: string
    category_id: string | null
    tags: string[]
    due_date: string | null
    progress?: number
  }) => void
  onCancel: () => void
  onDeleteAttachment?: (attachmentId: string) => void
  onFilesUploaded?: () => void
}

export function TaskForm({ task, categories, onSubmit, onCancel, onDeleteAttachment, onFilesUploaded }: TaskFormProps) {
  const [title, setTitle] = useState(task?.title || '')
  const [description, setDescription] = useState(task?.description || '')
  const [categoryId, setCategoryId] = useState(task?.category_id || '')
  const [tags, setTags] = useState<string[]>(task?.tags?.map(t => typeof t === 'string' ? t : t.name) || [])
  const [tagInput, setTagInput] = useState('')
  const [dueDate, setDueDate] = useState(task?.due_date || '')
  const [progress, setProgress] = useState(task?.progress ?? 0)

  // Tag autocomplete
  const [allTags, setAllTags] = useState<Tag[]>([])
  const [showSuggestions, setShowSuggestions] = useState(false)
  const tagInputRef = useRef<HTMLInputElement>(null)

  // File management
  const [attachments, setAttachments] = useState<Attachment[]>(task?.attachments || [])
  const [stagedFiles, setStagedFiles] = useState<File[]>([])
  const [uploading, setUploading] = useState(false)
  const [dragOver, setDragOver] = useState(false)
  const [fileError, setFileError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const isEditing = !!task

  // Computed limits
  const existingSize = attachments.reduce((sum, a) => sum + a.size, 0)
  const stagedSize = stagedFiles.reduce((sum, f) => sum + f.size, 0)
  const totalSize = existingSize + stagedSize
  const totalCount = attachments.length + stagedFiles.length

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onCancel])

  // Fetch all tags for autocomplete
  useEffect(() => {
    fetch('/api/tags').then(r => r.json()).then(setAllTags).catch(() => {})
  }, [])

  const filteredSuggestions = allTags.filter(t =>
    t.name.toLowerCase().includes(tagInput.toLowerCase()) &&
    !tags.includes(t.name)
  ).slice(0, 8)

  const addTag = (name?: string) => {
    const t = (name || tagInput).trim()
    if (t && !tags.includes(t) && tags.length < 10) {
      setTags([...tags, t])
      setTagInput('')
      setShowSuggestions(false)
    }
  }

  const validateAndAddFiles = useCallback((newFiles: File[]) => {
    setFileError(null)

    const valid: File[] = []
    for (const f of newFiles) {
      const ext = f.name.split('.').pop()?.toLowerCase() || ''
      if (!ALLOWED_EXTENSIONS.has(ext)) {
        setFileError(`"${f.name}" has an unsupported file type`)
        continue
      }
      valid.push(f)
    }

    if (valid.length === 0) return

    const availableSlots = MAX_FILES - totalCount
    if (availableSlots <= 0) {
      setFileError(`Maximum ${MAX_FILES} files per task`)
      return
    }
    const filesToAdd = valid.slice(0, availableSlots)
    if (filesToAdd.length < valid.length) {
      setFileError(`Only ${availableSlots} more file${availableSlots > 1 ? 's' : ''} allowed`)
    }

    const newSize = filesToAdd.reduce((sum, f) => sum + f.size, 0)
    if (totalSize + newSize > MAX_TOTAL_SIZE) {
      setFileError(`Total file size would exceed 50 MB limit`)
      return
    }

    setStagedFiles(prev => [...prev, ...filesToAdd])
  }, [totalCount, totalSize])

  const removeStagedFile = (index: number) => {
    setStagedFiles(prev => prev.filter((_, i) => i !== index))
    setFileError(null)
  }

  const handleDeleteAttachment = async (attId: string) => {
    if (onDeleteAttachment) {
      onDeleteAttachment(attId)
      setAttachments(prev => prev.filter(a => a.id !== attId))
    }
  }

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragOver(true)
  }

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragOver(false)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragOver(false)
    const files = Array.from(e.dataTransfer.files)
    if (files.length > 0) validateAndAddFiles(files)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!title.trim()) return

    setUploading(true)

    // Upload staged files first (if editing and there are files)
    if (isEditing && stagedFiles.length > 0) {
      const formData = new FormData()
      formData.append('task_id', task!.id)
      stagedFiles.forEach(f => formData.append('files', f))
      const res = await fetch('/api/uploads', { method: 'POST', body: formData })
      if (!res.ok) {
        const data = await res.json()
        setFileError(data.error || 'Upload failed')
        setUploading(false)
        return
      }
    }

    // Submit task data
    onSubmit({
      title: title.trim(),
      description: description.trim(),
      category_id: categoryId || null,
      tags,
      due_date: dueDate || null,
      ...(isEditing ? { progress } : {}),
    })

    if (stagedFiles.length > 0 && onFilesUploaded) {
      onFilesUploaded()
    }

    setUploading(false)
  }

  const progressColor = progress >= 100 ? 'text-accent-green' :
    progress >= 50 ? 'text-brand-400' : 'text-accent-amber'

  const acceptStr = Array.from(ALLOWED_EXTENSIONS).map(e => `.${e}`).join(',')

  // Get tag color for display
  const getTagColor = (name: string) => {
    const found = allTags.find(t => t.name.toLowerCase() === name.toLowerCase())
    return found?.color || '#3b82f6'
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="card w-full max-w-lg p-6 animate-scale-in max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-semibold text-white">
            {isEditing ? 'Edit Task' : 'New Task'}
          </h2>
          <button onClick={onCancel} className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Title */}
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

          {/* Description */}
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

          {/* Category + Due Date */}
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

          {/* Progress (edit mode only) */}
          {isEditing && (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-sm font-medium text-surface-800">Progress</label>
                <span className={cn('text-sm font-semibold tabular-nums', progressColor)}>
                  {progress}%
                </span>
              </div>
              <div className="relative">
                <div className="h-2 bg-surface-300/40 rounded-full overflow-hidden">
                  <div
                    className={cn(
                      'h-full rounded-full transition-all duration-200',
                      progress >= 100 ? 'bg-accent-green' :
                      progress >= 50 ? 'bg-brand-500' : 'bg-accent-amber'
                    )}
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={progress}
                  onChange={e => setProgress(parseInt(e.target.value))}
                  className="absolute inset-0 w-full opacity-0 cursor-pointer"
                />
              </div>
            </div>
          )}

          {/* Tags */}
          <div>
            <label className="block text-sm font-medium text-surface-800 mb-1.5">
              Tags ({tags.length}/10)
            </label>
            {tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mb-2">
                {tags.map(tag => {
                  const tagColor = getTagColor(tag)
                  return (
                    <span
                      key={tag}
                      className="badge gap-1"
                      style={{
                        backgroundColor: tagColor + '18',
                        color: tagColor,
                        border: `1px solid ${tagColor}25`,
                      }}
                    >
                      <Hash className="w-3 h-3" />
                      {tag}
                      <button
                        type="button"
                        onClick={() => setTags(tags.filter(t => t !== tag))}
                        className="hover:opacity-70"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </span>
                  )
                })}
              </div>
            )}
            <div className="relative">
              <div className="flex gap-2">
                <input
                  ref={tagInputRef}
                  type="text"
                  className="input-base flex-1"
                  placeholder="Add a tag..."
                  value={tagInput}
                  onChange={e => { setTagInput(e.target.value); setShowSuggestions(true) }}
                  onFocus={() => setShowSuggestions(true)}
                  onBlur={() => setTimeout(() => setShowSuggestions(false), 200)}
                  onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag() } }}
                  maxLength={30}
                />
                <button
                  type="button"
                  onClick={() => addTag()}
                  disabled={!tagInput.trim() || tags.length >= 10}
                  className="btn-secondary px-3"
                >
                  <Plus className="w-4 h-4" />
                </button>
              </div>

              {/* Autocomplete dropdown */}
              {showSuggestions && tagInput && filteredSuggestions.length > 0 && (
                <div className="absolute left-0 right-12 top-full mt-1 bg-surface-100 border border-surface-300/40 rounded-xl shadow-xl z-50 overflow-hidden">
                  {filteredSuggestions.map(tag => (
                    <button
                      key={tag.id}
                      type="button"
                      className="flex items-center gap-2 w-full px-3 py-2 text-sm text-left hover:bg-surface-300/30 transition-colors"
                      onMouseDown={e => { e.preventDefault(); addTag(tag.name) }}
                    >
                      <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: tag.color }} />
                      <span className="text-surface-900">{tag.name}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Attachments (edit mode only) */}
          {isEditing && (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-sm font-medium text-surface-800">
                  Attachments ({totalCount}/{MAX_FILES})
                </label>
                <span className="text-xs text-surface-700 tabular-nums">
                  {formatFileSize(totalSize)} / 50 MB
                </span>
              </div>

              {/* Existing attachments */}
              {(attachments.length > 0 || stagedFiles.length > 0) && (
                <div className="space-y-1.5 mb-3">
                  {attachments.map(att => (
                    <div
                      key={att.id}
                      className="flex items-center gap-2 bg-surface-200/40 rounded-lg p-2 text-sm group/att"
                    >
                      {getFileIcon(att.original_name)}
                      <span className="flex-1 truncate text-surface-800">{att.original_name}</span>
                      <span className="text-xs text-surface-700 tabular-nums">{formatFileSize(att.size)}</span>
                      <a
                        href={`/api/uploads/${att.id}`}
                        className="p-1 rounded hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                        title="Download"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </a>
                      <button
                        type="button"
                        onClick={() => handleDeleteAttachment(att.id)}
                        className="p-1 rounded hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors"
                        title="Remove"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}

                  {/* Staged (new) files */}
                  {stagedFiles.map((f, i) => (
                    <div
                      key={`staged-${i}`}
                      className="flex items-center gap-2 bg-brand-600/8 border border-brand-500/15 rounded-lg p-2 text-sm"
                    >
                      {getFileIcon(f.name)}
                      <span className="flex-1 truncate text-surface-800">{f.name}</span>
                      <span className="text-[10px] font-medium text-brand-400 bg-brand-600/15 px-1.5 py-0.5 rounded">NEW</span>
                      <span className="text-xs text-surface-700 tabular-nums">{formatFileSize(f.size)}</span>
                      <button
                        type="button"
                        onClick={() => removeStagedFile(i)}
                        className="p-1 rounded hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors"
                        title="Remove"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* Drop zone */}
              {totalCount < MAX_FILES && (
                <>
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    className="hidden"
                    accept={acceptStr}
                    onChange={e => {
                      const files = Array.from(e.target.files || [])
                      if (files.length > 0) validateAndAddFiles(files)
                      e.target.value = ''
                    }}
                  />
                  <div
                    onClick={() => fileInputRef.current?.click()}
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                    className={cn(
                      'border-2 border-dashed rounded-xl p-4 text-center cursor-pointer transition-all duration-150',
                      dragOver
                        ? 'border-brand-400 bg-brand-600/10'
                        : 'border-surface-400/30 hover:border-surface-500/50 hover:bg-surface-200/30'
                    )}
                  >
                    <Upload className={cn(
                      'w-5 h-5 mx-auto mb-1.5 transition-colors',
                      dragOver ? 'text-brand-400' : 'text-surface-700'
                    )} />
                    <p className="text-xs text-surface-800">
                      Drop files here or <span className="text-brand-400 font-medium">browse</span>
                    </p>
                    <p className="text-[10px] text-surface-700 mt-1">
                      Documents, images, archives &middot; 50 MB total
                    </p>
                  </div>
                </>
              )}

              {/* Error */}
              {fileError && (
                <div className="flex items-center gap-2 mt-2 text-xs text-accent-red">
                  <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                  {fileError}
                </div>
              )}
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onCancel} className="btn-secondary flex-1">
              Cancel
            </button>
            <button type="submit" disabled={uploading} className="btn-primary flex-1">
              {uploading ? 'Saving...' : isEditing ? 'Save Changes' : 'Create Task'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

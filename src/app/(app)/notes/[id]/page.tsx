'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { useRouter, useParams } from 'next/navigation'
import {
  ArrowLeft, Save, Trash2, Plus, X, Hash, Link2,
  Upload, FileText, Download, AlertCircle, Loader2,
  Image as ImageIcon, FileArchive, FileSpreadsheet,
  CheckSquare, Search, Palette,
} from 'lucide-react'
import { cn, formatFileSize, formatDate } from '@/lib/utils'
import { RichEditor } from '@/components/RichEditor'
import type { Note, Tag, NoteAttachment, LinkedTask } from '@/types'

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
const MAX_TOTAL_SIZE = 50 * 1024 * 1024

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

function getFileIcon(filename: string) {
  const ext = filename.split('.').pop()?.toLowerCase() || ''
  if (IMAGE_EXTENSIONS.has(ext)) return <ImageIcon className="w-4 h-4 text-accent-purple" />
  if (ARCHIVE_EXTENSIONS.has(ext)) return <FileArchive className="w-4 h-4 text-accent-amber" />
  if (SPREADSHEET_EXTENSIONS.has(ext)) return <FileSpreadsheet className="w-4 h-4 text-accent-green" />
  return <FileText className="w-4 h-4 text-brand-400" />
}

export default function NoteEditorPage() {
  const router = useRouter()
  const params = useParams()
  const noteId = params.id as string

  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const [tags, setTags] = useState<string[]>([])
  const [tagInput, setTagInput] = useState('')
  const [allTags, setAllTags] = useState<Tag[]>([])
  const [showTagSuggestions, setShowTagSuggestions] = useState(false)
  const [attachments, setAttachments] = useState<NoteAttachment[]>([])
  const [linkedTasks, setLinkedTasks] = useState<LinkedTask[]>([])
  const [stagedFiles, setStagedFiles] = useState<File[]>([])
  const [fileError, setFileError] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [noteColor, setNoteColor] = useState('')
  const [showColorPicker, setShowColorPicker] = useState(false)
  const colorPickerRef = useRef<HTMLDivElement>(null)
  const [showTaskLinker, setShowTaskLinker] = useState(false)
  const [taskSearch, setTaskSearch] = useState('')
  const [availableTasks, setAvailableTasks] = useState<LinkedTask[]>([])
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const autoSaveRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Load note
  useEffect(() => {
    const loadNote = async () => {
      const res = await fetch(`/api/notes/${noteId}`)
      if (!res.ok) { router.push('/notes'); return }
      const note: Note = await res.json()
      setTitle(note.title)
      setContent(note.content)
      setNoteColor(note.color || '')
      setTags(note.tags.map(t => t.name))
      setAttachments(note.attachments)
      setLinkedTasks(note.linked_tasks)
      setLoading(false)
    }
    loadNote()
  }, [noteId, router])

  // Load tags for autocomplete
  useEffect(() => {
    fetch('/api/tags').then(r => r.json()).then(setAllTags).catch(() => {})
  }, [])

  // Auto-save (debounced)
  const saveNote = useCallback(async (t?: string, c?: string, tg?: string[], lt?: string[]) => {
    setSaving(true)
    await fetch(`/api/notes/${noteId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: t ?? title,
        content: c ?? content,
        tags: tg ?? tags,
        linked_task_ids: lt ?? linkedTasks.map(lt => lt.id),
      }),
    })
    setSaving(false)
    setHasUnsavedChanges(false)
  }, [noteId, title, content, tags, linkedTasks])

  const scheduleAutoSave = useCallback(() => {
    setHasUnsavedChanges(true)
    if (autoSaveRef.current) clearTimeout(autoSaveRef.current)
    autoSaveRef.current = setTimeout(() => saveNote(), 2000)
  }, [saveNote])

  const handleTitleChange = (val: string) => {
    setTitle(val)
    scheduleAutoSave()
  }

  const handleContentChange = (html: string) => {
    setContent(html)
    scheduleAutoSave()
  }

  const addTag = (name?: string) => {
    const t = (name || tagInput).trim()
    if (t && !tags.includes(t) && tags.length < 10) {
      const newTags = [...tags, t]
      setTags(newTags)
      setTagInput('')
      setShowTagSuggestions(false)
      scheduleAutoSave()
    }
  }

  const removeTag = (name: string) => {
    const newTags = tags.filter(t => t !== name)
    setTags(newTags)
    scheduleAutoSave()
  }

  const getTagColor = (name: string) => {
    return allTags.find(t => t.name.toLowerCase() === name.toLowerCase())?.color || '#3b82f6'
  }

  const filteredTagSuggestions = allTags.filter(t =>
    t.name.toLowerCase().includes(tagInput.toLowerCase()) &&
    !tags.includes(t.name)
  ).slice(0, 8)

  // Close color picker on outside click
  useEffect(() => {
    if (!showColorPicker) return
    const handler = (e: MouseEvent) => {
      if (colorPickerRef.current && !colorPickerRef.current.contains(e.target as Node)) {
        setShowColorPicker(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showColorPicker])

  const handleSetColor = async (color: string) => {
    setNoteColor(color)
    setShowColorPicker(false)
    await fetch(`/api/notes/${noteId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ color }),
    })
  }

  // File uploads
  const existingSize = attachments.reduce((sum, a) => sum + a.size, 0)
  const stagedSize = stagedFiles.reduce((sum, f) => sum + f.size, 0)
  const totalSize = existingSize + stagedSize
  const totalCount = attachments.length + stagedFiles.length

  const validateAndAddFiles = useCallback((newFiles: File[]) => {
    setFileError(null)
    const valid: File[] = []
    for (const f of newFiles) {
      const ext = f.name.split('.').pop()?.toLowerCase() || ''
      if (!ALLOWED_EXTENSIONS.has(ext)) { setFileError(`"${f.name}" has an unsupported file type`); continue }
      valid.push(f)
    }
    if (valid.length === 0) return

    const availableSlots = MAX_FILES - totalCount
    if (availableSlots <= 0) { setFileError(`Maximum ${MAX_FILES} files per note`); return }
    const filesToAdd = valid.slice(0, availableSlots)
    const newSize = filesToAdd.reduce((sum, f) => sum + f.size, 0)
    if (totalSize + newSize > MAX_TOTAL_SIZE) { setFileError('Total file size would exceed 50 MB limit'); return }

    setStagedFiles(prev => [...prev, ...filesToAdd])
  }, [totalCount, totalSize])

  const uploadStagedFiles = async () => {
    if (stagedFiles.length === 0) return
    const formData = new FormData()
    formData.append('note_id', noteId)
    stagedFiles.forEach(f => formData.append('files', f))
    const res = await fetch('/api/note-uploads', { method: 'POST', body: formData })
    if (res.ok) {
      setStagedFiles([])
      // Reload note to get updated attachments
      const noteRes = await fetch(`/api/notes/${noteId}`)
      const note = await noteRes.json()
      setAttachments(note.attachments)
    } else {
      const data = await res.json()
      setFileError(data.error || 'Upload failed')
    }
  }

  const handleDeleteAttachment = async (attId: string) => {
    await fetch(`/api/note-uploads/${attId}`, { method: 'DELETE' })
    setAttachments(prev => prev.filter(a => a.id !== attId))
  }

  // Task linking
  const searchTasks = async (query: string) => {
    const params = new URLSearchParams({ per_page: '20' })
    if (query) params.set('search', query)
    const res = await fetch(`/api/tasks?${params}`)
    const data = await res.json()
    setAvailableTasks(data.tasks.map((t: { id: string; title: string; status: string; progress: number }) => ({
      id: t.id,
      title: t.title,
      status: t.status,
      progress: t.progress,
    })))
  }

  const linkTask = (task: LinkedTask) => {
    if (linkedTasks.some(lt => lt.id === task.id)) return
    const newLinked = [...linkedTasks, task]
    setLinkedTasks(newLinked)
    // Save immediately
    saveNote(undefined, undefined, undefined, newLinked.map(lt => lt.id))
  }

  const unlinkTask = (taskId: string) => {
    const newLinked = linkedTasks.filter(lt => lt.id !== taskId)
    setLinkedTasks(newLinked)
    saveNote(undefined, undefined, undefined, newLinked.map(lt => lt.id))
  }

  const handleManualSave = async () => {
    if (autoSaveRef.current) clearTimeout(autoSaveRef.current)
    await uploadStagedFiles()
    await saveNote()
  }

  const handleDelete = async () => {
    if (!confirm('Delete this note permanently?')) return
    await fetch(`/api/notes/${noteId}`, { method: 'DELETE' })
    router.push('/notes')
  }

  const acceptStr = Array.from(ALLOWED_EXTENSIONS).map(e => `.${e}`).join(',')

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-4 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <button
          onClick={() => router.push('/notes')}
          className="p-2 rounded-xl hover:bg-surface-300/30 text-surface-700 hover:text-surface-900 transition-colors flex-shrink-0"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2">
          {saving && <span className="text-xs text-surface-700">Saving...</span>}
          {!saving && hasUnsavedChanges && <span className="text-xs text-accent-amber">Unsaved</span>}
          {!saving && !hasUnsavedChanges && <span className="text-xs text-surface-700">Saved</span>}
          <div className="relative" ref={colorPickerRef}>
            <button
              onClick={() => setShowColorPicker(!showColorPicker)}
              className={cn('p-2 rounded-xl hover:bg-surface-300/30 transition-colors', showColorPicker && 'bg-surface-300/30')}
              title="Note color"
            >
              {noteColor ? (
                <div className="w-4 h-4 rounded-full" style={{ backgroundColor: noteColor }} />
              ) : (
                <Palette className="w-4 h-4 text-surface-700" />
              )}
            </button>
            {showColorPicker && (
              <div className="absolute right-0 top-full mt-1 bg-surface-100 border border-surface-300/40 rounded-xl shadow-xl z-50 p-2.5 min-w-[200px] animate-scale-in">
                <p className="text-[10px] font-semibold text-surface-700 uppercase tracking-wider mb-2 px-0.5">Card Color</p>
                <div className="grid grid-cols-6 gap-2">
                  {NOTE_COLORS.map(c => (
                    <button
                      key={c.value || 'none'}
                      type="button"
                      onClick={() => handleSetColor(c.value)}
                      className={cn(
                        'w-7 h-7 rounded-full transition-all hover:scale-110 flex items-center justify-center',
                        noteColor === c.value && 'ring-2 ring-offset-1 ring-brand-400 ring-offset-surface-100',
                        !c.value && 'border border-surface-400/40',
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
          <button onClick={handleManualSave} className="btn-primary flex items-center gap-2 text-sm py-2">
            <Save className="w-3.5 h-3.5" /> Save
          </button>
          <button onClick={handleDelete} className="btn-danger flex items-center gap-2 text-sm py-2">
            <Trash2 className="w-3.5 h-3.5" /> Delete
          </button>
        </div>
      </div>

      {/* Title */}
      <input
        type="text"
        value={title}
        onChange={e => handleTitleChange(e.target.value)}
        placeholder="Note title..."
        className="w-full text-2xl font-bold text-white bg-transparent border-none outline-none placeholder:text-surface-700"
        maxLength={200}
      />

      {/* Tags */}
      <div className="flex flex-wrap items-center gap-1.5">
        {tags.map(tag => {
          const color = getTagColor(tag)
          return (
            <span
              key={tag}
              className="badge gap-1"
              style={{
                backgroundColor: color + '18',
                color: color,
                border: `1px solid ${color}25`,
              }}
            >
              <Hash className="w-3 h-3" />
              {tag}
              <button type="button" onClick={() => removeTag(tag)} className="hover:opacity-70">
                <X className="w-3 h-3" />
              </button>
            </span>
          )
        })}
        <div className="relative">
          <input
            type="text"
            className="bg-transparent border-none outline-none text-sm text-surface-900 placeholder:text-surface-700 w-32"
            placeholder="+ Add tag"
            value={tagInput}
            onChange={e => { setTagInput(e.target.value); setShowTagSuggestions(true) }}
            onFocus={() => setShowTagSuggestions(true)}
            onBlur={() => setTimeout(() => setShowTagSuggestions(false), 200)}
            onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag() } }}
            maxLength={30}
          />
          {showTagSuggestions && tagInput && filteredTagSuggestions.length > 0 && (
            <div className="absolute left-0 top-full mt-1 bg-surface-100 border border-surface-300/40 rounded-xl shadow-xl z-50 overflow-hidden min-w-[180px]">
              {filteredTagSuggestions.map(tag => (
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

      {/* Rich Editor */}
      <RichEditor
        content={content}
        onChange={handleContentChange}
        noteId={noteId}
        noteColor={noteColor}
        onNoteColorChange={handleSetColor}
      />

      {/* Linked Tasks */}
      <div className="card p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-surface-900 flex items-center gap-2">
            <Link2 className="w-4 h-4 text-brand-400" />
            Linked Tasks
          </h3>
          <button
            onClick={() => { setShowTaskLinker(!showTaskLinker); if (!showTaskLinker) searchTasks('') }}
            className="btn-ghost text-xs flex items-center gap-1"
          >
            <Plus className="w-3.5 h-3.5" /> Link Task
          </button>
        </div>

        {linkedTasks.length > 0 && (
          <div className="space-y-1.5 mb-3">
            {linkedTasks.map(task => (
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
                <button
                  onClick={() => unlinkTask(task.id)}
                  className="p-1 rounded hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors"
                  title="Unlink"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        )}

        {linkedTasks.length === 0 && !showTaskLinker && (
          <p className="text-xs text-surface-700">No linked tasks</p>
        )}

        {/* Task linker */}
        {showTaskLinker && (
          <div className="border border-surface-300/30 rounded-xl p-3 animate-slide-down">
            <div className="relative mb-2">
              <Search className="w-3.5 h-3.5 text-surface-700 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                className="input-base pl-9 text-sm"
                placeholder="Search tasks..."
                value={taskSearch}
                onChange={e => { setTaskSearch(e.target.value); searchTasks(e.target.value) }}
                autoFocus
              />
            </div>
            <div className="max-h-40 overflow-y-auto space-y-1">
              {availableTasks
                .filter(t => !linkedTasks.some(lt => lt.id === t.id))
                .map(task => (
                  <button
                    key={task.id}
                    onClick={() => linkTask(task)}
                    className="flex items-center gap-2 w-full px-2 py-1.5 rounded-lg text-sm text-left hover:bg-surface-300/30 transition-colors"
                  >
                    <CheckSquare className={cn(
                      'w-3.5 h-3.5 flex-shrink-0',
                      task.status === 'completed' ? 'text-accent-green' : 'text-surface-700'
                    )} />
                    <span className="truncate text-surface-900">{task.title}</span>
                  </button>
                ))}
              {availableTasks.length === 0 && (
                <p className="text-xs text-surface-700 text-center py-2">No tasks found</p>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Attachments */}
      <div className="card p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-surface-900">
            Attachments ({totalCount}/{MAX_FILES})
          </h3>
          <span className="text-xs text-surface-700 tabular-nums">
            {formatFileSize(totalSize)} / 50 MB
          </span>
        </div>

        {/* Existing attachments */}
        {(attachments.length > 0 || stagedFiles.length > 0) && (
          <div className="space-y-1.5 mb-3">
            {attachments.map(att => (
              <div key={att.id} className="flex items-center gap-2 bg-surface-200/40 rounded-lg p-2 text-sm">
                {getFileIcon(att.original_name)}
                <span className="flex-1 truncate text-surface-800">{att.original_name}</span>
                <span className="text-xs text-surface-700 tabular-nums">{formatFileSize(att.size)}</span>
                <a
                  href={`/api/note-uploads/${att.id}`}
                  className="p-1 rounded hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                  title="Download"
                >
                  <Download className="w-3.5 h-3.5" />
                </a>
                <button
                  onClick={() => handleDeleteAttachment(att.id)}
                  className="p-1 rounded hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors"
                  title="Remove"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
            {stagedFiles.map((f, i) => (
              <div key={`staged-${i}`} className="flex items-center gap-2 bg-brand-600/8 border border-brand-500/15 rounded-lg p-2 text-sm">
                {getFileIcon(f.name)}
                <span className="flex-1 truncate text-surface-800">{f.name}</span>
                <span className="text-[10px] font-medium text-brand-400 bg-brand-600/15 px-1.5 py-0.5 rounded">NEW</span>
                <span className="text-xs text-surface-700 tabular-nums">{formatFileSize(f.size)}</span>
                <button
                  onClick={() => setStagedFiles(prev => prev.filter((_, j) => j !== i))}
                  className="p-1 rounded hover:bg-accent-red/10 text-surface-700 hover:text-accent-red transition-colors"
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
              onDragOver={e => { e.preventDefault(); e.stopPropagation(); setDragOver(true) }}
              onDragLeave={e => { e.preventDefault(); e.stopPropagation(); setDragOver(false) }}
              onDrop={e => {
                e.preventDefault(); e.stopPropagation(); setDragOver(false)
                const files = Array.from(e.dataTransfer.files)
                if (files.length > 0) validateAndAddFiles(files)
              }}
              className={cn(
                'border-2 border-dashed rounded-xl p-4 text-center cursor-pointer transition-all duration-150',
                dragOver
                  ? 'border-brand-400 bg-brand-600/10'
                  : 'border-surface-400/30 hover:border-surface-500/50 hover:bg-surface-200/30'
              )}
            >
              <Upload className={cn('w-5 h-5 mx-auto mb-1.5', dragOver ? 'text-brand-400' : 'text-surface-700')} />
              <p className="text-xs text-surface-800">
                Drop files here or <span className="text-brand-400 font-medium">browse</span>
              </p>
              <p className="text-[10px] text-surface-700 mt-1">
                Documents, images, archives &middot; 50 MB total
              </p>
            </div>
          </>
        )}

        {fileError && (
          <div className="flex items-center gap-2 mt-2 text-xs text-accent-red">
            <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
            {fileError}
          </div>
        )}

        {stagedFiles.length > 0 && (
          <button onClick={uploadStagedFiles} className="btn-primary text-sm mt-3 w-full py-2">
            Upload {stagedFiles.length} file{stagedFiles.length !== 1 ? 's' : ''}
          </button>
        )}
      </div>
    </div>
  )
}

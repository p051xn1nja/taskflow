'use client'

import { useState, useRef } from 'react'
import { Upload, X, FileText } from 'lucide-react'
import { formatFileSize } from '@/lib/utils'

interface FileUploadProps {
  taskId: string
  onUploaded: () => void
}

export function FileUpload({ taskId, onUploaded }: FileUploadProps) {
  const [files, setFiles] = useState<File[]>([])
  const [uploading, setUploading] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleUpload = async () => {
    if (files.length === 0) return
    setUploading(true)

    const formData = new FormData()
    formData.append('task_id', taskId)
    files.forEach(f => formData.append('files', f))

    await fetch('/api/uploads', { method: 'POST', body: formData })
    setFiles([])
    setUploading(false)
    onUploaded()
  }

  return (
    <div className="space-y-2">
      <input
        ref={inputRef}
        type="file"
        multiple
        className="hidden"
        onChange={e => {
          const newFiles = Array.from(e.target.files || [])
          setFiles(prev => [...prev, ...newFiles].slice(0, 10))
          e.target.value = ''
        }}
        accept=".pdf,.txt,.md,.docx,.doc,.xlsx,.xls,.pptx,.ppt,.csv,.json,.zip,.png,.jpg,.jpeg,.gif,.webp,.svg"
      />

      {files.length > 0 && (
        <div className="space-y-1">
          {files.map((f, i) => (
            <div key={i} className="flex items-center gap-2 bg-surface-200/40 rounded-lg p-2 text-sm">
              <FileText className="w-4 h-4 text-surface-700" />
              <span className="flex-1 truncate text-surface-800">{f.name}</span>
              <span className="text-xs text-surface-700">{formatFileSize(f.size)}</span>
              <button onClick={() => setFiles(files.filter((_, j) => j !== i))}>
                <X className="w-3.5 h-3.5 text-surface-700 hover:text-accent-red" />
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="flex gap-2">
        <button
          onClick={() => inputRef.current?.click()}
          className="btn-secondary text-sm flex items-center gap-2"
        >
          <Upload className="w-4 h-4" /> Choose Files
        </button>
        {files.length > 0 && (
          <button
            onClick={handleUpload}
            disabled={uploading}
            className="btn-primary text-sm"
          >
            {uploading ? 'Uploading...' : `Upload ${files.length} file${files.length > 1 ? 's' : ''}`}
          </button>
        )}
      </div>
    </div>
  )
}

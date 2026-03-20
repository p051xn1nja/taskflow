'use client'

import { useEffect, useRef } from 'react'
import { AlertTriangle, X } from 'lucide-react'

interface ConfirmModalProps {
  open: boolean
  title: string
  message: string
  confirmLabel?: string
  onConfirm: () => void
  onCancel: () => void
}

export function ConfirmModal({ open, title, message, confirmLabel = 'Delete', onConfirm, onCancel }: ConfirmModalProps) {
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, onCancel])

  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) onCancel()
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open, onCancel])

  if (!open) return null

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div ref={panelRef} className="card w-full max-w-sm p-6 animate-scale-in">
        <div className="flex items-start gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-accent-red/15 flex items-center justify-center flex-shrink-0">
            <AlertTriangle className="w-5 h-5 text-accent-red" />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-base font-semibold text-white">{title}</h3>
            <p className="text-sm text-surface-800 mt-1">{message}</p>
          </div>
          <button
            onClick={onCancel}
            className="p-1 rounded-lg hover:bg-surface-300/30 text-surface-700 transition-colors flex-shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="flex gap-3">
          <button onClick={onCancel} className="btn-secondary flex-1">
            Cancel
          </button>
          <button onClick={onConfirm} className="btn-danger flex-1">
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

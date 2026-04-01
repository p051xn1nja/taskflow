'use client'

import { useEffect, useRef } from 'react'
import { X, Download } from 'lucide-react'

interface PdfPreviewModalProps {
  url: string
  filename: string
  onClose: () => void
}

export function PdfPreviewModal({ url, filename, onClose }: PdfPreviewModalProps) {
  const backdropRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <div
      ref={backdropRef}
      className="fixed inset-0 bg-black/70 backdrop-blur-sm z-[60] flex flex-col items-center justify-center p-4"
      onClick={e => { if (e.target === backdropRef.current) onClose() }}
    >
      {/* Header bar */}
      <div className="w-full max-w-4xl flex items-center justify-between mb-2 animate-scale-in">
        <h3 className="text-sm font-medium text-white truncate flex-1 mr-4">{filename}</h3>
        <div className="flex items-center gap-1 flex-shrink-0">
          <a
            href={url}
            className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700 hover:text-brand-400 transition-colors"
            title="Download"
          >
            <Download className="w-4 h-4" />
          </a>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700 transition-colors"
            title="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* PDF iframe */}
      <div className="w-full max-w-4xl flex-1 min-h-0 rounded-xl overflow-hidden bg-white animate-scale-in">
        <iframe
          src={url}
          className="w-full h-full border-0"
          title={`Preview: ${filename}`}
        />
      </div>
    </div>
  )
}

/** Check if a filename is a PDF */
export function isPdf(filename: string): boolean {
  return filename.split('.').pop()?.toLowerCase() === 'pdf'
}

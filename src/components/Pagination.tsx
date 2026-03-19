'use client'

import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react'
import { cn } from '@/lib/utils'

interface PaginationProps {
  page: number
  totalPages: number
  total: number
  onPageChange: (page: number) => void
}

export function Pagination({ page, totalPages, total, onPageChange }: PaginationProps) {
  if (totalPages <= 1) return null

  // Build page numbers to show: always show first, last, current, and neighbors
  const pages: (number | 'dots')[] = []
  const addPage = (p: number) => {
    if (p >= 1 && p <= totalPages && !pages.includes(p)) pages.push(p)
  }

  addPage(1)
  if (page > 3) pages.push('dots')
  for (let i = Math.max(2, page - 1); i <= Math.min(totalPages - 1, page + 1); i++) {
    addPage(i)
  }
  if (page < totalPages - 2) pages.push('dots')
  addPage(totalPages)

  // Deduplicate consecutive dots
  const cleaned: (number | 'dots')[] = []
  for (const p of pages) {
    if (p === 'dots' && cleaned[cleaned.length - 1] === 'dots') continue
    cleaned.push(p)
  }

  return (
    <div className="flex items-center justify-center gap-1 pt-4">
      {/* First page */}
      <button
        onClick={() => onPageChange(1)}
        disabled={page <= 1}
        className="p-1.5 rounded-lg text-surface-700 hover:text-surface-950 hover:bg-surface-300/40 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
        title="First page"
      >
        <ChevronsLeft className="w-4 h-4" />
      </button>

      {/* Previous */}
      <button
        onClick={() => onPageChange(page - 1)}
        disabled={page <= 1}
        className="p-1.5 rounded-lg text-surface-700 hover:text-surface-950 hover:bg-surface-300/40 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
        title="Previous page"
      >
        <ChevronLeft className="w-4 h-4" />
      </button>

      {/* Page numbers */}
      <div className="flex items-center gap-0.5 mx-1">
        {cleaned.map((p, i) =>
          p === 'dots' ? (
            <span key={`dots-${i}`} className="w-8 text-center text-surface-600 text-xs select-none">
              ···
            </span>
          ) : (
            <button
              key={p}
              onClick={() => onPageChange(p)}
              className={cn(
                'min-w-[32px] h-8 rounded-lg text-xs font-medium transition-all',
                p === page
                  ? 'bg-brand-600 text-white shadow-md shadow-brand-600/25'
                  : 'text-surface-800 hover:bg-surface-300/50 hover:text-surface-950'
              )}
            >
              {p}
            </button>
          )
        )}
      </div>

      {/* Next */}
      <button
        onClick={() => onPageChange(page + 1)}
        disabled={page >= totalPages}
        className="p-1.5 rounded-lg text-surface-700 hover:text-surface-950 hover:bg-surface-300/40 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
        title="Next page"
      >
        <ChevronRight className="w-4 h-4" />
      </button>

      {/* Last page */}
      <button
        onClick={() => onPageChange(totalPages)}
        disabled={page >= totalPages}
        className="p-1.5 rounded-lg text-surface-700 hover:text-surface-950 hover:bg-surface-300/40 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
        title="Last page"
      >
        <ChevronsRight className="w-4 h-4" />
      </button>
    </div>
  )
}

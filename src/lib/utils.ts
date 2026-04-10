import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function generateId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 24)
}

export function formatDate(dateStr: string): string {
  const d = new Date(dateStr)
  return d.toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  })
}

export function formatDateTime(dateStr: string): string {
  const d = new Date(dateStr)
  return d.toLocaleString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
}

export function groupBy<T>(items: T[], keyFn: (item: T) => string): Record<string, T[]> {
  return items.reduce((groups, item) => {
    const key = keyFn(item)
    if (!groups[key]) groups[key] = []
    groups[key].push(item)
    return groups
  }, {} as Record<string, T[]>)
}

export function parseQuickTaskInput(raw: string, fallbackDueDate = '', now = new Date()): { title: string; due_date: string | null } {
  let title = raw.trim()
  let due: string | null = fallbackDueDate || null
  const toYmd = (d: Date) => d.toISOString().slice(0, 10)

  if (/\btoday\b/i.test(title)) {
    due = toYmd(now)
    title = title.replace(/\btoday\b/ig, '').trim()
  } else if (/\btomorrow\b/i.test(title)) {
    const d = new Date(now)
    d.setDate(d.getDate() + 1)
    due = toYmd(d)
    title = title.replace(/\btomorrow\b/ig, '').trim()
  } else if (/\bnext week\b/i.test(title)) {
    const d = new Date(now)
    d.setDate(d.getDate() + 7)
    due = toYmd(d)
    title = title.replace(/\bnext week\b/ig, '').trim()
  }

  title = title.replace(/\s{2,}/g, ' ').trim()
  return { title, due_date: due }
}

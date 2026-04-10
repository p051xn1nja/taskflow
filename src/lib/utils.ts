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
  const toYmd = (d: Date) => {
    const year = d.getFullYear()
    const month = String(d.getMonth() + 1).padStart(2, '0')
    const day = String(d.getDate()).padStart(2, '0')
    return `${year}-${month}-${day}`
  }
  const weekdays = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'] as const

  const nextWeekday = (from: Date, targetDay: number) => {
    const d = new Date(from)
    const delta = (targetDay - d.getDay() + 7) % 7 || 7
    d.setDate(d.getDate() + delta)
    return d
  }

  const addMonthClamped = (from: Date) => {
    const d = new Date(from)
    const originalDay = d.getDate()
    d.setDate(1)
    d.setMonth(d.getMonth() + 1)
    const lastDay = new Date(d.getFullYear(), d.getMonth() + 1, 0).getDate()
    d.setDate(Math.min(originalDay, lastDay))
    return d
  }

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
  } else if (/\bnext month\b/i.test(title)) {
    const d = addMonthClamped(now)
    due = toYmd(d)
    title = title.replace(/\bnext month\b/ig, '').trim()
  } else {
    const weekdayPattern = /\bnext (sunday|monday|tuesday|wednesday|thursday|friday|saturday)\b/i
    const match = title.match(weekdayPattern)
    if (match) {
      const weekday = match[1].toLowerCase() as typeof weekdays[number]
      due = toYmd(nextWeekday(now, weekdays.indexOf(weekday)))
      title = title.replace(weekdayPattern, '').trim()
    }
  }

  title = title.replace(/\s{2,}/g, ' ').trim()
  return { title, due_date: due }
}

export function parsePositiveInt(value: string | null | undefined, fallback: number, max?: number): number {
  const parsed = Number.parseInt(value ?? '', 10)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  if (typeof max === 'number') return Math.min(parsed, max)
  return parsed
}

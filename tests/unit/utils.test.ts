import { describe, it, expect } from 'vitest'
import { cn, generateId, formatDate, formatDateTime, formatFileSize, groupBy } from '@/lib/utils'

describe('cn (class name merger)', () => {
  it('merges class names', () => {
    expect(cn('px-2', 'py-1')).toBe('px-2 py-1')
  })

  it('handles conditional classes', () => {
    expect(cn('base', false && 'hidden', 'extra')).toBe('base extra')
  })

  it('deduplicates conflicting tailwind classes', () => {
    expect(cn('px-2', 'px-4')).toBe('px-4')
  })

  it('handles undefined and null inputs', () => {
    expect(cn('base', undefined, null)).toBe('base')
  })

  it('returns empty string for no input', () => {
    expect(cn()).toBe('')
  })
})

describe('generateId', () => {
  it('returns a 24-character hex string', () => {
    const id = generateId()
    expect(id).toHaveLength(24)
    expect(id).toMatch(/^[a-f0-9]{24}$/)
  })

  it('generates unique IDs', () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateId()))
    expect(ids.size).toBe(100)
  })
})

describe('formatDate', () => {
  it('formats ISO date string', () => {
    const result = formatDate('2025-06-15T10:00:00Z')
    expect(result).toContain('Jun')
    expect(result).toContain('15')
    expect(result).toContain('2025')
  })

  it('handles date-only string', () => {
    const result = formatDate('2025-01-01')
    expect(result).toContain('2025')
  })
})

describe('formatDateTime', () => {
  it('includes time in output', () => {
    const result = formatDateTime('2025-06-15T14:30:00Z')
    expect(result).toContain('Jun')
    expect(result).toContain('15')
    expect(result).toContain('2025')
  })
})

describe('formatFileSize', () => {
  it('formats bytes', () => {
    expect(formatFileSize(500)).toBe('500 B')
  })

  it('formats kilobytes', () => {
    expect(formatFileSize(2048)).toBe('2.0 KB')
  })

  it('formats megabytes', () => {
    expect(formatFileSize(5 * 1024 * 1024)).toBe('5.0 MB')
  })

  it('handles zero', () => {
    expect(formatFileSize(0)).toBe('0 B')
  })

  it('formats boundary value (1 KB)', () => {
    expect(formatFileSize(1024)).toBe('1.0 KB')
  })
})

describe('groupBy', () => {
  it('groups items by key function', () => {
    const items = [
      { name: 'a', type: 'x' },
      { name: 'b', type: 'y' },
      { name: 'c', type: 'x' },
    ]
    const result = groupBy(items, i => i.type)
    expect(result).toEqual({
      x: [{ name: 'a', type: 'x' }, { name: 'c', type: 'x' }],
      y: [{ name: 'b', type: 'y' }],
    })
  })

  it('returns empty object for empty array', () => {
    expect(groupBy([], () => 'key')).toEqual({})
  })

  it('handles single group', () => {
    const result = groupBy([1, 2, 3], () => 'all')
    expect(result).toEqual({ all: [1, 2, 3] })
  })
})

'use client'

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useRouter } from 'next/navigation'
import {
  ChevronLeft, ChevronRight, Plus, Filter, Search,
  CalendarDays, CalendarRange, Calendar as CalendarIcon, Grid3X3,
  CheckSquare, FileText, Loader2, X, Hash, Paperclip, Download, MapPin, Pencil, Link2,
} from 'lucide-react'
import { cn, formatDate, formatFileSize } from '@/lib/utils'
import { TaskForm } from '@/components/TaskForm'
import type { Category, Status, Tag, Task, Note } from '@/types'

type ViewMode = 'day' | 'week' | 'month' | 'year'

interface CalendarItem {
  date: string
  type: 'task' | 'note'
  id: string
  title: string
  color: string
  status_name?: string
  status_color?: string
  is_completed?: boolean
  progress?: number
  category_name?: string
  category_color?: string
  start_date?: string
  end_date?: string
}

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
const MONTHS_SHORT = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

function getMonday(d: Date): Date {
  const day = d.getDay()
  const diff = d.getDate() - day + (day === 0 ? -6 : 1)
  return new Date(d.getFullYear(), d.getMonth(), diff)
}

function isSameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate()
}

function toDateStr(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

export default function CalendarPage() {
  const router = useRouter()
  const [view, setView] = useState<ViewMode>('month')
  const [currentDate, setCurrentDate] = useState(new Date())
  const [items, setItems] = useState<CalendarItem[]>([])
  const [loading, setLoading] = useState(true)
  const [categories, setCategories] = useState<Category[]>([])
  const [statuses, setStatuses] = useState<Status[]>([])
  const [allTags, setAllTags] = useState<Tag[]>([])
  const [showFilters, setShowFilters] = useState(false)
  const [filterCategory, setFilterCategory] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterTag, setFilterTag] = useState('')
  const [filterType, setFilterType] = useState('all')
  const [showCreateMenu, setShowCreateMenu] = useState(false)

  // Task detail modal
  const [taskDetail, setTaskDetail] = useState<Task | null>(null)
  const [taskDetailLoading, setTaskDetailLoading] = useState(false)
  const taskDetailRef = useRef<HTMLDivElement>(null)

  // Note detail modal
  const [noteDetail, setNoteDetail] = useState<Note | null>(null)
  const [noteDetailLoading, setNoteDetailLoading] = useState(false)
  const noteDetailRef = useRef<HTMLDivElement>(null)

  // Task edit modal
  const [editingTask, setEditingTask] = useState<Task | null>(null)

  // Abort controller for stale fetch cancellation
  const abortRef = useRef<AbortController | null>(null)

  // Day click popup state
  const [dayPopup, setDayPopup] = useState<{ date: string; x: number; y: number } | null>(null)
  const popupRef = useRef<HTMLDivElement>(null)

  const createMenuRef = useRef<HTMLDivElement>(null)

  // Close popup on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (popupRef.current && !popupRef.current.contains(e.target as Node)) {
        setDayPopup(null)
      }
    }
    if (dayPopup) document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [dayPopup])

  // Close create menu on outside click
  useEffect(() => {
    if (!showCreateMenu) return
    const handler = (e: MouseEvent) => {
      if (createMenuRef.current && !createMenuRef.current.contains(e.target as Node)) setShowCreateMenu(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showCreateMenu])

  // Close task detail on outside click
  useEffect(() => {
    if (!taskDetail) return
    const handler = (e: MouseEvent) => {
      if (taskDetailRef.current && !taskDetailRef.current.contains(e.target as Node)) setTaskDetail(null)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [taskDetail])

  // Close note detail on outside click
  useEffect(() => {
    if (!noteDetail) return
    const handler = (e: MouseEvent) => {
      if (noteDetailRef.current && !noteDetailRef.current.contains(e.target as Node)) setNoteDetail(null)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [noteDetail])

  // ESC to close popups
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (editingTask) { setEditingTask(null); return }
        if (taskDetail) { setTaskDetail(null); return }
        if (noteDetail) { setNoteDetail(null); return }
        if (dayPopup) { setDayPopup(null); return }
        if (showCreateMenu) { setShowCreateMenu(false); return }
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [editingTask, taskDetail, noteDetail, dayPopup, showCreateMenu])

  // Calculate date range for current view
  const dateRange = useMemo(() => {
    const y = currentDate.getFullYear()
    const m = currentDate.getMonth()

    if (view === 'day') {
      return { from: toDateStr(currentDate), to: toDateStr(currentDate) }
    }
    if (view === 'week') {
      const mon = getMonday(currentDate)
      const sun = new Date(mon)
      sun.setDate(mon.getDate() + 6)
      return { from: toDateStr(mon), to: toDateStr(sun) }
    }
    if (view === 'month') {
      const first = new Date(y, m, 1)
      const last = new Date(y, m + 1, 0)
      const gridStart = getMonday(first)
      const gridEnd = new Date(last)
      const endDay = gridEnd.getDay()
      if (endDay !== 0) gridEnd.setDate(gridEnd.getDate() + (7 - endDay))
      return { from: toDateStr(gridStart), to: toDateStr(gridEnd) }
    }
    return { from: `${y}-01-01`, to: `${y}-12-31` }
  }, [currentDate, view])

  const fetchItems = useCallback(async () => {
    // Cancel any in-flight request so stale responses don't overwrite fresh data
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    setLoading(true)
    const params = new URLSearchParams({
      date_from: dateRange.from,
      date_to: dateRange.to,
    })
    if (filterCategory) params.set('category_id', filterCategory)
    if (filterStatus) params.set('status_id', filterStatus)
    if (filterTag) params.set('tag', filterTag)
    if (filterType !== 'all') params.set('types', filterType)

    try {
      const res = await fetch(`/api/calendar?${params}`, { signal: controller.signal })
      const data = await res.json()
      if (!controller.signal.aborted) {
        setItems(data.items || [])
        setLoading(false)
      }
    } catch (e: unknown) {
      if (e instanceof DOMException && e.name === 'AbortError') return
      if (!controller.signal.aborted) {
        setItems([])
        setLoading(false)
      }
    }
  }, [dateRange, filterCategory, filterStatus, filterTag, filterType])

  useEffect(() => { fetchItems() }, [fetchItems])

  useEffect(() => {
    Promise.all([
      fetch('/api/categories').then(r => r.json()),
      fetch('/api/statuses').then(r => r.json()),
      fetch('/api/tags').then(r => r.json()),
    ]).then(([cats, stats, tags]) => {
      setCategories(cats)
      setStatuses(stats)
      setAllTags(tags)
    })
  }, [])

  // Group items by date - for range tasks, add them to every day in range
  const itemsByDate = useMemo(() => {
    const map: Record<string, CalendarItem[]> = {}
    for (const item of items) {
      if (item.type === 'task' && item.start_date && item.end_date) {
        // Range task: add to every day from start to end
        const start = new Date(item.start_date + 'T00:00:00')
        const end = new Date(item.end_date + 'T00:00:00')
        const cur = new Date(start)
        while (cur <= end) {
          const ds = toDateStr(cur)
          if (!map[ds]) map[ds] = []
          map[ds].push(item)
          cur.setDate(cur.getDate() + 1)
        }
      } else {
        const d = item.date.split(/[T ]/)[0]
        if (!map[d]) map[d] = []
        map[d].push(item)
      }
    }
    return map
  }, [items])

  // Deduplicated items for a given date (range tasks appear once)
  const getUniqueItems = (ds: string) => {
    const dayItems = itemsByDate[ds] || []
    const seen = new Set<string>()
    return dayItems.filter(item => {
      const key = `${item.type}-${item.id}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
  }

  // Navigation
  const navigate = (dir: number) => {
    const d = new Date(currentDate)
    if (view === 'day') d.setDate(d.getDate() + dir)
    else if (view === 'week') d.setDate(d.getDate() + dir * 7)
    else if (view === 'month') d.setMonth(d.getMonth() + dir)
    else d.setFullYear(d.getFullYear() + dir)
    setCurrentDate(d)
  }

  const goToday = () => setCurrentDate(new Date())

  const handleItemClick = async (item: CalendarItem) => {
    if (item.type === 'note') {
      setNoteDetailLoading(true)
      setNoteDetail(null)
      try {
        const res = await fetch(`/api/notes/${item.id}`)
        if (res.ok) {
          setNoteDetail(await res.json())
        }
      } catch {
        // ignore
      }
      setNoteDetailLoading(false)
      return
    }
    // Fetch full task details and show in modal
    setTaskDetailLoading(true)
    setTaskDetail(null)
    try {
      const res = await fetch(`/api/tasks/${item.id}`)
      if (res.ok) {
        const task = await res.json()
        setTaskDetail(task)
      }
    } catch {
      // ignore
    }
    setTaskDetailLoading(false)
  }

  const handleCreateTaskForDate = (dateStr: string) => {
    router.push(`/?new_task=1&start_date=${dateStr}&date=${dateStr}`)
    setDayPopup(null)
    setShowCreateMenu(false)
  }

  const handleCreateNoteForDate = async () => {
    const res = await fetch('/api/notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'Untitled Note', content: '' }),
    })
    const { id } = await res.json()
    router.push(`/notes/${id}`)
    setDayPopup(null)
    setShowCreateMenu(false)
  }

  const handleCreateTask = () => {
    const dateStr = toDateStr(currentDate)
    handleCreateTaskForDate(dateStr)
  }

  const handleCreateNote = async () => {
    await handleCreateNoteForDate()
  }

  const handleEditTask = () => {
    if (taskDetail) {
      setEditingTask(taskDetail)
      setTaskDetail(null)
    }
  }

  const handleEditSubmit = async (data: { title: string; description: string; category_id: string | null; tags: string[]; start_date: string | null; due_date: string | null; location: string; progress?: number }) => {
    if (!editingTask) return
    await fetch(`/api/tasks/${editingTask.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    setEditingTask(null)
    fetchItems()
  }

  const handleDeleteAttachment = async (attachmentId: string) => {
    await fetch(`/api/uploads/${attachmentId}`, { method: 'DELETE' })
  }

  const handleDayClick = (e: React.MouseEvent, dateStr: string) => {
    e.stopPropagation()
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    setDayPopup({
      date: dateStr,
      x: rect.left + rect.width / 2,
      y: rect.bottom + 4,
    })
  }

  // Title
  const title = useMemo(() => {
    const y = currentDate.getFullYear()
    const m = currentDate.getMonth()
    if (view === 'day') return `${MONTHS[m]} ${currentDate.getDate()}, ${y}`
    if (view === 'week') {
      const mon = getMonday(currentDate)
      const sun = new Date(mon); sun.setDate(mon.getDate() + 6)
      if (mon.getMonth() === sun.getMonth()) return `${MONTHS[mon.getMonth()]} ${mon.getDate()}-${sun.getDate()}, ${y}`
      return `${MONTHS_SHORT[mon.getMonth()]} ${mon.getDate()} - ${MONTHS_SHORT[sun.getMonth()]} ${sun.getDate()}, ${y}`
    }
    if (view === 'month') return `${MONTHS[m]} ${y}`
    return `${y}`
  }, [currentDate, view])

  const today = new Date()

  const viewButtons: { id: ViewMode; icon: React.ReactNode; label: string }[] = [
    { id: 'day', icon: <CalendarDays className="w-3.5 h-3.5" />, label: 'Day' },
    { id: 'week', icon: <CalendarRange className="w-3.5 h-3.5" />, label: 'Week' },
    { id: 'month', icon: <CalendarIcon className="w-3.5 h-3.5" />, label: 'Month' },
    { id: 'year', icon: <Grid3X3 className="w-3.5 h-3.5" />, label: 'Year' },
  ]

  // Check if a task bar should render on this date cell (for month view)
  const getBarInfo = (item: CalendarItem, dateStr: string) => {
    if (item.type !== 'task' || !item.start_date || !item.end_date) return null
    const sd = item.start_date
    const ed = item.end_date
    const isStart = dateStr === sd
    const isEnd = dateStr === ed
    const isMiddle = dateStr > sd && dateStr < ed
    if (!isStart && !isEnd && !isMiddle) return null
    return { isStart, isEnd, isMiddle }
  }

  const ItemPill = ({ item, dateStr }: { item: CalendarItem; dateStr: string }) => {
    const barInfo = getBarInfo(item, dateStr)

    // Range task bar rendering
    if (barInfo) {
      const { isStart, isEnd, isMiddle } = barInfo
      return (
        <button
          onClick={(e) => { e.stopPropagation(); handleItemClick(item) }}
          className={cn(
            'flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-medium truncate w-full text-left transition-colors min-h-[20px]',
            item.is_completed && 'opacity-50',
            isStart && 'rounded-l',
            isEnd && 'rounded-r',
            isMiddle && 'px-1',
          )}
          style={{
            backgroundColor: item.color + '25',
            color: item.color,
            borderLeft: isStart ? `3px solid ${item.color}` : undefined,
          }}
        >
          <CheckSquare className="w-2.5 h-2.5 flex-shrink-0" />
          <span className="truncate">{item.title}</span>
        </button>
      )
    }

    // Regular pill (single-day task or note)
    return (
      <button
        onClick={(e) => { e.stopPropagation(); handleItemClick(item) }}
        className={cn(
          'flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium truncate w-full text-left transition-colors',
          item.type === 'note' ? 'hover:bg-accent-purple/15' : 'hover:bg-surface-300/30',
          item.is_completed && 'opacity-50 line-through',
        )}
        style={{ color: item.color }}
      >
        {item.type === 'task' ? <CheckSquare className="w-2.5 h-2.5 flex-shrink-0" /> : <FileText className="w-2.5 h-2.5 flex-shrink-0" />}
        <span className="truncate">{item.title}</span>
      </button>
    )
  }

  // MONTH VIEW
  const renderMonth = () => {
    const y = currentDate.getFullYear()
    const m = currentDate.getMonth()
    const firstDay = new Date(y, m, 1)
    const gridStart = getMonday(firstDay)
    const weeks: Date[][] = []
    let d = new Date(gridStart)
    for (let w = 0; w < 6; w++) {
      const week: Date[] = []
      for (let i = 0; i < 7; i++) {
        week.push(new Date(d))
        d.setDate(d.getDate() + 1)
      }
      weeks.push(week)
      if (d.getMonth() !== m && d.getDay() === 1) break
    }

    return (
      <div className="card overflow-hidden">
        <div className="grid grid-cols-7 border-b border-surface-300/20">
          {DAYS.map(day => (
            <div key={day} className="py-2 text-center text-[11px] font-semibold text-surface-700 uppercase tracking-wider">
              {day}
            </div>
          ))}
        </div>
        <div className="grid grid-cols-7">
          {weeks.flat().map((date, idx) => {
            const ds = toDateStr(date)
            const dayItems = getUniqueItems(ds)
            const isCurrentMonth = date.getMonth() === m
            const isToday = isSameDay(date, today)
            return (
              <div
                key={idx}
                className={cn(
                  'min-h-[100px] border-b border-r border-surface-300/10 p-1.5 transition-colors cursor-pointer hover:bg-surface-200/20',
                  !isCurrentMonth && 'bg-surface-50/30',
                  isToday && 'bg-brand-600/8',
                )}
                onClick={(e) => handleDayClick(e, ds)}
              >
                <div className={cn(
                  'text-xs font-medium mb-1 w-6 h-6 flex items-center justify-center rounded-full',
                  isToday ? 'bg-brand-600 text-white' : isCurrentMonth ? 'text-surface-900' : 'text-surface-600',
                )}>
                  {date.getDate()}
                </div>
                <div className="space-y-0.5">
                  {dayItems.slice(0, 3).map(item => (
                    <ItemPill key={`${item.type}-${item.id}`} item={item} dateStr={ds} />
                  ))}
                  {dayItems.length > 3 && (
                    <p className="text-[10px] text-surface-700 px-1.5">+{dayItems.length - 3} more</p>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  // WEEK VIEW
  const renderWeek = () => {
    const mon = getMonday(currentDate)
    const days: Date[] = []
    for (let i = 0; i < 7; i++) {
      const d = new Date(mon)
      d.setDate(mon.getDate() + i)
      days.push(d)
    }

    return (
      <div className="grid grid-cols-7 gap-2">
        {days.map(date => {
          const ds = toDateStr(date)
          const dayItems = getUniqueItems(ds)
          const isToday = isSameDay(date, today)
          return (
            <div
              key={ds}
              className={cn('card p-3 min-h-[300px] cursor-pointer', isToday && 'ring-2 ring-brand-500/30')}
              onClick={(e) => handleDayClick(e, ds)}
            >
              <div className="text-center mb-3">
                <p className="text-[10px] font-semibold text-surface-700 uppercase">{DAYS[days.indexOf(date)]}</p>
                <p className={cn(
                  'text-lg font-bold mt-0.5',
                  isToday ? 'text-brand-400' : 'text-surface-950'
                )}>
                  {date.getDate()}
                </p>
                <p className="text-[10px] text-surface-700">{MONTHS_SHORT[date.getMonth()]}</p>
              </div>
              <div className="space-y-1">
                {dayItems.map(item => {
                  const barInfo = getBarInfo(item, ds)
                  return (
                    <button
                      key={`${item.type}-${item.id}`}
                      onClick={(e) => { e.stopPropagation(); handleItemClick(item) }}
                      className={cn(
                        'w-full text-left p-2 rounded-lg text-xs transition-colors',
                        item.type === 'task' ? 'bg-surface-200/40 hover:bg-surface-200/70' : 'bg-accent-purple/8 hover:bg-accent-purple/15',
                        item.is_completed && 'opacity-50',
                        barInfo && 'border-l-2',
                      )}
                      style={barInfo ? { borderLeftColor: item.color, backgroundColor: item.color + '10' } : undefined}
                    >
                      <div className="flex items-center gap-1.5 mb-0.5">
                        {item.type === 'task' ? (
                          <CheckSquare className="w-3 h-3 flex-shrink-0" style={{ color: item.color }} />
                        ) : (
                          <FileText className="w-3 h-3 flex-shrink-0 text-accent-purple" />
                        )}
                        <span className={cn('font-medium truncate', item.is_completed && 'line-through opacity-70')} style={{ color: item.color }}>
                          {item.title}
                        </span>
                      </div>
                      {item.status_name && (
                        <span className="text-[10px] font-medium" style={{ color: item.status_color }}>{item.status_name}</span>
                      )}
                      {item.category_name && (
                        <span className="text-[10px] ml-1" style={{ color: item.category_color }}>{item.category_name}</span>
                      )}
                      {barInfo && (
                        <div className="text-[9px] text-surface-700 mt-0.5">
                          {item.start_date && item.end_date && `${formatDate(item.start_date)} - ${formatDate(item.end_date)}`}
                        </div>
                      )}
                    </button>
                  )
                })}
                {dayItems.length === 0 && (
                  <p className="text-[10px] text-surface-600 text-center py-4">No items</p>
                )}
              </div>
            </div>
          )
        })}
      </div>
    )
  }

  // DAY VIEW
  const renderDay = () => {
    const ds = toDateStr(currentDate)
    const dayItems = getUniqueItems(ds)
    const taskItems = dayItems.filter(i => i.type === 'task')
    const noteItems = dayItems.filter(i => i.type === 'note')
    const isToday = isSameDay(currentDate, today)

    return (
      <div className="max-w-2xl mx-auto space-y-4">
        <div
          className={cn('card p-6 text-center cursor-pointer hover:bg-surface-200/20', isToday && 'ring-2 ring-brand-500/30')}
          onClick={(e) => handleDayClick(e, ds)}
        >
          <p className="text-surface-700 text-sm">{DAYS[(currentDate.getDay() + 6) % 7]}</p>
          <p className={cn('text-4xl font-bold mt-1', isToday ? 'text-brand-400' : 'text-white')}>
            {currentDate.getDate()}
          </p>
          <p className="text-surface-700 text-sm mt-1">{MONTHS[currentDate.getMonth()]} {currentDate.getFullYear()}</p>
          {dayItems.length > 0 && (
            <p className="text-xs text-surface-800 mt-3">{dayItems.length} item{dayItems.length !== 1 ? 's' : ''}</p>
          )}
        </div>

        {taskItems.length > 0 && (
          <div className="card p-4">
            <h3 className="text-sm font-semibold text-surface-900 flex items-center gap-2 mb-3">
              <CheckSquare className="w-4 h-4 text-brand-400" /> Tasks ({taskItems.length})
            </h3>
            <div className="space-y-2">
              {taskItems.map(item => {
                const barInfo = getBarInfo(item, ds)
                return (
                  <button key={item.id} onClick={() => handleItemClick(item)} className={cn(
                    'flex items-center gap-3 p-3 rounded-xl bg-surface-200/40 transition-colors hover:bg-surface-200/70 w-full text-left',
                    item.is_completed && 'opacity-50',
                    barInfo && 'border-l-3',
                  )}
                  style={barInfo ? { borderLeftColor: item.color, borderLeftWidth: '3px' } : undefined}
                  >
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: item.color }} />
                    <div className="flex-1 min-w-0">
                      <p className={cn('text-sm font-medium truncate', item.is_completed && 'line-through opacity-70')} style={{ color: item.color }}>
                        {item.title}
                      </p>
                      <div className="flex items-center gap-2 mt-0.5">
                        {item.status_name && <span className="text-[10px] font-medium" style={{ color: item.status_color }}>{item.status_name}</span>}
                        {item.category_name && <span className="text-[10px]" style={{ color: item.category_color }}>{item.category_name}</span>}
                        {item.progress != null && item.progress > 0 && !item.is_completed && (
                          <span className="text-[10px] text-surface-700">{item.progress}%</span>
                        )}
                        {item.start_date && item.end_date && (
                          <span className="text-[10px] text-surface-600">{formatDate(item.start_date)} - {formatDate(item.end_date)}</span>
                        )}
                      </div>
                    </div>
                  </button>
                )
              })}
            </div>
          </div>
        )}

        {noteItems.length > 0 && (
          <div className="card p-4">
            <h3 className="text-sm font-semibold text-surface-900 flex items-center gap-2 mb-3">
              <FileText className="w-4 h-4 text-accent-purple" /> Notes ({noteItems.length})
            </h3>
            <div className="space-y-2">
              {noteItems.map(item => (
                <button key={item.id} onClick={() => router.push(`/notes/${item.id}`)}
                  className="flex items-center gap-3 p-3 rounded-xl bg-accent-purple/8 hover:bg-accent-purple/15 transition-colors w-full text-left">
                  <FileText className="w-4 h-4 text-accent-purple flex-shrink-0" />
                  <span className="text-sm font-medium text-surface-950 truncate">{item.title}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {dayItems.length === 0 && !loading && (
          <div className="text-center py-12">
            <CalendarIcon className="w-8 h-8 text-surface-700 mx-auto mb-2" />
            <p className="text-sm text-surface-700">Nothing scheduled</p>
          </div>
        )}
      </div>
    )
  }

  // YEAR VIEW
  const renderYear = () => {
    const y = currentDate.getFullYear()
    return (
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
        {Array.from({ length: 12 }, (_, m) => {
          const firstDay = new Date(y, m, 1)
          const gridStart = getMonday(firstDay)
          const weeks: Date[][] = []
          let d = new Date(gridStart)
          for (let w = 0; w < 6; w++) {
            const week: Date[] = []
            for (let i = 0; i < 7; i++) {
              week.push(new Date(d))
              d.setDate(d.getDate() + 1)
            }
            weeks.push(week)
          }

          return (
            <div key={m} className="card p-3 cursor-pointer hover:border-surface-400/40 transition-all"
              onClick={() => { setCurrentDate(new Date(y, m, 1)); setView('month') }}>
              <h4 className="text-xs font-semibold text-surface-900 mb-2">{MONTHS_SHORT[m]}</h4>
              <div className="grid grid-cols-7 gap-px">
                {DAYS.map(day => (
                  <div key={day} className="text-[8px] text-surface-600 text-center font-medium">{day[0]}</div>
                ))}
                {weeks.flat().map((date, idx) => {
                  const ds = toDateStr(date)
                  const dayItems = itemsByDate[ds] || []
                  const hasItems = dayItems.length > 0
                  const isThisMonth = date.getMonth() === m
                  const isToday2 = isSameDay(date, today)
                  const dotColor = hasItems ? dayItems[0].color : undefined
                  return (
                    <div key={idx} className={cn(
                      'w-full aspect-square flex items-center justify-center relative',
                      !isThisMonth && 'opacity-20',
                    )}>
                      <span className={cn(
                        'text-[9px] leading-none',
                        isToday2 ? 'text-brand-400 font-bold' : 'text-surface-800',
                      )}>
                        {date.getDate()}
                      </span>
                      {hasItems && isThisMonth && (
                        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-1 h-1 rounded-full" style={{ backgroundColor: dotColor }} />
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>
    )
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Calendar</h1>
          <p className="text-surface-700 text-sm mt-0.5">{items.length} item{items.length !== 1 ? 's' : ''} in view</p>
        </div>
        <div className="relative" ref={createMenuRef}>
          <button onClick={() => setShowCreateMenu(!showCreateMenu)} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" /> Create
          </button>
          {showCreateMenu && (
            <div className="absolute right-0 top-full mt-1 bg-surface-100 border border-surface-300/40 rounded-xl shadow-xl z-50 overflow-hidden min-w-[160px]">
              <button onClick={handleCreateTask} className="flex items-center gap-2 w-full px-4 py-2.5 text-sm hover:bg-surface-300/30 transition-colors text-surface-900">
                <CheckSquare className="w-4 h-4 text-brand-400" /> New Task
              </button>
              <button onClick={handleCreateNote} className="flex items-center gap-2 w-full px-4 py-2.5 text-sm hover:bg-surface-300/30 transition-colors text-surface-900">
                <FileText className="w-4 h-4 text-accent-purple" /> New Note
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Navigation bar */}
      <div className="card p-3">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          {/* Date nav */}
          <div className="flex items-center gap-2">
            <button onClick={() => navigate(-1)} className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700 transition-colors">
              <ChevronLeft className="w-4 h-4" />
            </button>
            <h2 className="text-sm font-semibold text-white min-w-[180px] text-center">{title}</h2>
            <button onClick={() => navigate(1)} className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700 transition-colors">
              <ChevronRight className="w-4 h-4" />
            </button>
            <button onClick={goToday} className="btn-ghost text-xs px-2 py-1">Today</button>
          </div>

          {/* View toggles */}
          <div className="flex items-center gap-1 bg-surface-200/40 rounded-xl p-0.5">
            {viewButtons.map(v => (
              <button key={v.id} onClick={() => setView(v.id)}
                className={cn(
                  'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all',
                  view === v.id ? 'bg-brand-600/20 text-brand-400 shadow-sm' : 'text-surface-700 hover:text-surface-900'
                )}>
                {v.icon}<span className="hidden sm:inline">{v.label}</span>
              </button>
            ))}
          </div>

          {/* Filter toggle */}
          <button onClick={() => setShowFilters(!showFilters)}
            className={cn('btn-secondary flex items-center gap-2 text-xs py-1.5', showFilters && 'bg-brand-600/15 text-brand-400 border-brand-500/30')}>
            <Filter className="w-3.5 h-3.5" /> Filters
          </button>
        </div>

        {/* Filters */}
        {showFilters && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-3 pt-3 border-t border-surface-300/20 animate-slide-down">
            <select className="input-base text-xs" value={filterCategory} onChange={e => setFilterCategory(e.target.value)}>
              <option value="">All Categories</option>
              {categories.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
            <select className="input-base text-xs" value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
              <option value="">All Statuses</option>
              {statuses.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
            <select className="input-base text-xs" value={filterTag} onChange={e => setFilterTag(e.target.value)}>
              <option value="">All Tags</option>
              {allTags.map(t => <option key={t.id} value={t.name}>{t.name}</option>)}
            </select>
            <select className="input-base text-xs" value={filterType} onChange={e => setFilterType(e.target.value)}>
              <option value="all">Tasks & Notes</option>
              <option value="tasks">Tasks Only</option>
              <option value="notes">Notes Only</option>
            </select>
          </div>
        )}
      </div>

      {/* Calendar */}
      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      ) : (
        <>
          {view === 'month' && renderMonth()}
          {view === 'week' && renderWeek()}
          {view === 'day' && renderDay()}
          {view === 'year' && renderYear()}
        </>
      )}

      {/* Task detail modal */}
      {(taskDetail || taskDetailLoading) && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          {taskDetailLoading ? (
            <div className="card p-8 animate-scale-in">
              <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
            </div>
          ) : taskDetail && (
            <div ref={taskDetailRef} className="card w-full max-w-lg p-6 animate-scale-in max-h-[85vh] overflow-y-auto">
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1 min-w-0">
                  <h2 className={cn(
                    'text-lg font-semibold text-white',
                    (taskDetail.task_status?.is_completed ?? taskDetail.status === 'completed') && 'line-through text-surface-700',
                  )}>
                    {taskDetail.title}
                  </h2>
                  <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                    {taskDetail.category && (
                      <span className="badge text-[10px]" style={{
                        backgroundColor: taskDetail.category.color + '20',
                        color: taskDetail.category.color,
                        border: `1px solid ${taskDetail.category.color}30`,
                      }}>
                        {taskDetail.category.name}
                      </span>
                    )}
                    {taskDetail.task_status && (
                      <span className="badge text-[10px] gap-0.5" style={{
                        backgroundColor: taskDetail.task_status.color + '15',
                        color: taskDetail.task_status.color,
                        border: `1px solid ${taskDetail.task_status.color}25`,
                      }}>
                        {taskDetail.task_status.name}
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-1 flex-shrink-0">
                  <button onClick={handleEditTask} className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700 hover:text-brand-400 transition-colors" title="Edit task">
                    <Pencil className="w-4 h-4" />
                  </button>
                  <button onClick={() => setTaskDetail(null)} className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700 transition-colors">
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>

              {/* Progress */}
              <div className="flex items-center gap-3 mb-4">
                <div className="flex-1 h-1.5 bg-surface-300/40 rounded-full overflow-hidden">
                  <div className={cn(
                    'h-full rounded-full transition-all',
                    taskDetail.progress >= 100 ? 'bg-accent-green' :
                    taskDetail.progress >= 50 ? 'bg-brand-500' : 'bg-accent-amber'
                  )} style={{ width: `${taskDetail.progress}%` }} />
                </div>
                <span className="text-xs font-medium text-surface-800 w-8 text-right tabular-nums">{taskDetail.progress}%</span>
              </div>

              {/* Description */}
              {taskDetail.description && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-surface-800 mb-1 block">Description</label>
                  <div className="text-sm text-surface-800 bg-surface-200/40 rounded-xl p-3 whitespace-pre-wrap">
                    {taskDetail.description}
                  </div>
                </div>
              )}

              {/* Location */}
              {taskDetail.location && (
                <div className="flex items-center gap-1.5 mb-4 text-xs text-surface-800">
                  <MapPin className="w-3.5 h-3.5 text-surface-700 flex-shrink-0" />
                  {taskDetail.location}
                </div>
              )}

              {/* Dates */}
              {(taskDetail.start_date || taskDetail.due_date) && (
                <div className="flex items-center gap-4 mb-4 text-xs text-surface-800">
                  {taskDetail.start_date && (
                    <span className="flex items-center gap-1.5">
                      <CalendarIcon className="w-3.5 h-3.5 text-surface-700" />
                      Start: {formatDate(taskDetail.start_date)}
                    </span>
                  )}
                  {taskDetail.due_date && (
                    <span className={cn('flex items-center gap-1.5',
                      taskDetail.due_date && new Date(taskDetail.due_date) < new Date() && !(taskDetail.task_status?.is_completed) && 'text-accent-red'
                    )}>
                      <CalendarIcon className="w-3.5 h-3.5" />
                      Due: {formatDate(taskDetail.due_date)}
                    </span>
                  )}
                </div>
              )}

              {/* Tags */}
              {taskDetail.tags.length > 0 && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-surface-800 mb-1.5 block">Tags</label>
                  <div className="flex flex-wrap gap-1.5">
                    {taskDetail.tags.map(tag => (
                      <span key={tag.id} className="badge gap-1" style={{
                        backgroundColor: tag.color + '18',
                        color: tag.color,
                        border: `1px solid ${tag.color}25`,
                      }}>
                        <Hash className="w-3 h-3" />
                        {tag.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Attachments */}
              {taskDetail.attachments.length > 0 && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-surface-800 mb-1.5 block">
                    <Paperclip className="w-3 h-3 inline mr-1" />
                    Attachments ({taskDetail.attachments.length})
                  </label>
                  <div className="space-y-1.5">
                    {taskDetail.attachments.map(att => (
                      <div key={att.id} className="flex items-center gap-2 bg-surface-200/40 rounded-lg p-2 text-sm">
                        <FileText className="w-4 h-4 text-surface-700 flex-shrink-0" />
                        <span className="flex-1 truncate text-surface-800">{att.original_name}</span>
                        <span className="text-xs text-surface-700">{formatFileSize(att.size)}</span>
                        <a href={`/api/uploads/${att.id}`}
                          className="p-1 rounded hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                          title="Download">
                          <Download className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Meta */}
              <div className="text-[11px] text-surface-700 pt-2 border-t border-surface-300/20">
                Created {formatDate(taskDetail.created_at)}
                {taskDetail.updated_at && taskDetail.updated_at !== taskDetail.created_at && (
                  <span> &middot; Updated {formatDate(taskDetail.updated_at)}</span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Note detail modal */}
      {(noteDetail || noteDetailLoading) && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          {noteDetailLoading ? (
            <div className="card p-8 animate-scale-in">
              <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
            </div>
          ) : noteDetail && (
            <div ref={noteDetailRef} className="card w-full max-w-lg p-6 animate-scale-in max-h-[85vh] overflow-y-auto"
              style={noteDetail.color ? { borderTop: `3px solid ${noteDetail.color}` } : undefined}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1 min-w-0">
                  <h2 className="text-lg font-semibold text-white">{noteDetail.title}</h2>
                </div>
                <div className="flex items-center gap-1 flex-shrink-0">
                  <button
                    onClick={() => { setNoteDetail(null); router.push(`/notes/${noteDetail.id}`) }}
                    className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700 hover:text-brand-400 transition-colors"
                    title="Edit note"
                  >
                    <Pencil className="w-4 h-4" />
                  </button>
                  <button onClick={() => setNoteDetail(null)} className="p-1.5 rounded-lg hover:bg-surface-300/30 text-surface-700 transition-colors">
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>

              {noteDetail.tags.length > 0 && (
                <div className="mb-4">
                  <div className="flex flex-wrap gap-1.5">
                    {noteDetail.tags.map(tag => (
                      <span key={tag.id} className="badge gap-1" style={{
                        backgroundColor: tag.color + '18',
                        color: tag.color,
                        border: `1px solid ${tag.color}25`,
                      }}>
                        <Hash className="w-3 h-3" />
                        {tag.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {noteDetail.content && (
                <div className="mb-4">
                  <div
                    className="text-sm text-surface-800 bg-surface-200/40 rounded-xl p-3 rich-editor-content prose-sm"
                    dangerouslySetInnerHTML={{ __html: noteDetail.content }}
                  />
                </div>
              )}

              {noteDetail.linked_tasks.length > 0 && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-surface-800 mb-1.5 block">
                    <Link2 className="w-3 h-3 inline mr-1" />
                    Linked Tasks ({noteDetail.linked_tasks.length})
                  </label>
                  <div className="space-y-1.5">
                    {noteDetail.linked_tasks.map(task => (
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
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {noteDetail.attachments.length > 0 && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-surface-800 mb-1.5 block">
                    <Paperclip className="w-3 h-3 inline mr-1" />
                    Attachments ({noteDetail.attachments.length})
                  </label>
                  <div className="space-y-1.5">
                    {noteDetail.attachments.map(att => (
                      <div key={att.id} className="flex items-center gap-2 bg-surface-200/40 rounded-lg p-2 text-sm">
                        <FileText className="w-4 h-4 text-surface-700 flex-shrink-0" />
                        <span className="flex-1 truncate text-surface-800">{att.original_name}</span>
                        <span className="text-xs text-surface-700">{formatFileSize(att.size)}</span>
                        <a href={`/api/note-uploads/${att.id}`}
                          className="p-1 rounded hover:bg-surface-300/40 text-surface-700 hover:text-brand-400 transition-colors"
                          title="Download">
                          <Download className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="text-[11px] text-surface-700 pt-2 border-t border-surface-300/20">
                Created {formatDate(noteDetail.created_at)}
                {noteDetail.updated_at && noteDetail.updated_at !== noteDetail.created_at && (
                  <span> &middot; Updated {formatDate(noteDetail.updated_at)}</span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Task edit modal */}
      {editingTask && (
        <TaskForm
          task={editingTask}
          categories={categories}
          onSubmit={handleEditSubmit}
          onCancel={() => setEditingTask(null)}
          onDeleteAttachment={handleDeleteAttachment}
          onFilesUploaded={() => fetchItems()}
        />
      )}

      {/* Day click popup */}
      {dayPopup && (
        <div
          ref={popupRef}
          className="fixed z-[60] bg-surface-100 border border-surface-300/40 rounded-xl shadow-2xl overflow-hidden min-w-[180px] animate-scale-in"
          style={{
            left: Math.min(dayPopup.x - 90, window.innerWidth - 200),
            top: Math.min(dayPopup.y, window.innerHeight - 120),
          }}
        >
          <div className="px-3 py-2 border-b border-surface-300/20">
            <p className="text-[11px] font-semibold text-surface-700">{formatDate(dayPopup.date)}</p>
          </div>
          <button
            onClick={() => handleCreateTaskForDate(dayPopup.date)}
            className="flex items-center gap-2.5 w-full px-4 py-3 text-sm hover:bg-surface-300/30 transition-colors text-surface-900"
          >
            <CheckSquare className="w-4 h-4 text-brand-400" /> New Task
          </button>
          <button
            onClick={handleCreateNoteForDate}
            className="flex items-center gap-2.5 w-full px-4 py-3 text-sm hover:bg-surface-300/30 transition-colors text-surface-900"
          >
            <FileText className="w-4 h-4 text-accent-purple" /> New Note
          </button>
        </div>
      )}
    </div>
  )
}

'use client'

import { useState, useEffect, useCallback, useMemo } from 'react'
import { useRouter } from 'next/navigation'
import {
  ChevronLeft, ChevronRight, Plus, Filter, Search,
  CalendarDays, CalendarRange, Calendar as CalendarIcon, Grid3X3,
  CheckSquare, FileText, Loader2, X,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import type { Category, Status, Tag } from '@/types'

type ViewMode = 'day' | 'week' | 'month' | 'year'

interface CalendarItem {
  date: string
  type: 'task' | 'note'
  id: string
  title: string
  color: string
  status_name?: string
  is_completed?: boolean
  progress?: number
  category_name?: string
  category_color?: string
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

  // Calculate date range for current view
  const dateRange = useMemo(() => {
    const y = currentDate.getFullYear()
    const m = currentDate.getMonth()
    const d = currentDate.getDate()

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
      // Extend to fill calendar grid
      const gridStart = getMonday(first)
      const gridEnd = new Date(last)
      const endDay = gridEnd.getDay()
      if (endDay !== 0) gridEnd.setDate(gridEnd.getDate() + (7 - endDay))
      return { from: toDateStr(gridStart), to: toDateStr(gridEnd) }
    }
    // Year
    return { from: `${y}-01-01`, to: `${y}-12-31` }
  }, [currentDate, view])

  const fetchItems = useCallback(async () => {
    setLoading(true)
    const params = new URLSearchParams({
      date_from: dateRange.from,
      date_to: dateRange.to,
    })
    if (filterCategory) params.set('category_id', filterCategory)
    if (filterStatus) params.set('status_id', filterStatus)
    if (filterTag) params.set('tag', filterTag)
    if (filterType !== 'all') params.set('types', filterType)

    const res = await fetch(`/api/calendar?${params}`)
    const data = await res.json()
    setItems(data.items || [])
    setLoading(false)
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

  // Group items by date
  const itemsByDate = useMemo(() => {
    const map: Record<string, CalendarItem[]> = {}
    for (const item of items) {
      const d = item.date.split('T')[0] || item.date.split(' ')[0]
      if (!map[d]) map[d] = []
      map[d].push(item)
    }
    return map
  }, [items])

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

  const handleItemClick = (item: CalendarItem) => {
    if (item.type === 'note') router.push(`/notes/${item.id}`)
  }

  const handleCreateTask = () => {
    // Navigate to tasks page — task form will auto-fill due_date from URL param
    const dateStr = toDateStr(currentDate)
    router.push(`/?new_task=1&date=${dateStr}`)
    setShowCreateMenu(false)
  }

  const handleCreateNote = async () => {
    const res = await fetch('/api/notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'Untitled Note', content: '' }),
    })
    const { id } = await res.json()
    router.push(`/notes/${id}`)
    setShowCreateMenu(false)
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

  // View buttons
  const viewButtons: { id: ViewMode; icon: React.ReactNode; label: string }[] = [
    { id: 'day', icon: <CalendarDays className="w-3.5 h-3.5" />, label: 'Day' },
    { id: 'week', icon: <CalendarRange className="w-3.5 h-3.5" />, label: 'Week' },
    { id: 'month', icon: <CalendarIcon className="w-3.5 h-3.5" />, label: 'Month' },
    { id: 'year', icon: <Grid3X3 className="w-3.5 h-3.5" />, label: 'Year' },
  ]

  const ItemPill = ({ item }: { item: CalendarItem }) => (
    <button
      onClick={() => handleItemClick(item)}
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
      // Stop if we've passed the month and filled the row
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
            const dayItems = itemsByDate[ds] || []
            const isCurrentMonth = date.getMonth() === m
            const isToday = isSameDay(date, today)
            return (
              <div
                key={idx}
                className={cn(
                  'min-h-[100px] border-b border-r border-surface-300/10 p-1.5 transition-colors',
                  !isCurrentMonth && 'bg-surface-50/30',
                  isToday && 'bg-brand-600/8',
                )}
              >
                <div className={cn(
                  'text-xs font-medium mb-1 w-6 h-6 flex items-center justify-center rounded-full',
                  isToday ? 'bg-brand-600 text-white' : isCurrentMonth ? 'text-surface-900' : 'text-surface-600',
                )}>
                  {date.getDate()}
                </div>
                <div className="space-y-0.5">
                  {dayItems.slice(0, 3).map(item => (
                    <ItemPill key={`${item.type}-${item.id}`} item={item} />
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
          const dayItems = itemsByDate[ds] || []
          const isToday = isSameDay(date, today)
          return (
            <div key={ds} className={cn('card p-3 min-h-[300px]', isToday && 'ring-2 ring-brand-500/30')}>
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
                {dayItems.map(item => (
                  <button
                    key={`${item.type}-${item.id}`}
                    onClick={() => handleItemClick(item)}
                    className={cn(
                      'w-full text-left p-2 rounded-lg text-xs transition-colors',
                      item.type === 'task' ? 'bg-surface-200/40 hover:bg-surface-200/70' : 'bg-accent-purple/8 hover:bg-accent-purple/15',
                      item.is_completed && 'opacity-50',
                    )}
                  >
                    <div className="flex items-center gap-1.5 mb-0.5">
                      {item.type === 'task' ? (
                        <CheckSquare className="w-3 h-3 flex-shrink-0" style={{ color: item.color }} />
                      ) : (
                        <FileText className="w-3 h-3 flex-shrink-0 text-accent-purple" />
                      )}
                      <span className={cn('font-medium truncate text-surface-950', item.is_completed && 'line-through text-surface-700')}>
                        {item.title}
                      </span>
                    </div>
                    {item.status_name && (
                      <span className="text-[10px] font-medium" style={{ color: item.color }}>{item.status_name}</span>
                    )}
                    {item.category_name && (
                      <span className="text-[10px] ml-1" style={{ color: item.category_color }}>{item.category_name}</span>
                    )}
                  </button>
                ))}
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
    const dayItems = itemsByDate[ds] || []
    const taskItems = dayItems.filter(i => i.type === 'task')
    const noteItems = dayItems.filter(i => i.type === 'note')
    const isToday = isSameDay(currentDate, today)

    return (
      <div className="max-w-2xl mx-auto space-y-4">
        <div className={cn('card p-6 text-center', isToday && 'ring-2 ring-brand-500/30')}>
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
              {taskItems.map(item => (
                <div key={item.id} className={cn(
                  'flex items-center gap-3 p-3 rounded-xl bg-surface-200/40 transition-colors hover:bg-surface-200/70',
                  item.is_completed && 'opacity-50',
                )}>
                  <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: item.color }} />
                  <div className="flex-1 min-w-0">
                    <p className={cn('text-sm font-medium text-surface-950 truncate', item.is_completed && 'line-through text-surface-700')}>
                      {item.title}
                    </p>
                    <div className="flex items-center gap-2 mt-0.5">
                      {item.status_name && <span className="text-[10px] font-medium" style={{ color: item.color }}>{item.status_name}</span>}
                      {item.category_name && <span className="text-[10px]" style={{ color: item.category_color }}>{item.category_name}</span>}
                      {item.progress != null && item.progress > 0 && !item.is_completed && (
                        <span className="text-[10px] text-surface-700">{item.progress}%</span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
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
          const daysInMonth = new Date(y, m + 1, 0).getDate()
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
                  const hasItems = !!itemsByDate[ds]?.length
                  const isThisMonth = date.getMonth() === m
                  const isToday2 = isSameDay(date, today)
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
                        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-1 h-1 rounded-full bg-brand-400" />
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
        <div className="relative">
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
    </div>
  )
}

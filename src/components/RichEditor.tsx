'use client'

import { useEditor, EditorContent } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'
import { Table } from '@tiptap/extension-table'
import TableRow from '@tiptap/extension-table-row'
import TableCell from '@tiptap/extension-table-cell'
import TableHeader from '@tiptap/extension-table-header'
import Image from '@tiptap/extension-image'
import { TextStyle } from '@tiptap/extension-text-style'
import Color from '@tiptap/extension-color'
import TextAlign from '@tiptap/extension-text-align'
import Underline from '@tiptap/extension-underline'
import Link from '@tiptap/extension-link'
import Highlight from '@tiptap/extension-highlight'
import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Bold, Italic, Underline as UnderlineIcon, Strikethrough, Code,
  Heading1, Heading2, Heading3, List, ListOrdered,
  Quote, Minus, ImagePlus, Link as LinkIcon, Unlink,
  Table as TableIcon, TableCellsMerge, Trash2,
  AlignLeft, AlignCenter, AlignRight, AlignJustify,
  Highlighter, Palette, Paintbrush, Undo2, Redo2,
  Plus, ArrowDown, ArrowUp, ArrowLeft, ArrowRight, X, Settings2,
} from 'lucide-react'
import { cn } from '@/lib/utils'

const TEXT_COLORS = [
  '#ffffff', '#94a3c4', '#ef4444', '#f97316', '#f59e0b', '#22c55e',
  '#14b8a6', '#06b6d4', '#3b82f6', '#6366f1', '#8b5cf6', '#ec4899',
]

const HIGHLIGHT_COLORS = [
  '#00000000', '#fef08a80', '#bbf7d080', '#bae6fd80',
  '#c4b5fd80', '#fecdd380', '#fde68a80', '#d9f99d80',
]

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

interface RichEditorProps {
  content: string
  onChange: (html: string) => void
  noteId?: string
  editable?: boolean
  noteColor?: string
  onNoteColorChange?: (color: string) => void
}

export function RichEditor({ content, onChange, noteId, editable = true, noteColor, onNoteColorChange }: RichEditorProps) {
  const [showTableModal, setShowTableModal] = useState(false)
  const [showTableAttrModal, setShowTableAttrModal] = useState(false)
  const [tableRows, setTableRows] = useState(3)
  const [tableCols, setTableCols] = useState(3)
  const [showLinkInput, setShowLinkInput] = useState(false)
  const [linkUrl, setLinkUrl] = useState('')
  const [showColorPicker, setShowColorPicker] = useState(false)
  const [showHighlightPicker, setShowHighlightPicker] = useState(false)
  const [showNoteColorPicker, setShowNoteColorPicker] = useState(false)
  const [tableAttr, setTableAttr] = useState({
    borderWidth: '1',
    borderColor: '#4a5a8a',
    cellPadding: '8',
    width: '100',
  })
  const fileInputRef = useRef<HTMLInputElement>(null)
  const colorPickerRef = useRef<HTMLDivElement>(null)
  const highlightPickerRef = useRef<HTMLDivElement>(null)
  const noteColorPickerRef = useRef<HTMLDivElement>(null)
  const linkInputRef = useRef<HTMLDivElement>(null)
  const tableModalRef = useRef<HTMLDivElement>(null)
  const tableAttrRef = useRef<HTMLDivElement>(null)

  const closeAllMenus = useCallback(() => {
    setShowColorPicker(false)
    setShowHighlightPicker(false)
    setShowNoteColorPicker(false)
    setShowLinkInput(false)
    setShowTableModal(false)
  }, [])

  // ESC to close any open menu or table attr modal
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (showTableAttrModal) { setShowTableAttrModal(false); return }
        if (showColorPicker || showHighlightPicker || showNoteColorPicker || showLinkInput || showTableModal) {
          closeAllMenus()
        }
      }
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [showColorPicker, showHighlightPicker, showNoteColorPicker, showLinkInput, showTableModal, showTableAttrModal, closeAllMenus])

  // Click outside to close toolbar dropdowns
  useEffect(() => {
    if (!showColorPicker && !showHighlightPicker && !showNoteColorPicker && !showLinkInput && !showTableModal) return
    const handler = (e: MouseEvent) => {
      const target = e.target as Node
      if (showColorPicker && colorPickerRef.current && !colorPickerRef.current.contains(target)) setShowColorPicker(false)
      if (showHighlightPicker && highlightPickerRef.current && !highlightPickerRef.current.contains(target)) setShowHighlightPicker(false)
      if (showNoteColorPicker && noteColorPickerRef.current && !noteColorPickerRef.current.contains(target)) setShowNoteColorPicker(false)
      if (showLinkInput && linkInputRef.current && !linkInputRef.current.contains(target)) setShowLinkInput(false)
      if (showTableModal && tableModalRef.current && !tableModalRef.current.contains(target)) setShowTableModal(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showColorPicker, showHighlightPicker, showNoteColorPicker, showLinkInput, showTableModal])

  // Click outside to close table attr modal
  useEffect(() => {
    if (!showTableAttrModal) return
    const handler = (e: MouseEvent) => {
      if (tableAttrRef.current && !tableAttrRef.current.contains(e.target as Node)) setShowTableAttrModal(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showTableAttrModal])

  const editor = useEditor({
    extensions: [
      StarterKit.configure({
        heading: { levels: [1, 2, 3] },
      }),
      Table.configure({
        resizable: true,
        HTMLAttributes: {
          class: 'editor-table',
        },
      }),
      TableRow,
      TableCell,
      TableHeader,
      Image.configure({
        HTMLAttributes: {
          class: 'editor-image',
        },
      }),
      TextStyle,
      Color,
      TextAlign.configure({
        types: ['heading', 'paragraph'],
      }),
      Underline,
      Link.configure({
        openOnClick: false,
        HTMLAttributes: {
          class: 'editor-link',
        },
      }),
      Highlight.configure({
        multicolor: true,
      }),
    ],
    content,
    editable,
    onUpdate: ({ editor }) => {
      onChange(editor.getHTML())
    },
    editorProps: {
      attributes: {
        class: 'rich-editor-content',
      },
    },
  })

  const handleImageUpload = useCallback(async (file: File) => {
    if (!editor) return
    const formData = new FormData()
    formData.append('file', file)
    if (noteId) formData.append('note_id', noteId)

    const res = await fetch('/api/editor-upload', { method: 'POST', body: formData })
    if (res.ok) {
      const { url } = await res.json()
      editor.chain().focus().setImage({ src: url }).run()
    }
  }, [editor, noteId])

  const handleImageClick = () => {
    fileInputRef.current?.click()
  }

  const addLink = () => {
    if (!editor || !linkUrl) return
    editor.chain().focus().extendMarkRange('link').setLink({ href: linkUrl }).run()
    setShowLinkInput(false)
    setLinkUrl('')
  }

  const insertTable = () => {
    if (!editor) return
    editor.chain().focus().insertTable({
      rows: tableRows,
      cols: tableCols,
      withHeaderRow: true,
    }).run()
    setShowTableModal(false)
  }

  const applyTableAttributes = () => {
    if (!editor) return
    // Apply via CSS custom properties on the table element
    const { borderWidth, borderColor, cellPadding, width } = tableAttr
    const style = `--table-border-width: ${borderWidth}px; --table-border-color: ${borderColor}; --table-cell-padding: ${cellPadding}px; --table-width: ${width}%;`
    editor.chain().focus().updateAttributes('table', {
      style,
    }).run()
    setShowTableAttrModal(false)
  }

  if (!editor) return null

  const ToolbarButton = ({
    onClick,
    active,
    disabled,
    children,
    title,
  }: {
    onClick: () => void
    active?: boolean
    disabled?: boolean
    children: React.ReactNode
    title: string
  }) => (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={cn(
        'p-1.5 rounded-md transition-colors',
        active
          ? 'bg-brand-600/20 text-brand-400'
          : 'text-surface-700 hover:bg-surface-300/30 hover:text-surface-900',
        disabled && 'opacity-30 cursor-not-allowed'
      )}
    >
      {children}
    </button>
  )

  const Separator = () => <div className="w-px h-5 bg-surface-400/20 mx-0.5" />

  return (
    <div className="border border-surface-300/30 rounded-xl overflow-hidden bg-surface-100/60">
      {/* Toolbar */}
      {editable && (
        <div className="flex flex-wrap items-center gap-0.5 px-2 py-1.5 border-b border-surface-300/20 bg-surface-50/80">
          {/* Undo/Redo */}
          <ToolbarButton onClick={() => editor.chain().focus().undo().run()} disabled={!editor.can().undo()} title="Undo">
            <Undo2 className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().redo().run()} disabled={!editor.can().redo()} title="Redo">
            <Redo2 className="w-3.5 h-3.5" />
          </ToolbarButton>

          <Separator />

          {/* Text formatting */}
          <ToolbarButton onClick={() => editor.chain().focus().toggleBold().run()} active={editor.isActive('bold')} title="Bold">
            <Bold className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().toggleItalic().run()} active={editor.isActive('italic')} title="Italic">
            <Italic className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().toggleUnderline().run()} active={editor.isActive('underline')} title="Underline">
            <UnderlineIcon className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().toggleStrike().run()} active={editor.isActive('strike')} title="Strikethrough">
            <Strikethrough className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().toggleCode().run()} active={editor.isActive('code')} title="Code">
            <Code className="w-3.5 h-3.5" />
          </ToolbarButton>

          <Separator />

          {/* Text color */}
          <div className="relative" ref={colorPickerRef}>
            <ToolbarButton onClick={() => { setShowColorPicker(!showColorPicker); setShowHighlightPicker(false) }} title="Text Color">
              <Palette className="w-3.5 h-3.5" />
            </ToolbarButton>
            {showColorPicker && (
              <div className="absolute top-full left-0 mt-1 p-2.5 bg-surface-100 border border-surface-300/40 rounded-xl shadow-xl z-50 grid grid-cols-6 gap-2">
                {TEXT_COLORS.map(c => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => { editor.chain().focus().setColor(c).run(); setShowColorPicker(false) }}
                    className="w-8 h-8 rounded-lg border border-surface-400/30 hover:scale-110 transition-transform"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Highlight */}
          <div className="relative" ref={highlightPickerRef}>
            <ToolbarButton onClick={() => { setShowHighlightPicker(!showHighlightPicker); setShowColorPicker(false) }} active={editor.isActive('highlight')} title="Highlight">
              <Highlighter className="w-3.5 h-3.5" />
            </ToolbarButton>
            {showHighlightPicker && (
              <div className="absolute top-full left-0 mt-1 p-2.5 bg-surface-100 border border-surface-300/40 rounded-xl shadow-xl z-50 grid grid-cols-4 gap-2">
                {HIGHLIGHT_COLORS.map((c, i) => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => {
                      if (i === 0) editor.chain().focus().unsetHighlight().run()
                      else editor.chain().focus().toggleHighlight({ color: c }).run()
                      setShowHighlightPicker(false)
                    }}
                    className={cn(
                      'w-8 h-8 rounded-lg border border-surface-400/30 hover:scale-110 transition-transform',
                      i === 0 && 'flex items-center justify-center'
                    )}
                    style={i > 0 ? { backgroundColor: c } : {}}
                    title={i === 0 ? 'Remove highlight' : undefined}
                  >
                    {i === 0 && <X className="w-3.5 h-3.5 text-surface-700" />}
                  </button>
                ))}
              </div>
            )}
          </div>

          <Separator />

          {/* Headings */}
          <ToolbarButton onClick={() => editor.chain().focus().toggleHeading({ level: 1 }).run()} active={editor.isActive('heading', { level: 1 })} title="Heading 1">
            <Heading1 className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().toggleHeading({ level: 2 }).run()} active={editor.isActive('heading', { level: 2 })} title="Heading 2">
            <Heading2 className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().toggleHeading({ level: 3 }).run()} active={editor.isActive('heading', { level: 3 })} title="Heading 3">
            <Heading3 className="w-3.5 h-3.5" />
          </ToolbarButton>

          <Separator />

          {/* Alignment */}
          <ToolbarButton onClick={() => editor.chain().focus().setTextAlign('left').run()} active={editor.isActive({ textAlign: 'left' })} title="Align Left">
            <AlignLeft className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().setTextAlign('center').run()} active={editor.isActive({ textAlign: 'center' })} title="Align Center">
            <AlignCenter className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().setTextAlign('right').run()} active={editor.isActive({ textAlign: 'right' })} title="Align Right">
            <AlignRight className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().setTextAlign('justify').run()} active={editor.isActive({ textAlign: 'justify' })} title="Justify">
            <AlignJustify className="w-3.5 h-3.5" />
          </ToolbarButton>

          <Separator />

          {/* Lists */}
          <ToolbarButton onClick={() => editor.chain().focus().toggleBulletList().run()} active={editor.isActive('bulletList')} title="Bullet List">
            <List className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().toggleOrderedList().run()} active={editor.isActive('orderedList')} title="Numbered List">
            <ListOrdered className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().toggleBlockquote().run()} active={editor.isActive('blockquote')} title="Quote">
            <Quote className="w-3.5 h-3.5" />
          </ToolbarButton>
          <ToolbarButton onClick={() => editor.chain().focus().setHorizontalRule().run()} title="Horizontal Rule">
            <Minus className="w-3.5 h-3.5" />
          </ToolbarButton>

          <Separator />

          {/* Link */}
          <div className="relative" ref={linkInputRef}>
            <ToolbarButton
              onClick={() => {
                if (editor.isActive('link')) {
                  editor.chain().focus().unsetLink().run()
                } else {
                  setShowLinkInput(!showLinkInput)
                }
              }}
              active={editor.isActive('link')}
              title={editor.isActive('link') ? 'Remove Link' : 'Add Link'}
            >
              {editor.isActive('link') ? <Unlink className="w-3.5 h-3.5" /> : <LinkIcon className="w-3.5 h-3.5" />}
            </ToolbarButton>
            {showLinkInput && (
              <div className="absolute top-full left-0 mt-1 flex gap-1 bg-surface-100 border border-surface-300/40 rounded-lg shadow-xl z-50 p-2">
                <input
                  type="url"
                  value={linkUrl}
                  onChange={e => setLinkUrl(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') addLink() }}
                  placeholder="https://..."
                  className="input-base text-xs w-48"
                  autoFocus
                />
                <button type="button" onClick={addLink} className="btn-primary text-xs px-2 py-1">Add</button>
                <button type="button" onClick={() => setShowLinkInput(false)} className="btn-ghost text-xs px-2 py-1">
                  <X className="w-3 h-3" />
                </button>
              </div>
            )}
          </div>

          {/* Image */}
          <ToolbarButton onClick={handleImageClick} title="Insert Image">
            <ImagePlus className="w-3.5 h-3.5" />
          </ToolbarButton>
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            className="hidden"
            onChange={e => {
              const file = e.target.files?.[0]
              if (file) handleImageUpload(file)
              e.target.value = ''
            }}
          />

          <Separator />

          {/* Table */}
          <div className="relative" ref={tableModalRef}>
            <ToolbarButton onClick={() => setShowTableModal(!showTableModal)} active={editor.isActive('table')} title="Insert Table">
              <TableIcon className="w-3.5 h-3.5" />
            </ToolbarButton>
            {showTableModal && (
              <div className="absolute top-full left-0 mt-1 bg-surface-100 border border-surface-300/40 rounded-lg shadow-xl z-50 p-3 w-48">
                <p className="text-xs font-medium text-surface-800 mb-2">Insert Table</p>
                <div className="grid grid-cols-2 gap-2 mb-2">
                  <div>
                    <label className="text-[10px] text-surface-700">Rows</label>
                    <input type="number" min="1" max="20" value={tableRows} onChange={e => setTableRows(parseInt(e.target.value) || 1)}
                      className="input-base text-xs" />
                  </div>
                  <div>
                    <label className="text-[10px] text-surface-700">Cols</label>
                    <input type="number" min="1" max="10" value={tableCols} onChange={e => setTableCols(parseInt(e.target.value) || 1)}
                      className="input-base text-xs" />
                  </div>
                </div>
                <button type="button" onClick={insertTable} className="btn-primary text-xs w-full py-1.5">Insert</button>
              </div>
            )}
          </div>

          {/* Card color (note accent) */}
          {onNoteColorChange && (
            <>
              <Separator />
              <div className="relative" ref={noteColorPickerRef}>
                <ToolbarButton
                  onClick={() => { setShowNoteColorPicker(!showNoteColorPicker); setShowColorPicker(false); setShowHighlightPicker(false) }}
                  title="Card Color"
                >
                  {noteColor ? (
                    <div className="w-3.5 h-3.5 rounded-full border border-surface-400/30" style={{ backgroundColor: noteColor }} />
                  ) : (
                    <Paintbrush className="w-3.5 h-3.5" />
                  )}
                </ToolbarButton>
                {showNoteColorPicker && (
                  <div className="absolute bottom-full left-0 mb-1 p-2.5 bg-surface-100 border border-surface-300/40 rounded-xl shadow-xl z-50 min-w-[200px] animate-scale-in">
                    <p className="text-[10px] font-semibold text-surface-700 uppercase tracking-wider mb-2 px-0.5">Card Color</p>
                    <div className="grid grid-cols-6 gap-2">
                      {NOTE_COLORS.map(c => (
                        <button
                          key={c.value || 'none'}
                          type="button"
                          onClick={() => { onNoteColorChange(c.value); setShowNoteColorPicker(false) }}
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
            </>
          )}

          {/* Table operations (when inside table) */}
          {editor.isActive('table') && (
            <>
              <ToolbarButton onClick={() => editor.chain().focus().addColumnAfter().run()} title="Add Column Right">
                <div className="flex items-center"><ArrowRight className="w-3 h-3" /><Plus className="w-2.5 h-2.5 -ml-0.5" /></div>
              </ToolbarButton>
              <ToolbarButton onClick={() => editor.chain().focus().addColumnBefore().run()} title="Add Column Left">
                <div className="flex items-center"><ArrowLeft className="w-3 h-3" /><Plus className="w-2.5 h-2.5 -ml-0.5" /></div>
              </ToolbarButton>
              <ToolbarButton onClick={() => editor.chain().focus().addRowAfter().run()} title="Add Row Below">
                <div className="flex items-center"><ArrowDown className="w-3 h-3" /><Plus className="w-2.5 h-2.5 -ml-0.5" /></div>
              </ToolbarButton>
              <ToolbarButton onClick={() => editor.chain().focus().addRowBefore().run()} title="Add Row Above">
                <div className="flex items-center"><ArrowUp className="w-3 h-3" /><Plus className="w-2.5 h-2.5 -ml-0.5" /></div>
              </ToolbarButton>
              <ToolbarButton onClick={() => editor.chain().focus().deleteColumn().run()} title="Delete Column">
                <div className="flex items-center text-accent-red"><TableCellsMerge className="w-3.5 h-3.5" /></div>
              </ToolbarButton>
              <ToolbarButton onClick={() => editor.chain().focus().deleteRow().run()} title="Delete Row">
                <div className="flex items-center text-accent-red"><Minus className="w-3.5 h-3.5" /></div>
              </ToolbarButton>
              <ToolbarButton onClick={() => editor.chain().focus().deleteTable().run()} title="Delete Table">
                <Trash2 className="w-3.5 h-3.5 text-accent-red" />
              </ToolbarButton>
              <ToolbarButton onClick={() => setShowTableAttrModal(true)} title="Table Settings">
                <Settings2 className="w-3.5 h-3.5" />
              </ToolbarButton>
            </>
          )}
        </div>
      )}

      {/* Editor */}
      <EditorContent editor={editor} className="min-h-[300px]" />

      {/* Table attributes modal */}
      {showTableAttrModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div ref={tableAttrRef} className="card w-full max-w-sm p-5 animate-scale-in">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-white">Table Settings</h3>
              <button type="button" onClick={() => setShowTableAttrModal(false)} className="p-1 rounded hover:bg-surface-300/30 text-surface-700">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-xs font-medium text-surface-800 mb-1 block">Border Width (px)</label>
                <input type="number" min="0" max="10" value={tableAttr.borderWidth}
                  onChange={e => setTableAttr(p => ({ ...p, borderWidth: e.target.value }))}
                  className="input-base text-sm" />
              </div>
              <div>
                <label className="text-xs font-medium text-surface-800 mb-1 block">Border Color</label>
                <div className="flex gap-2">
                  <input type="color" value={tableAttr.borderColor}
                    onChange={e => setTableAttr(p => ({ ...p, borderColor: e.target.value }))}
                    className="w-8 h-8 rounded cursor-pointer" />
                  <input type="text" value={tableAttr.borderColor}
                    onChange={e => setTableAttr(p => ({ ...p, borderColor: e.target.value }))}
                    className="input-base text-sm flex-1" />
                </div>
              </div>
              <div>
                <label className="text-xs font-medium text-surface-800 mb-1 block">Cell Padding (px)</label>
                <input type="number" min="0" max="30" value={tableAttr.cellPadding}
                  onChange={e => setTableAttr(p => ({ ...p, cellPadding: e.target.value }))}
                  className="input-base text-sm" />
              </div>
              <div>
                <label className="text-xs font-medium text-surface-800 mb-1 block">Width (%)</label>
                <input type="number" min="10" max="100" value={tableAttr.width}
                  onChange={e => setTableAttr(p => ({ ...p, width: e.target.value }))}
                  className="input-base text-sm" />
              </div>
            </div>
            <div className="flex gap-2 mt-4">
              <button type="button" onClick={() => setShowTableAttrModal(false)} className="btn-secondary flex-1 text-sm">Cancel</button>
              <button type="button" onClick={applyTableAttributes} className="btn-primary flex-1 text-sm">Apply</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

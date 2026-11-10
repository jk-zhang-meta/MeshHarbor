// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-90 P1f — a tool call's view is built only from fields of the types its
// tool documents; anything else falls back to JSON.
import { describe, expect, it } from 'vitest'
import { resultMode, toolView, WRITE_HEAD } from '@/utils/toolView'

describe('toolView (FR-90 P1f)', () => {
  it('shows a command line, with what it is for', () => {
    expect(toolView('Bash', { command: 'ls -la', description: 'List files', run_in_background: true })).toEqual({
      kind: 'bash',
      command: 'ls -la',
      description: 'List files',
      background: true,
    })
  })

  it('shows an edit as a diff, and every edit of a MultiEdit', () => {
    const v = toolView('Edit', { file_path: '/w/a.rs', old_string: 'let x = 1;', new_string: 'let x = 2;' })
    expect(v.kind).toBe('edit')
    if (v.kind !== 'edit') return
    expect(v.path).toBe('/w/a.rs')
    expect(v.changes[0].rows?.map((r) => r.kind)).toEqual(['del', 'add'])
    const m = toolView('MultiEdit', {
      file_path: '/w/b.rs',
      edits: [
        { old_string: 'a', new_string: 'b' },
        { old_string: 'c', new_string: 'd', replace_all: true },
      ],
    })
    expect(m.kind === 'edit' && m.changes.map((c) => c.all)).toEqual([false, true])
  })

  it("shows a new file's first lines and how many there are", () => {
    const content = Array.from({ length: WRITE_HEAD + 5 }, (_, i) => `line ${i}`).join('\n') + '\n'
    const v = toolView('Write', { file_path: '/w/new.txt', content })
    expect(v.kind === 'write' && [v.head.length, v.total]).toEqual([WRITE_HEAD, WRITE_HEAD + 5])
  })

  it('reads a file range as lines from offset to offset + limit - 1', () => {
    expect(toolView('Read', { file_path: '/w/a', offset: 10, limit: 5 })).toEqual({ kind: 'read', path: '/w/a', from: 10, to: 14 })
    expect(toolView('Read', { file_path: '/w/a', limit: 5 })).toEqual({ kind: 'read', path: '/w/a', from: 1, to: 5 })
    expect(toolView('Read', { file_path: '/w/a' })).toEqual({ kind: 'read', path: '/w/a', from: undefined, to: undefined })
  })

  it('shows a to-do list, an unknown status read as to do', () => {
    const v = toolView('TodoWrite', {
      todos: [
        { content: 'one', status: 'completed', activeForm: 'Doing one' },
        { content: 'two', status: 'in_progress' },
        { content: 'three', status: 'blocked' },
      ],
    })
    expect(v.kind === 'todos' && v.items.map((i) => i.status)).toEqual(['completed', 'in_progress', 'pending'])
  })

  it('falls back to JSON for a field of the wrong type, an unknown tool, or no object', () => {
    expect(toolView('Edit', { file_path: '/w/a', old_string: 1, new_string: 'x' }).kind).toBe('json')
    expect(toolView('Bash', { command: ['rm', '-rf'] }).kind).toBe('json')
    expect(toolView('TodoWrite', { todos: [{ content: 'ok' }, 'not a todo'] }).kind).toBe('json')
    expect(toolView('mcp__meshharbor__approve', { a: 1 })).toEqual({ kind: 'json', text: '{\n  "a": 1\n}' })
    expect(toolView('Bash', 'ls').kind).toBe('json')
  })

  it('shows a result in full, folded, as one line or not at all — a failure always in full', () => {
    expect(resultMode('Bash', true)).toBe('output')
    expect(resultMode('Read', true)).toBe('folded')
    expect(resultMode('Edit', true)).toBe('line')
    expect(resultMode('TodoWrite', true)).toBe('hidden')
    expect(['Bash', 'Read', 'Edit', 'TodoWrite'].map((t) => resultMode(t, false))).toEqual(['output', 'output', 'output', 'output'])
  })
})

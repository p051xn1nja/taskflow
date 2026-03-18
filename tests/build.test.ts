import { describe, it, expect } from 'vitest'
import { execSync } from 'child_process'
import path from 'path'
import fs from 'fs'

const ROOT = path.resolve(__dirname, '..')

describe('Build checks', () => {
  it('TypeScript compiles without errors', () => {
    expect(() =>
      execSync('npx tsc --noEmit', { cwd: ROOT, timeout: 60000 })
    ).not.toThrow()
  }, 60000)

  it('required source files exist', () => {
    const requiredFiles = [
      'src/app/(app)/board/page.tsx',
      'src/app/(app)/layout.tsx',
      'src/app/api/tasks/route.ts',
      'src/app/api/tasks/[id]/route.ts',
      'src/app/api/categories/route.ts',
      'src/app/api/categories/[id]/route.ts',
      'src/components/Sidebar.tsx',
      'src/components/TaskForm.tsx',
      'src/lib/db.ts',
      'src/lib/auth.ts',
      'src/lib/api-helpers.ts',
      'src/lib/utils.ts',
      'src/types/index.ts',
      'src/middleware.ts',
    ]

    for (const file of requiredFiles) {
      expect(fs.existsSync(path.join(ROOT, file)), `Missing: ${file}`).toBe(true)
    }
  })

  it('package.json has required scripts', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf-8'))
    expect(pkg.scripts.dev).toBeDefined()
    expect(pkg.scripts.build).toBeDefined()
    expect(pkg.scripts.start).toBeDefined()
    expect(pkg.scripts.test).toBeDefined()
  })

  it('package.json has required dependencies', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf-8'))
    const deps = { ...pkg.dependencies, ...pkg.devDependencies }
    const required = ['next', 'react', 'better-sqlite3', 'next-auth', 'tailwindcss', 'typescript', 'vitest']
    for (const dep of required) {
      expect(deps[dep], `Missing dependency: ${dep}`).toBeDefined()
    }
  })
})

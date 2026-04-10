import { describe, it, expect, beforeEach } from 'vitest'
import { checkRateLimit, getClientIdentifier, __resetRateLimitBucketsForTests } from '@/lib/security'

beforeEach(() => {
  __resetRateLimitBucketsForTests()
})

describe('checkRateLimit', () => {
  it('blocks after reaching limit within window', () => {
    const key = 'unit:rate'
    expect(checkRateLimit(key, { limit: 2, windowMs: 10_000 }).allowed).toBe(true)
    expect(checkRateLimit(key, { limit: 2, windowMs: 10_000 }).allowed).toBe(true)
    expect(checkRateLimit(key, { limit: 2, windowMs: 10_000 }).allowed).toBe(false)
  })
})

describe('getClientIdentifier', () => {
  it('supports web Request/Headers objects', () => {
    const req = new Request('http://localhost', {
      headers: {
        'x-forwarded-for': '203.0.113.10, 10.0.0.1',
      },
    })
    const id = getClientIdentifier(req)
    expect(id).toMatch(/^[a-f0-9]{16}$/)
  })

  it('supports NextAuth-style plain header objects', () => {
    const req = {
      headers: {
        'x-forwarded-for': '198.51.100.22',
      },
    }
    const id = getClientIdentifier(req)
    expect(id).toMatch(/^[a-f0-9]{16}$/)
  })

  it('does not throw when headers are missing', () => {
    const id = getClientIdentifier({})
    expect(id).toMatch(/^[a-f0-9]{16}$/)
  })
})

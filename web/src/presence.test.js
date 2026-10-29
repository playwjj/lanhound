import { describe, expect, it } from 'vitest'
import { dayStrips, usualHours } from './presence'

const at = (y, mo, d, h, mi = 0) => new Date(y, mo - 1, d, h, mi).getTime()
const iso = (ms) => new Date(ms).toISOString()
const ONGOING = '0001-01-01T00:00:00Z'

describe('dayStrips', () => {
  it('splits a session across midnight and clips at now', () => {
    const now = at(2026, 10, 29, 12)
    const sessions = [{ start: iso(at(2026, 10, 28, 18)), end: ONGOING }]
    const days = dayStrips(sessions, now, 'en')
    expect(days).toHaveLength(7)
    const [yesterday, today] = days.slice(-2)
    expect(yesterday.segs).toHaveLength(1)
    expect(yesterday.segs[0].left).toBeCloseTo(75) // from 18:00
    expect(yesterday.segs[0].width).toBeCloseTo(25) // to midnight
    expect(today.segs[0].left).toBe(0)
    expect(today.segs[0].width).toBeCloseTo(50) // until noon, not beyond now
    expect(days[0].segs).toHaveLength(0)
  })
})

describe('usualHours', () => {
  const tip = (day, h, p) => `${day} ${h} ${p}%`

  it('only counts time since the device was first seen', () => {
    const now = at(2026, 10, 29, 12) // a Thursday
    const first = at(2026, 10, 29, 9)
    const sessions = [{ start: iso(at(2026, 10, 29, 9, 30)), end: iso(at(2026, 10, 29, 11)) }]
    const rows = usualHours(sessions, first, now, 'en', tip)
    const thu = rows[3]
    expect(thu.cells[8].value).toBeNull() // before first seen: not observed
    expect(thu.cells[9].value).toBeCloseTo(0.5) // 9:30–10:00 of 9:00–10:00
    expect(thu.cells[10].value).toBeCloseTo(1)
    expect(thu.cells[11].value).toBe(0) // observed, offline
    expect(thu.cells[11].tip).toBe(`${thu.label} 11 0%`)
    expect(rows[0].cells.every((c) => c.value === null)).toBe(true) // no Monday yet
  })
})

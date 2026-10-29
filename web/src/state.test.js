import { beforeEach, describe, expect, it, vi } from 'vitest'
import { handleMessage, state } from './state'

describe('event stream', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve([]) })))
    handleMessage({ type: 'snapshot', data: { devices: [{ id: 1, ip: '192.168.2.1', lastSeen: 'a' }], status: { baseline: true } } })
  })

  it('replaces everything on a snapshot', () => {
    expect(state.devices[1].ip).toBe('192.168.2.1')
    expect(state.connected).toBe(true)
  })

  it('applies device, seen and remove messages', () => {
    handleMessage({ type: 'device', data: { id: 2, ip: '192.168.2.2', lastSeen: 'x' } })
    handleMessage({ type: 'seen', data: { 1: 'b', 2: 'c', 99: 'ignored' } })
    expect(state.devices[1].lastSeen).toBe('b')
    expect(state.devices[2].lastSeen).toBe('c')
    expect(state.devices[99]).toBeUndefined()
    handleMessage({ type: 'remove', data: { id: 2 } })
    expect(state.devices[2]).toBeUndefined()
  })

  it('keeps alerts newest first, without duplicates', () => {
    state.alerts = []
    handleMessage({ type: 'alert', data: { id: 1 } })
    handleMessage({ type: 'alert', data: { id: 2 } })
    handleMessage({ type: 'alert', data: { id: 2 } })
    expect(state.alerts.map((a) => a.id)).toEqual([2, 1])
  })

  it('patches status sub-objects', () => {
    handleMessage({ type: 'baseline', data: false })
    handleMessage({ type: 'hass', data: { connected: true } })
    expect(state.status.baseline).toBe(false)
    expect(state.status.hass.connected).toBe(true)
  })
})

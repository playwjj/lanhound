// Presence maths for the device panel, kept free of Vue so it can be
// tested. Sessions are { start, end } ISO times; end "0001-…" = ongoing.

const HOUR = 3600e3
const DAY = 864e5

function endOf(s, nowMs) {
  return s.end.startsWith('0001') ? nowMs : new Date(s.end).getTime()
}

// dayStrips: the last seven local days, oldest first, each with the
// online segments that fall into it as percentages of the day.
export function dayStrips(sessions, nowMs, locale) {
  const out = []
  const today = new Date(nowMs)
  today.setHours(0, 0, 0, 0)
  const fmt = new Intl.DateTimeFormat(locale, { weekday: 'short', month: 'numeric', day: 'numeric' })
  for (let i = 6; i >= 0; i--) {
    const start = new Date(today)
    start.setDate(today.getDate() - i)
    const end = new Date(start)
    end.setDate(start.getDate() + 1)
    const s0 = start.getTime()
    const s1 = end.getTime()
    const segs = []
    for (const s of sessions) {
      const from = Math.max(new Date(s.start).getTime(), s0)
      const to = Math.min(endOf(s, nowMs), s1, nowMs)
      if (to > from) segs.push({ left: ((from - s0) / DAY) * 100, width: Math.max(((to - from) / DAY) * 100, 0.4) })
    }
    out.push({ label: fmt.format(start), segs })
  }
  return out
}

// usualHours: weekday (Monday first) × hour, the share of each slot the
// device was online over the last 28 days, counting only time since it
// was first seen. A slot never observed has value null.
export function usualHours(sessions, firstSeenMs, nowMs, locale, tip) {
  const begin = Math.max(nowMs - 28 * DAY, firstSeenMs)
  const online = Array.from({ length: 7 }, () => new Array(24).fill(0))
  const total = Array.from({ length: 7 }, () => new Array(24).fill(0))
  const slot = (ms) => {
    const d = new Date(ms)
    return [(d.getDay() + 6) % 7, d.getHours()]
  }
  for (let t0 = Math.floor(begin / HOUR) * HOUR; t0 < nowMs; t0 += HOUR) {
    const span = Math.min(t0 + HOUR, nowMs) - Math.max(t0, begin)
    if (span > 0) {
      const [w, h] = slot(t0)
      total[w][h] += span
    }
  }
  for (const s of sessions) {
    let a = Math.max(new Date(s.start).getTime(), begin)
    const b = Math.min(endOf(s, nowMs), nowMs)
    while (a < b) {
      const next = Math.min(Math.floor(a / HOUR) * HOUR + HOUR, b)
      const [w, h] = slot(a)
      online[w][h] += next - a
      a = next
    }
  }
  const fmt = new Intl.DateTimeFormat(locale, { weekday: 'short' })
  const monday = new Date(2024, 0, 1) // a Monday
  return online.map((hours, w) => {
    const day = fmt.format(new Date(monday.getTime() + w * DAY))
    return {
      label: day,
      cells: hours.map((ms, h) => {
        if (!total[w][h]) return { value: null, tip: '' }
        const share = ms / total[w][h]
        return { value: share, tip: tip(day, h, Math.round(share * 100)) }
      }),
    }
  })
}

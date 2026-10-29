import { reactive, ref } from 'vue'

// Live state, fed by the server's event stream. The first message after
// every (re)connect is a full snapshot, so nothing drifts.
export const state = reactive({
  devices: {}, // id → device
  status: null,
  connected: false,
  alerts: [], // newest first
  alertsSeen: readSeen(), // highest alert id the user has looked at
})

function readSeen() {
  try {
    return Number(localStorage.getItem('lanhound.alertsSeen')) || 0
  } catch {
    return 0
  }
}

export function markAlertsSeen() {
  state.alertsSeen = state.alerts[0]?.id ?? state.alertsSeen
  try {
    localStorage.setItem('lanhound.alertsSeen', String(state.alertsSeen))
  } catch {}
}

async function loadAlerts() {
  try {
    const res = await fetch('/api/alerts?limit=200')
    if (res.ok) state.alerts = await res.json()
  } catch {}
}

// A ticking "now" so relative times ("3 min ago") stay fresh.
export const now = ref(Date.now())
setInterval(() => (now.value = Date.now()), 15000)

let es
export function connect() {
  es?.close()
  es = new EventSource('/api/events')
  es.onopen = () => (state.connected = true)
  es.onerror = () => (state.connected = false)
  es.onmessage = (e) => {
    const { type, data } = JSON.parse(e.data)
    switch (type) {
      case 'snapshot':
        state.devices = Object.fromEntries(data.devices.map((d) => [d.id, d]))
        state.status = data.status
        state.connected = true
        loadAlerts()
        break
      case 'alert':
        if (!state.alerts.some((a) => a.id === data.id)) state.alerts.unshift(data)
        if (state.alerts.length > 200) state.alerts.length = 200
        break
      case 'device':
        state.devices[data.id] = data
        break
      case 'remove':
        delete state.devices[data.id]
        break
      case 'status':
        state.status = data
        break
      case 'hass':
        if (state.status) state.status.hass = data
        break
      case 'routers':
        if (state.status) state.status.routers = data
        break
      case 'alerts':
        if (state.status) state.status.alerts = data
        break
      case 'baseline':
        if (state.status) state.status.baseline = data
        break
    }
  }
}

// Apply a device returned by a REST call right away instead of waiting
// for its echo on the event stream.
export function upsert(d) {
  state.devices[d.id] = d
}

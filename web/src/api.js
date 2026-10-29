// Thin fetch wrapper. Every state-changing request carries the
// X-LanHound header the server requires (CSRF protection).
async function call(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-LanHound': '1' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!res.ok) throw new Error((await res.text()).trim() || res.statusText)
  return res.json()
}

export const api = {
  patch: (id, p) => call('PATCH', `/api/devices/${id}`, p),
  remove: (id) => call('DELETE', `/api/devices/${id}`),
  merge: (id, into) => call('POST', `/api/devices/${id}/merge`, { into }),
  history: (id, days = 7) => call('GET', `/api/devices/${id}/history?days=${days}`),
  activity: (days = 7) => call('GET', `/api/activity?days=${days}`),
  knownAll: () => call('POST', '/api/known-all'),
  scan: () => call('POST', '/api/scan'),
  trustAlert: (id) => call('POST', `/api/alerts/${id}/trust`),
  addProbe: (name) => call('POST', '/api/probes', { name }),
  removeProbe: (id) => call('DELETE', `/api/probes/${id}`),
  setServices: (enabled) => call('PUT', '/api/services', { enabled }),
  probe: (id) => call('POST', `/api/devices/${id}/probe`),
  hass: () => call('GET', '/api/hass'),
  saveHass: (c) => call('PUT', '/api/hass', c),
  testHass: (c) => call('POST', '/api/hass/test', c),
  routers: () => call('GET', '/api/routers'),
  saveRouters: (list) => call('PUT', '/api/routers', list),
  testRouter: (cfg) => call('POST', '/api/routers/test', cfg),
  settings: () => call('GET', '/api/settings'),
  saveSettings: (s) => call('PUT', '/api/settings', s),
  testSettings: (s) => call('POST', '/api/settings/test', s),
}

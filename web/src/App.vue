<script setup>
import { computed, onMounted, ref } from 'vue'
import { state, connect, now } from './state'
import { api } from './api'
import { t, locale, setLocale } from './i18n'
import { ago, displayName, ipKey } from './format'
import Icon from './components/Icon.vue'
import DeviceList from './components/DeviceList.vue'
import DeviceDrawer from './components/DeviceDrawer.vue'
import SettingsDialog from './components/SettingsDialog.vue'
import AlertsPanel from './components/AlertsPanel.vue'
import ActivityCard from './components/ActivityCard.vue'

onMounted(connect)

const query = ref('')
const filter = ref('all')
const selectedId = ref(null)
const showSettings = ref(false)
const showAlerts = ref(false)
function openFromAlert(id) {
  showAlerts.value = false
  selectedId.value = id
}
const unread = computed(() => state.alerts.filter((a) => a.id > state.alertsSeen))
const unreadSevere = computed(() => unread.value.some((a) => !['new_device', 'device_online', 'recognized'].includes(a.kind)))

const devices = computed(() => Object.values(state.devices))
const counts = computed(() => ({
  all: devices.value.length,
  online: devices.value.filter((d) => d.online).length,
  offline: devices.value.filter((d) => !d.online).length,
  new: devices.value.filter((d) => !d.known).length,
}))

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase()
  return devices.value.filter((d) => {
    if (filter.value === 'online' && !d.online) return false
    if (filter.value === 'offline' && d.online) return false
    if (filter.value === 'new' && d.known) return false
    if (!q) return true
    const link = d.link ? [d.link.type, t('link_' + d.link.type)] : []
    return [displayName(d), d.hostname, d.ip, d.vendor, d.model, d.note, ...d.macs, ...(d.ipv6 ?? []), ...link]
      .filter(Boolean)
      .some((v) => v.toLowerCase().includes(q))
  })
})

// One section per scanned interface ("设备按接口分段呈现"), plus one for
// devices whose interface is no longer watched.
const sections = computed(() => {
  const ifaces = state.status?.interfaces ?? []
  const groups = ifaces.map((i) => ({ key: i.interface + i.network, iface: i, devices: [] }))
  const byName = Object.fromEntries(groups.map((g) => [g.iface.interface, g]))
  // Devices only a router knows, one section per source; anything else
  // (an interface that went away) in a catch-all.
  const routers = Object.fromEntries((state.status?.routers ?? []).map((r) => ['router:' + r.label, r]))
  const extra = {}
  for (const d of filtered.value) {
    const g = byName[d.interface]
    if (g) {
      g.devices.push(d)
      continue
    }
    const key = routers[d.interface] || d.interface?.startsWith('router:') ? d.interface : '_other' // (a || b) ? …
    extra[key] ??= { key, iface: null, router: routers[d.interface] ?? (key !== '_other' ? { label: key.slice(7) } : null), devices: [] }
    extra[key].devices.push(d)
  }
  groups.push(...Object.values(extra))
  for (const g of groups) g.devices.sort((a, b) => b.online - a.online || ipKey(a.ip).localeCompare(ipKey(b.ip)))
  return groups
})

const sweeping = computed(() => state.status?.interfaces?.some((i) => i.sweeping))
const selected = computed(() => (selectedId.value != null ? state.devices[selectedId.value] : null))
const scanning = ref(false)

async function scanNow() {
  scanning.value = true
  try {
    await api.scan()
  } finally {
    setTimeout(() => (scanning.value = false), 1500)
  }
}

async function markAllKnown() {
  await api.knownAll()
}
</script>

<template>
  <header class="top">
    <div class="wrap top-inner">
      <div class="brand">
        <img src="/favicon.svg" alt="" width="30" height="30" class="logo" />
        <span>LanHound</span>
      </div>
      <div class="stats">
        <span class="stat"><span class="dot on"></span>{{ counts.online }} {{ t('online') }}</span>
        <span class="stat muted">{{ counts.all }} {{ t('total') }}</span>
        <span v-if="counts.new" class="stat"><span class="badge new">{{ counts.new }} {{ t('new') }}</span></span>
      </div>
      <div class="actions">
        <span class="conn" :class="{ off: !state.connected }" :title="state.connected ? t('live') : t('reconnecting')">
          <span class="dot" :class="{ on: state.connected }"></span>
          <span class="conn-label">{{ state.connected ? t('live') : t('reconnecting') }}</span>
        </span>
        <button class="btn" :disabled="sweeping || scanning" @click="scanNow">
          <Icon name="refresh" :class="{ spin: sweeping || scanning }" />
          <span class="hide-sm">{{ sweeping || scanning ? t('scanning') : t('scanNow') }}</span>
        </button>
        <button class="btn icon" :title="t('language')" @click="setLocale(locale === 'zh' ? 'en' : 'zh')">
          {{ locale === 'zh' ? 'EN' : '中' }}
        </button>
        <button class="btn icon bell" :title="t('alerts')" @click="showAlerts = true">
          <Icon name="bell" />
          <span v-if="unread.length" class="unread" :class="{ severe: unreadSevere }">{{ unread.length > 99 ? '99+' : unread.length }}</span>
        </button>
        <button class="btn icon" :title="t('settings')" @click="showSettings = true">
          <Icon name="settings" />
        </button>
      </div>
    </div>
  </header>

  <main class="wrap">
    <div v-if="state.status?.baseline" class="banner">
      <Icon name="refresh" class="spin" />
      <span class="grow">{{ t('baseline') }}</span>
    </div>
    <div v-else-if="state.status && !state.status.notify" class="banner warn">
      <Icon name="bell" />
      <span class="grow">{{ t('notifyHint') }}</span>
      <button class="btn small" @click="showSettings = true">{{ t('setUp') }}</button>
    </div>
    <div v-if="counts.new && !state.status?.baseline" class="banner">
      <span class="grow">{{ t('unreviewed', { n: counts.new }) }}</span>
      <button class="btn small" @click="filter = 'new'">{{ t('new') }}</button>
      <button class="btn small primary" @click="markAllKnown"><Icon name="check" :size="14" />{{ t('markAllKnown') }}</button>
    </div>

    <ActivityCard v-if="devices.length" />

    <div class="toolbar">
      <label class="search">
        <Icon name="search" class="search-icon" />
        <input v-model="query" type="search" :placeholder="t('search')" />
      </label>
      <a class="btn export" href="/api/devices.csv" download :title="t('exportCsv')"><Icon name="download" /><span class="hide-sm">CSV</span></a>
      <div class="seg" role="tablist">
        <button
          v-for="f in ['all', 'online', 'offline', 'new']"
          :key="f"
          :class="{ active: filter === f }"
          role="tab"
          :aria-selected="filter === f"
          @click="filter = f"
        >
          {{ t(f) }} <span class="count">{{ counts[f] }}</span>
        </button>
      </div>
    </div>

    <section v-for="g in sections" :key="g.key" class="section">
      <div class="section-head">
        <template v-if="g.iface">
          <strong>{{ g.iface.interface }}</strong>
          <span class="mono">{{ g.iface.network }}</span>
          <span class="muted hide-sm">{{ t('hosts', { n: g.iface.hosts }) }}</span>
          <span class="muted sweep">
            <template v-if="g.iface.sweeping"><Icon name="refresh" :size="12" class="spin" /> {{ t('sweeping') }}</template>
            <template v-else-if="g.iface.lastSweep && !g.iface.lastSweep.startsWith('0001')">{{
              t('lastSweep', { t: ago(g.iface.lastSweep, now) })
            }}</template>
            <template v-else>{{ t('neverSwept') }}</template>
          </span>
          <span v-if="g.iface.error" class="err" :title="g.iface.error"><Icon name="alert" :size="13" /> {{ g.iface.error }}</span>
        </template>
        <template v-else-if="g.router">
          <strong>{{ t('viaRouter', { name: g.router.label }) }}</strong>
          <span class="muted hide-sm">{{ t('routerOnly') }}</span>
          <span v-if="g.router.lastError" class="err" :title="g.router.lastError"><Icon name="alert" :size="13" /> {{ g.router.lastError }}</span>
          <span v-else-if="g.router.lastPoll" class="muted sweep">{{ t('routerOk', { n: g.router.devices, t: ago(g.router.lastPoll, now) }) }}</span>
        </template>
        <strong v-else>—</strong>
        <span class="grow"></span>
        <span class="muted">{{ g.devices.length }}</span>
      </div>
      <DeviceList :devices="g.devices" @select="selectedId = $event" />
    </section>

    <p v-if="!devices.length" class="empty muted">{{ t('noDevices') }}</p>
    <p v-else-if="!filtered.length" class="empty muted">{{ t('noMatch') }}</p>

    <footer v-if="state.status" class="foot muted">
      LanHound {{ state.status.version }}
      <template v-if="state.status.skipped.length"> · {{ t('skipped') }}: {{ state.status.skipped.join('; ') }}</template>
    </footer>
  </main>

  <DeviceDrawer v-if="selected" :device="selected" @close="selectedId = null" @select="selectedId = $event" />
  <SettingsDialog v-if="showSettings" @close="showSettings = false" />
  <AlertsPanel v-if="showAlerts" @close="showAlerts = false" @select="openFromAlert" />
</template>

<style scoped>
.wrap {
  max-width: 1180px;
  margin: 0 auto;
  padding: 0 16px;
}
.top {
  background: var(--navy);
  color: #fff;
  position: sticky;
  top: 0;
  z-index: 10;
}
.top-inner {
  display: flex;
  align-items: center;
  gap: 18px;
  height: 56px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 9px;
  font-weight: 650;
  font-size: 17px;
  letter-spacing: 0.2px;
}
.logo {
  background: #fff;
  border-radius: 8px;
  padding: 2px;
}
.stats {
  display: flex;
  gap: 14px;
  align-items: center;
  font-size: 13px;
}
.stats .muted {
  color: #b6c6da;
}
.stat {
  display: inline-flex;
  align-items: center;
  gap: 7px;
}
.actions {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 8px;
}
.actions .btn {
  background: rgb(255 255 255 / 0.08);
  border-color: rgb(255 255 255 / 0.18);
  color: #fff;
}
.actions .btn:hover {
  background: rgb(255 255 255 / 0.16);
}
.bell {
  position: relative;
}
.unread {
  position: absolute;
  top: -6px;
  right: -6px;
  min-width: 18px;
  height: 18px;
  padding: 0 5px;
  border-radius: 9px;
  background: var(--amber);
  color: #1f1300;
  font-size: 11px;
  font-weight: 700;
  line-height: 18px;
  text-align: center;
}
.unread.severe {
  background: #ef4444;
  color: #fff;
}
.conn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #b6c6da;
  margin-right: 4px;
}
.conn .dot.on {
  box-shadow: 0 0 0 3px rgb(34 197 94 / 0.25);
}
main {
  padding-top: 16px;
  padding-bottom: 40px;
}
.toolbar {
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
.search {
  position: relative;
  flex: 1;
  min-width: 220px;
}
.search input {
  padding-left: 32px;
  height: 36px;
}
.search-icon {
  position: absolute;
  left: 10px;
  top: 10px;
  color: var(--muted);
}
.export {
  text-decoration: none;
  height: 36px;
}
.seg {
  display: inline-flex;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 3px;
}
.seg button {
  border: 0;
  background: none;
  padding: 4px 11px;
  border-radius: 6px;
  color: var(--muted);
}
.seg button.active {
  background: var(--accent-soft);
  color: var(--accent);
  font-weight: 600;
}
.count {
  font-size: 11.5px;
  opacity: 0.75;
}
.section {
  margin-bottom: 18px;
}
.section-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 4px 8px;
  flex-wrap: wrap;
}
.sweep {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 12.5px;
}
.err {
  color: var(--danger);
  font-size: 12.5px;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.grow {
  flex: 1;
}
.empty {
  text-align: center;
  padding: 40px 0;
}
.foot {
  text-align: center;
  font-size: 12px;
  margin-top: 24px;
}
@media (max-width: 720px) {
  .hide-sm,
  .conn-label {
    display: none;
  }
  .stats {
    gap: 8px;
  }
  .stats .muted {
    display: none;
  }
  .brand span {
    display: none;
  }
  .top-inner {
    gap: 10px;
  }
}
</style>

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { api } from '../api'
import { now, state, upsert } from '../state'
import { t, locale } from '../i18n'
import { ago, dateTime, displayName } from '../format'
import Icon from './Icon.vue'
import InlineName from './InlineName.vue'
import DeviceHistory from './DeviceHistory.vue'
import DeviceServices from './DeviceServices.vue'

const props = defineProps({ device: { type: Object, required: true } })
const emit = defineEmits(['close', 'select'])

const note = ref('')
const noteDirty = computed(() => note.value.trim() !== (props.device.note || ''))
const mergeTarget = ref('')
const showMerge = ref(false)
const confirmForget = ref(false)
const busy = ref(false)
const error = ref('')

watch(
  () => props.device.id,
  () => {
    note.value = props.device.note || ''
    showMerge.value = confirmForget.value = false
    mergeTarget.value = ''
    error.value = ''
  },
  { immediate: true },
)

function onKey(e) {
  if (e.key === 'Escape') emit('close')
}
onMounted(() => window.addEventListener('keydown', onKey))
onUnmounted(() => window.removeEventListener('keydown', onKey))

const similar = computed(() => (props.device.sameAs ? state.devices[props.device.sameAs] : null))
const why = computed(() => (props.device.sameAsWhy || []).map((w) => t('why_' + w)).join(locale.value === 'zh' ? '、' : ', '))
const others = computed(() =>
  Object.values(state.devices)
    .filter((d) => d.id !== props.device.id)
    .sort((a, b) => (displayName(a) || a.mac).localeCompare(displayName(b) || b.mac)),
)

async function run(fn) {
  busy.value = true
  error.value = ''
  try {
    await fn()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

const saveNote = () => run(async () => upsert(await api.patch(props.device.id, { note: note.value })))
const toggleCritical = () => run(async () => upsert(await api.patch(props.device.id, { critical: !props.device.critical })))
const toggleKnown = () => run(async () => upsert(await api.patch(props.device.id, { known: !props.device.known })))
const merge = (into) =>
  run(async () => {
    const merged = await api.merge(props.device.id, Number(into))
    upsert(merged)
    emit('select', merged.id)
  })
const forget = () =>
  run(async () => {
    await api.remove(props.device.id)
    emit('close')
  })

</script>

<template>
  <div class="scrim" @click="emit('close')"></div>
  <aside class="drawer" role="dialog" :aria-label="displayName(device) || device.mac">
    <header class="d-head">
      <span class="dot" :class="{ on: device.online }"></span>
      <div class="d-title">
        <InlineName :device="device" />
        <span class="muted small">{{ device.online ? t('online') : `${t('lastSeen')} ${ago(device.lastSeen, now)}` }}</span>
      </div>
      <button class="btn icon" :title="t('close')" @click="emit('close')"><Icon name="x" /></button>
    </header>

    <div class="d-body">
      <div v-if="similar" class="banner warn">
        <Icon name="merge" />
        <span class="grow">{{ t('sameName', { name: displayName(similar) || similar.mac, why }) }}</span>
        <button class="btn small" :disabled="busy" @click="merge(similar.id)">{{ t('mergeInto') }}</button>
      </div>
      <p v-if="error" class="error">{{ error }}</p>

      <div class="known-row">
        <button class="btn" :class="{ primary: !device.known }" :disabled="busy" @click="toggleKnown">
          <Icon name="check" :size="14" />{{ device.known ? t('unmarkKnown') : t('markKnown') }}
        </button>
        <span v-if="!device.known" class="badge new">{{ t('new') }}</span>
        <span v-else class="muted small">{{ t('known') }} ✓</span>
      </div>

      <label class="crit">
        <input type="checkbox" :checked="device.critical" :disabled="busy" @change="toggleCritical" />
        <span>
          <strong>{{ t('critical') }}</strong>
          <span class="muted small"> — {{ t('criticalHelp') }}</span>
        </span>
      </label>

      <dl class="facts">
        <dt>{{ t('ip') }}</dt>
        <dd class="mono">{{ device.ip || '—' }}</dd>
        <template v-if="device.ipv6?.length">
          <dt>IPv6</dt>
          <dd>
            <div v-for="a in device.ipv6" :key="a" class="mono">{{ a }}</div>
          </dd>
        </template>
        <dt>{{ t('hostname') }}</dt>
        <dd>
          {{ device.hostname || '—' }}
          <span v-if="device.hostname" class="muted small">{{ t('via', { src: device.hostnameSource }) }}</span>
        </dd>
        <template v-if="device.model">
          <dt>{{ t('model') }}</dt>
          <dd>{{ device.model }}</dd>
        </template>
        <template v-if="device.link">
          <dt>{{ t('link') }}</dt>
          <dd>
            {{ t('link_' + device.link.type) }}
            <template v-if="device.link.certain">
              <span v-if="device.link.band"> · {{ device.link.band }}</span>
              <span v-if="device.link.signal"> · {{ device.link.signal }} dBm</span>
              <span class="muted small"> {{ t('linkVia', { r: device.link.via }) }}</span>
            </template>
            <span v-else class="muted small" :title="t('linkGuessTip')">
              ({{ t('linkLikely') }}: {{ device.link.reasons.map((r) => t('why_' + r.replace('-', '_'))).join(locale === 'zh' ? '、' : ', ') }})
            </span>
          </dd>
        </template>
        <template v-if="device.kind">
          <dt>{{ t('kind') }}</dt>
          <dd>{{ t('kind_' + device.kind) }}</dd>
        </template>
        <dt>{{ t('vendor') }}</dt>
        <dd>{{ device.vendor || '—' }}</dd>
        <template v-if="device.dhcpFingerprint">
          <dt>{{ t('dhcpFingerprint') }}</dt>
          <dd class="mono small">{{ device.dhcpFingerprint }}</dd>
        </template>
        <dt>{{ t('interface') }}</dt>
        <dd>{{ device.interface || '—' }}</dd>
        <dt>{{ t('macs') }}</dt>
        <dd>
          <div v-for="m in device.macs" :key="m" class="mono">
            {{ m }} <span v-if="m === device.mac && device.macs.length > 1" class="muted small">●</span>
          </div>
          <span v-if="device.randomized" class="badge random" :title="t('randomMacTip')">{{ t('randomMac') }}</span>
        </dd>
        <dt>{{ t('firstSeen') }}</dt>
        <dd>{{ dateTime(device.firstSeen) }}</dd>
        <dt>{{ t('lastSeen') }}</dt>
        <dd>{{ dateTime(device.lastSeen) }}</dd>
      </dl>

      <DeviceServices :device="device" />

      <label class="field">
        <span class="label">{{ t('note') }}</span>
        <textarea v-model="note" rows="2" maxlength="500" :placeholder="t('notePlaceholder')"></textarea>
      </label>
      <div v-if="noteDirty" class="right">
        <button class="btn small" @click="note = device.note || ''">{{ t('cancel') }}</button>
        <button class="btn small primary" :disabled="busy" @click="saveNote">{{ t('save') }}</button>
      </div>

      <DeviceHistory :device="device" />

      <div class="danger-zone">
        <template v-if="!showMerge">
          <button class="btn small" @click="showMerge = true"><Icon name="merge" :size="14" />{{ t('mergeManual') }}</button>
        </template>
        <div v-else class="merge-box">
          <p class="muted small">{{ t('mergeHelp') }}</p>
          <div class="merge-row">
            <select v-model="mergeTarget">
              <option value="" disabled>{{ t('pick') }}</option>
              <option v-for="o in others" :key="o.id" :value="o.id">{{ displayName(o) || o.mac }} — {{ o.ip || o.mac }}</option>
            </select>
            <button class="btn small primary" :disabled="!mergeTarget || busy" @click="merge(mergeTarget)">{{ t('merge') }}</button>
            <button class="btn small" @click="showMerge = false">{{ t('cancel') }}</button>
          </div>
        </div>

        <template v-if="!confirmForget">
          <button class="btn small danger" @click="confirmForget = true"><Icon name="trash" :size="14" />{{ t('forget') }}</button>
        </template>
        <div v-else class="confirm">
          <p class="small">{{ t('forgetConfirm') }}</p>
          <div class="right">
            <button class="btn small" @click="confirmForget = false">{{ t('cancel') }}</button>
            <button class="btn small danger solid" :disabled="busy" @click="forget">{{ t('yesForget') }}</button>
          </div>
        </div>
      </div>
    </div>
  </aside>
</template>

<style scoped>
.scrim {
  position: fixed;
  inset: 0;
  background: rgb(15 23 42 / 0.35);
  z-index: 20;
}
.drawer {
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  width: min(460px, 100vw);
  background: var(--surface);
  border-left: 1px solid var(--border);
  z-index: 21;
  display: flex;
  flex-direction: column;
  box-shadow: -8px 0 30px rgb(15 23 42 / 0.15);
}
.d-head {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
}
.d-title {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}
.d-title :deep(.name-btn) {
  font-size: 16px;
}
.d-body {
  overflow-y: auto;
  padding: 16px;
}
.small {
  font-size: 12px;
}
.grow {
  flex: 1;
}
.error {
  color: var(--danger);
}
.known-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 14px;
}
.crit {
  display: flex;
  gap: 8px;
  align-items: baseline;
  margin-bottom: 14px;
  cursor: pointer;
}
.facts {
  display: grid;
  grid-template-columns: 110px 1fr;
  gap: 7px 12px;
  margin: 0 0 16px;
}
.facts dt {
  color: var(--muted);
}
.facts dd {
  margin: 0;
  min-width: 0;
  overflow-wrap: anywhere;
}
.field {
  display: block;
}
.label {
  display: block;
  color: var(--muted);
  margin-bottom: 4px;
}
textarea {
  resize: vertical;
}
.right {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 8px;
}
.danger-zone {
  margin-top: 24px;
  padding-top: 14px;
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 10px;
}
.merge-box,
.confirm {
  width: 100%;
}
.merge-row {
  display: flex;
  gap: 8px;
}
.merge-row select {
  flex: 1;
  min-width: 0;
}
.confirm p,
.merge-box p {
  margin: 0 0 6px;
}
</style>

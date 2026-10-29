<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { now, state } from '../state'
import { t } from '../i18n'
import { ago, isZero } from '../format'
import Icon from './Icon.vue'

const list = ref(null)
const tests = ref({}) // index → result
const busy = ref(false)
const msg = ref('')
const err = ref('')

onMounted(async () => {
  list.value = await api.routers()
})

function add() {
  list.value.push({ kind: 'openwrt', label: '', url: 'http://192.168.1.1', username: 'root', password: '', enabled: true, insecure: false })
}

function remove(i) {
  list.value.splice(i, 1)
  tests.value = {}
}

async function test(i) {
  tests.value = { ...tests.value, [i]: { pending: true } }
  try {
    tests.value = { ...tests.value, [i]: await api.testRouter(list.value[i]) }
  } catch (e) {
    tests.value = { ...tests.value, [i]: { error: e.message } }
  }
}

const svcBusy = ref(false)
async function toggleServices(e) {
  svcBusy.value = true
  try {
    await api.setServices(e.target.checked)
  } finally {
    svcBusy.value = false
  }
}

async function save() {
  busy.value = true
  msg.value = err.value = ''
  try {
    const cfgs = list.value.map(({ lastPoll, lastError, devices, ...c }) => c)
    list.value = await api.saveRouters(cfgs)
    msg.value = t('saved')
  } catch (e) {
    err.value = e.message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div v-if="list" class="routers">
    <fieldset>
      <legend>{{ t('svcTitle') }}</legend>
      <label class="check">
        <input type="checkbox" :checked="state.status?.serviceScan" :disabled="svcBusy" @change="toggleServices" />
        {{ t('svcToggle') }}
      </label>
      <span class="help">{{ t('svcHelp') }}</span>
    </fieldset>

    <h4>{{ t('routers') }}</h4>
    <p class="muted intro">{{ t('routersIntro') }}</p>

    <fieldset v-for="(r, i) in list" :key="r.id || 'new' + i">
      <legend>
        <label class="check"><input v-model="r.enabled" type="checkbox" /> {{ r.label || t('newRouter') }}</label>
      </legend>
      <div class="grid">
        <label class="field">
          <span class="label">{{ t('routerKind') }}</span>
          <select v-model="r.kind">
            <option value="openwrt">OpenWrt (LuCI)</option>
            <option value="url">{{ t('routerKindUrl') }}</option>
          </select>
        </label>
        <label class="field">
          <span class="label">{{ t('routerLabel') }}</span>
          <input v-model="r.label" type="text" maxlength="40" :placeholder="t('routerLabelPh')" />
        </label>
      </div>
      <label class="field">
        <span class="label">URL</span>
        <input v-model="r.url" type="url" :placeholder="r.kind === 'openwrt' ? 'http://192.168.1.1' : 'http://192.168.1.1/dhcp.leases'" />
        <span class="help">{{ r.kind === 'openwrt' ? t('routerUrlHelpOpenwrt') : t('routerUrlHelpText') }}</span>
      </label>
      <div class="grid">
        <label class="field">
          <span class="label">{{ t('username') }}</span>
          <input v-model="r.username" type="text" autocomplete="off" :placeholder="r.kind === 'openwrt' ? 'root' : ''" />
        </label>
        <label class="field">
          <span class="label">{{ t('password') }}</span>
          <input v-model="r.password" type="password" autocomplete="new-password" />
        </label>
      </div>
      <label class="check small"><input v-model="r.insecure" type="checkbox" /> {{ t('routerInsecure') }}</label>

      <div v-if="r.lastPoll && !isZero(r.lastPoll)" class="small" :class="r.lastError ? 'err' : 'muted'">
        {{ r.lastError ? t('routerFailed', { e: r.lastError }) : t('routerOk', { n: r.devices, t: ago(r.lastPoll, now) }) }}
      </div>
      <div v-if="tests[i]" class="test small">
        <span v-if="tests[i].pending" class="muted">{{ t('testing') }}</span>
        <span v-else-if="tests[i].error" class="err">{{ tests[i].error }}</span>
        <template v-else>
          <span class="ok">{{ t('routerTestOk', { n: tests[i].devices }) }}</span>
          <ul>
            <li v-for="s in tests[i].sample" :key="s.mac" class="mono">{{ s.mac }} {{ s.ip }} <span class="muted">{{ s.hostname }}</span></li>
          </ul>
        </template>
      </div>
      <div class="row">
        <button type="button" class="btn small" @click="test(i)">{{ t('testConnection') }}</button>
        <button type="button" class="btn small danger" @click="remove(i)"><Icon name="trash" :size="13" />{{ t('remove') }}</button>
      </div>
    </fieldset>

    <button type="button" class="btn" @click="add">+ {{ t('addRouter') }}</button>

    <p v-if="msg" class="ok small">{{ msg }}</p>
    <p v-if="err" class="err small">{{ err }}</p>
    <div class="foot">
      <span class="muted small hint">{{ t('routerPrivacy') }}</span>
      <button type="button" class="btn primary" :disabled="busy" @click="save">{{ t('save') }}</button>
    </div>
  </div>
</template>

<style scoped>
.routers {
  display: grid;
  gap: 12px;
}
h4 {
  margin: 6px 0 0;
}
.intro {
  margin: 0;
  font-size: 13px;
}
fieldset {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 10px 14px 14px;
  margin: 0;
  display: grid;
  gap: 10px;
}
legend {
  font-weight: 600;
  padding: 0 6px;
}
.grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}
.field {
  display: grid;
  gap: 4px;
}
.label {
  color: var(--muted);
}
.help {
  font-size: 12px;
  color: var(--muted);
}
.check {
  display: inline-flex;
  gap: 6px;
  align-items: center;
}
.row {
  display: flex;
  gap: 8px;
}
.test ul {
  margin: 4px 0 0;
  padding-left: 16px;
}
.small {
  font-size: 12.5px;
}
.ok {
  color: var(--ok);
}
.err {
  color: var(--danger);
  overflow-wrap: anywhere;
}
.foot {
  display: flex;
  gap: 8px;
  align-items: center;
  justify-content: flex-end;
}
.hint {
  margin-right: auto;
}
@media (max-width: 520px) {
  .grid {
    grid-template-columns: 1fr;
  }
}
</style>

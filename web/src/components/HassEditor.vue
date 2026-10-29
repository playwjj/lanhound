<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { state } from '../state'
import { t } from '../i18n'

const form = ref(null)
const busy = ref(false)
const msg = ref('')
const err = ref('')

onMounted(async () => {
  form.value = (await api.hass()).config
})

async function act(fn, ok) {
  busy.value = true
  msg.value = err.value = ''
  try {
    await fn()
    msg.value = ok
  } catch (e) {
    err.value = e.message
  } finally {
    busy.value = false
  }
}
const save = () => act(async () => (form.value = (await api.saveHass(form.value)).config), t('saved'))
const test = () => act(() => api.testHass(form.value), t('hassTestOk'))
</script>

<template>
  <form v-if="form" class="hass" @submit.prevent="save">
    <p class="muted intro">{{ t('hassIntro') }}</p>
    <p v-if="state.status?.hass?.locked" class="lock small">{{ t('hassLocked') }}</p>

    <label class="check">
      <input v-model="form.enabled" type="checkbox" :disabled="state.status?.hass?.locked" />
      <span>{{ t('hassEnable') }}</span>
    </label>
    <label class="field">
      <span class="label">{{ t('hassBroker') }}</span>
      <input v-model="form.url" type="text" placeholder="mqtt://192.168.2.5:1883" :disabled="state.status?.hass?.locked" />
      <span class="help">{{ t('hassBrokerHelp') }}</span>
    </label>
    <div class="grid">
      <label class="field">
        <span class="label">{{ t('username') }}</span>
        <input v-model="form.username" type="text" autocomplete="off" :disabled="state.status?.hass?.locked" />
      </label>
      <label class="field">
        <span class="label">{{ t('password') }}</span>
        <input v-model="form.password" type="password" autocomplete="new-password" :disabled="state.status?.hass?.locked" />
      </label>
    </div>
    <div class="grid">
      <label class="field">
        <span class="label">{{ t('hassPrefix') }}</span>
        <input v-model="form.prefix" type="text" placeholder="homeassistant" />
      </label>
      <label class="field">
        <span class="label">{{ t('hassWhich') }}</span>
        <select v-model="form.all">
          <option :value="false">{{ t('hassKnownOnly') }}</option>
          <option :value="true">{{ t('hassAll') }}</option>
        </select>
      </label>
    </div>
    <label class="check small"><input v-model="form.insecure" type="checkbox" /> {{ t('hassInsecure') }}</label>

    <p v-if="state.status?.hass?.enabled" class="small" :class="state.status.hass.connected ? 'ok' : 'err'">
      {{
        state.status.hass.connected
          ? t('hassConnected', { n: state.status.hass.devices })
          : t('hassDisconnected', { e: state.status.hass.lastError || '…' })
      }}
    </p>
    <p v-if="msg" class="ok small">{{ msg }}</p>
    <p v-if="err" class="err small">{{ err }}</p>
    <div class="foot">
      <button type="button" class="btn" :disabled="busy" @click="test">{{ t('testConnection') }}</button>
      <button type="submit" class="btn primary" :disabled="busy">{{ t('save') }}</button>
    </div>
  </form>
</template>

<style scoped>
.hass {
  display: grid;
  gap: 12px;
}
.intro {
  margin: 0;
  font-size: 13px;
}
.lock {
  color: var(--warn);
  margin: 0;
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
  display: flex;
  gap: 8px;
  align-items: center;
}
.small {
  font-size: 12.5px;
  margin: 0;
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
  justify-content: flex-end;
}
@media (max-width: 520px) {
  .grid {
    grid-template-columns: 1fr;
  }
}
</style>

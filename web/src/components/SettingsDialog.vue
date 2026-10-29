<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api'
import { state, now } from '../state'
import { t } from '../i18n'
import { ago, isZero } from '../format'
import Icon from './Icon.vue'

const emit = defineEmits(['close'])
const form = ref(null)
const locked = ref([])
const msg = ref('')
const err = ref('')
const busy = ref(false)

onMounted(async () => {
  const s = await api.settings()
  locked.value = s.locked
  delete s.locked
  form.value = s
  window.addEventListener('keydown', onKey)
})
onUnmounted(() => window.removeEventListener('keydown', onKey))

function onKey(e) {
  if (e.key === 'Escape') emit('close')
}

const isLocked = (f) => locked.value.includes(f)

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

const save = () =>
  act(async () => {
    const s = await api.saveSettings(form.value)
    delete s.locked
    form.value = s
  }, t('saved'))
const test = () => act(() => api.testSettings(form.value), t('testOk'))
</script>

<template>
  <div class="scrim" @click="emit('close')"></div>
  <div class="dialog" role="dialog" :aria-label="t('settings')">
    <header>
      <Icon name="bell" />
      <strong>{{ t('notifications') }}</strong>
      <span class="grow"></span>
      <button class="btn icon" :title="t('close')" @click="emit('close')"><Icon name="x" /></button>
    </header>

    <form v-if="form" class="body" @submit.prevent="save">
      <div class="checks">
        <label class="check">
          <input v-model="form.notifyNew" type="checkbox" />
          <span>{{ t('notifyNew') }}</span>
        </label>
        <label class="check">
          <input v-model="form.notifySecurity" type="checkbox" />
          <span>{{ t('notifySecurity') }}</span>
        </label>
        <label class="check">
          <input v-model="form.notifyCritical" type="checkbox" />
          <span>{{ t('notifyCritical') }}</span>
        </label>
      </div>

      <label class="field">
        <span class="label">{{ t('alertLang') }}</span>
        <select v-model="form.language" :disabled="isLocked('language')">
          <option value="en">English</option>
          <option value="zh">中文</option>
        </select>
      </label>

      <fieldset>
        <legend>Telegram</legend>
        <label class="field">
          <span class="label">{{ t('telegramToken') }} <em v-if="isLocked('telegramToken')">{{ t('lockedEnv') }}</em></span>
          <input v-model="form.telegramToken" type="password" autocomplete="off" placeholder="123456789:AA…" :disabled="isLocked('telegramToken')" />
          <span class="help">{{ t('telegramTokenHelp') }}</span>
        </label>
        <label class="field">
          <span class="label">{{ t('telegramChat') }} <em v-if="isLocked('telegramChatId')">{{ t('lockedEnv') }}</em></span>
          <input v-model="form.telegramChatId" type="text" placeholder="123456789" :disabled="isLocked('telegramChatId')" />
          <span class="help">{{ t('telegramChatHelp') }}</span>
        </label>
        <label class="field">
          <span class="label">{{ t('telegramApi') }} <em v-if="isLocked('telegramApi')">{{ t('lockedEnv') }}</em></span>
          <input v-model="form.telegramApi" type="url" placeholder="https://api.telegram.org" :disabled="isLocked('telegramApi')" />
          <span class="help">{{ t('telegramApiHelp') }}</span>
        </label>
      </fieldset>

      <fieldset>
        <legend>Webhook</legend>
        <label class="field">
          <span class="label">{{ t('webhook') }} <em v-if="isLocked('webhookUrl')">{{ t('lockedEnv') }}</em></span>
          <input v-model="form.webhookUrl" type="url" placeholder="https://example.com/hook" :disabled="isLocked('webhookUrl')" />
          <span class="help">{{ t('webhookHelp') }}</span>
        </label>
      </fieldset>

      <p v-if="state.status?.alerts?.lastError" class="err small">{{ t('alertError', { e: state.status.alerts.lastError }) }}</p>
      <p v-else-if="state.status && !isZero(state.status.alerts?.lastSent)" class="muted small">
        {{ t('lastAlert', { t: ago(state.status.alerts.lastSent, now) }) }}
      </p>
      <p v-if="msg" class="ok small">{{ msg }}</p>
      <p v-if="err" class="err small">{{ err }}</p>

      <div class="foot">
        <span class="muted small hint">{{ t('password') }}</span>
        <button type="button" class="btn" :disabled="busy" @click="test">{{ t('sendTest') }}</button>
        <button type="submit" class="btn primary" :disabled="busy">{{ t('save') }}</button>
      </div>
    </form>
  </div>
</template>

<style scoped>
.scrim {
  position: fixed;
  inset: 0;
  background: rgb(15 23 42 / 0.4);
  z-index: 30;
}
.dialog {
  position: fixed;
  z-index: 31;
  left: 50%;
  top: 50%;
  transform: translate(-50%, -50%);
  width: min(560px, calc(100vw - 24px));
  max-height: calc(100vh - 32px);
  display: flex;
  flex-direction: column;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 14px;
  box-shadow: 0 20px 50px rgb(15 23 42 / 0.25);
}
header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
}
.grow {
  flex: 1;
}
.body {
  overflow-y: auto;
  padding: 16px;
  display: grid;
  gap: 14px;
}
fieldset {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 10px 14px 14px;
  margin: 0;
  display: grid;
  gap: 12px;
}
legend {
  font-weight: 600;
  padding: 0 6px;
}
.field {
  display: grid;
  gap: 4px;
}
.label {
  color: var(--muted);
}
.label em {
  font-style: normal;
  font-size: 11.5px;
  color: var(--warn);
  margin-left: 6px;
}
.help {
  font-size: 12px;
  color: var(--muted);
}
.checks {
  display: grid;
  gap: 6px;
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
.err {
  color: var(--danger);
}
.ok {
  color: var(--ok);
}
.foot {
  display: flex;
  gap: 8px;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
}
.hint {
  margin-right: auto;
}
</style>

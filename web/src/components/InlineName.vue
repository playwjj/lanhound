<script setup>
import { nextTick, ref } from 'vue'
import { api } from '../api'
import { upsert } from '../state'
import { t } from '../i18n'
import { displayName } from '../format'
import Icon from './Icon.vue'

const props = defineProps({ device: Object })
const editing = ref(false)
const value = ref('')
const input = ref(null)

async function start() {
  value.value = props.device.name || props.device.hostname || ''
  editing.value = true
  await nextTick()
  input.value?.select()
}

async function save() {
  if (!editing.value) return
  editing.value = false
  if (value.value.trim() === (props.device.name || props.device.hostname || '')) return
  upsert(await api.patch(props.device.id, { name: value.value }))
}
</script>

<template>
  <span class="inline-name" @click.stop>
    <input
      v-if="editing"
      ref="input"
      v-model="value"
      type="text"
      maxlength="64"
      @keydown.enter="save"
      @keydown.esc="editing = false"
      @blur="save"
    />
    <button v-else class="name-btn" :title="t('rename')" @click="start">
      <span :class="{ unnamed: !displayName(device) }">{{ displayName(device) || t('unnamed') }}</span>
      <Icon name="pencil" :size="12" class="pen" />
    </button>
  </span>
</template>

<style scoped>
.inline-name {
  display: inline-flex;
  min-width: 0;
  max-width: 100%;
}
.name-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border: 0;
  background: none;
  padding: 0;
  font-weight: 600;
  text-align: left;
  min-width: 0;
}
.name-btn span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.unnamed {
  color: var(--muted);
  font-weight: 500;
  font-style: italic;
}
.pen {
  color: var(--muted);
  opacity: 0;
  flex: none;
  transition: opacity 0.15s;
}
.name-btn:hover .pen,
.name-btn:focus-visible .pen {
  opacity: 1;
}
input {
  padding: 2px 6px;
  font-weight: 600;
  height: 26px;
}
@media (hover: none) {
  .pen {
    opacity: 0.6;
  }
}
</style>

<template>
  <FormHeading>AmneziaWG 3.1</FormHeading>
  <p class="col-span-full text-sm text-gray-500 dark:text-neutral-300">
    {{ $t(client ? 'awg31.clientDescription' : 'awg31.serverDescription') }}
  </p>
  <template v-for="field in textFields" :key="field">
    <div class="flex items-center">
      <FormLabel :for="`${prefix}-${field}`">{{
        $t(`awg31.${field}`)
      }}</FormLabel>
      <BaseTooltip :text="$t(`awg31.${field}Desc`)">
        <IconsInfo class="size-4" />
      </BaseTooltip>
    </div>
    <BaseInput
      :id="`${prefix}-${field}`"
      :model-value="settings?.[field] ?? ''"
      :type="field === 'headerProtectionKey' && !showKey ? 'password' : 'text'"
      autocomplete="off"
      :placeholder="$t('awg31.inherit')"
      @update:model-value="setText(field, $event)"
    />
    <div
      v-if="field === 'headerProtectionKey'"
      class="col-span-full flex items-center gap-2 text-sm"
    >
      <input :id="`${prefix}-show-key`" v-model="showKey" type="checkbox" />
      <label :for="`${prefix}-show-key`">{{ $t('awg31.showKey') }}</label>
    </div>
  </template>
  <template v-for="field in booleanFields" :key="field">
    <div class="flex items-center">
      <FormLabel :for="`${prefix}-${field}`">{{
        $t(`awg31.${field}`)
      }}</FormLabel>
      <BaseTooltip :text="$t(`awg31.${field}Desc`)">
        <IconsInfo class="size-4" />
      </BaseTooltip>
    </div>
    <select
      :id="`${prefix}-${field}`"
      :value="settings?.[field] == null ? 'inherit' : String(settings[field])"
      class="rounded-lg border-2 border-gray-100 bg-white px-3 py-2 focus:border-red-800 focus:outline-none dark:border-neutral-800 dark:bg-neutral-700"
      @change="setBoolean(field, $event)"
    >
      <option value="inherit">{{ $t('awg31.inherit') }}</option>
      <option value="true">{{ $t('general.yes') }}</option>
      <option value="false">{{ $t('general.no') }}</option>
    </select>
  </template>
  <BaseSecondaryButton
    type="button"
    class="col-span-full justify-center"
    @click="settings = null"
  >
    {{ $t('awg31.reset') }}
  </BaseSecondaryButton>
</template>

<script setup lang="ts">
import type { AwgSettings as Settings } from '../../../shared/types/amneziawg';

const props = withDefaults(
  defineProps<{ client?: boolean; prefix: string }>(),
  {
    client: false,
  }
);
const settings = defineModel<Settings | null>();
const showKey = ref(false);
const textFields = computed(() => {
  const fields: (keyof Omit<Settings, 'randomTrailers' | 'disableCookies'>)[] =
    [
      'contentPaddingAddition',
      'rekeyAfterTime',
      'rekeyTimeout',
      'rejectAfterTime',
      'keepaliveTimeout',
      'maxHandshakeAttempts',
      'persistentKeepaliveRange',
    ];
  return props.client ? fields : ['headerProtectionKey' as const, ...fields];
});
const booleanFields = computed(() =>
  props.client
    ? (['disableCookies'] as const)
    : (['randomTrailers', 'disableCookies'] as const)
);

function setText(
  field: keyof Omit<Settings, 'randomTrailers' | 'disableCookies'>,
  value: unknown
) {
  const next = { ...settings.value };
  const normalized = String(value ?? '').trim();
  if (normalized) next[field] = normalized;
  else Reflect.deleteProperty(next, field);
  settings.value = Object.keys(next).length ? next : null;
}

function setBoolean(field: 'randomTrailers' | 'disableCookies', event: Event) {
  const value = (event.target as HTMLSelectElement).value;
  const next = { ...settings.value };
  if (value === 'inherit') Reflect.deleteProperty(next, field);
  else next[field] = value === 'true';
  settings.value = Object.keys(next).length ? next : null;
}
</script>

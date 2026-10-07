<template>
  <main>
    <div
      v-if="loadError"
      class="mb-4 rounded-lg border border-red-800 p-4"
      role="alert"
    >
      {{ loadError.message }}
      <BaseSecondaryButton type="button" class="mt-2" @click="reload">{{
        $t('routing.reload')
      }}</BaseSecondaryButton>
    </div>
    <FormElement v-if="config" @submit.prevent="save(false)">
      <FormGroup>
        <FormHeading>{{ $t('routing.title') }}</FormHeading>
        <p class="col-span-full text-sm text-gray-500 dark:text-neutral-300">
          {{ $t('routing.description') }}
        </p>
        <p
          class="col-span-full rounded-lg border border-amber-300 p-3 text-sm dark:border-amber-700"
          role="note"
        >
          {{ $t('routing.isolationNote') }}
        </p>
        <FormSwitchField
          id="routing-enabled"
          v-model="config.enabled"
          :label="$t('routing.enabled')"
          :description="$t('routing.enabledDesc')"
        />
        <div
          class="col-span-full flex flex-wrap items-center gap-3 text-sm"
          role="status"
        >
          <span class="inline-flex items-center gap-2">
            <span
              :class="
                status?.state === 'running'
                  ? 'bg-green-500'
                  : status?.state === 'failed'
                    ? 'bg-red-600'
                    : 'bg-neutral-400'
              "
              class="size-2 rounded-full"
            />
            {{ $t(`routing.state.${status?.state ?? 'stopped'}`) }}
          </span>
          <span v-if="status?.appliedAt"
            >{{ $t('routing.appliedAt') }}:
            {{ new Date(status.appliedAt).toLocaleString() }}</span
          >
          <span
            v-if="status?.error"
            class="break-words text-red-700 dark:text-red-300"
            >{{ status.error }}</span
          >
        </div>
      </FormGroup>

      <FormGroup>
        <FormHeading>{{ $t('routing.egresses') }}</FormHeading>
        <p class="col-span-full text-sm text-gray-500 dark:text-neutral-300">
          {{ $t('routing.egressDescription') }}
        </p>
        <div
          v-for="egress in config.egresses"
          :key="egress.id"
          class="col-span-full rounded-lg border-2 border-gray-100 p-4 dark:border-neutral-600"
        >
          <div class="mb-4 flex items-center justify-between gap-3">
            <h4 class="min-w-0 break-words text-lg font-medium">
              {{ egress.name || $t('routing.newEgress') }}
            </h4>
            <BaseSecondaryButton
              type="button"
              :aria-label="$t('routing.removeEgress')"
              @click="removeEgress(egress.id)"
              ><IconsDelete class="size-4"
            /></BaseSecondaryButton>
          </div>
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label
                :for="`egress-name-${egress.id}`"
                class="mb-2 block text-sm"
                >{{ $t('general.name') }}</label
              >
              <BaseInput
                :id="`egress-name-${egress.id}`"
                v-model="egress.name"
                class="w-full px-3 py-2"
                required
              />
            </div>
            <div>
              <span class="mb-2 block text-sm">{{
                $t('routing.identifier')
              }}</span>
              <code class="block px-3 py-2 text-sm">{{ egress.id }}</code>
            </div>
          </div>
          <div class="my-4 flex items-start gap-2 text-sm">
            <input
              :id="`independent-${egress.id}`"
              v-model="acknowledged[egress.id]"
              type="checkbox"
              class="mt-1"
            />
            <label :for="`independent-${egress.id}`">{{
              $t('routing.independentPeer')
            }}</label>
          </div>
          <div class="mb-3 flex flex-wrap gap-2">
            <BaseSecondaryButton
              type="button"
              @click="revealed[egress.id] = !revealed[egress.id]"
            >
              {{
                $t(
                  revealed[egress.id]
                    ? 'routing.hideProfile'
                    : 'routing.editProfile'
                )
              }}
            </BaseSecondaryButton>
            <label
              class="inline-flex cursor-pointer items-center rounded border-2 border-gray-100 px-4 py-2 transition hover:border-red-800 hover:bg-red-800 hover:text-white dark:border-neutral-600"
            >
              <IconsDownload class="mr-2 size-4 rotate-180" />{{
                $t('routing.uploadProfile')
              }}
              <input
                type="file"
                accept=".conf,text/plain"
                class="sr-only"
                @change="uploadProfile(egress.id, $event)"
              />
            </label>
            <BaseSecondaryButton
              type="button"
              :disabled="!egress.profile || busy"
              @click="validateProfile(egress)"
              >{{ $t('routing.validateProfile') }}</BaseSecondaryButton
            >
          </div>
          <div v-if="revealed[egress.id]">
            <label :for="`profile-${egress.id}`" class="mb-2 block text-sm">{{
              $t('routing.profile')
            }}</label>
            <BaseTextArea
              :id="`profile-${egress.id}`"
              v-model="egress.profile"
              rows="10"
              autocomplete="off"
              spellcheck="false"
              class="w-full px-3 py-2 font-mono text-sm"
              :placeholder="$t('routing.profilePlaceholder')"
              @update:model-value="clearImport(egress.id)"
            />
          </div>
          <p v-else class="text-sm text-gray-500 dark:text-neutral-300">
            {{
              $t(egress.profile ? 'routing.profileHidden' : 'routing.noProfile')
            }}
          </p>
          <div
            v-if="imports[egress.id]"
            class="mt-4 rounded-lg bg-gray-50 p-3 text-sm dark:bg-neutral-800"
            role="status"
          >
            <p class="font-medium text-green-700 dark:text-green-400">
              {{ $t('routing.validProfile') }}
            </p>
            <dl class="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
              <dt>{{ $t('client.address') }}</dt>
              <dd class="break-all">
                {{ imports[egress.id]?.summary.address }}
              </dd>
              <dt>{{ $t('client.endpoint') }}</dt>
              <dd class="break-all">
                {{ imports[egress.id]?.summary.endpoint }}
              </dd>
              <dt>MTU</dt>
              <dd>{{ imports[egress.id]?.summary.mtu }}</dd>
              <dt>{{ $t('routing.parameters') }}</dt>
              <dd class="break-words">
                {{ imports[egress.id]?.summary.parameterNames.join(', ') }}
              </dd>
            </dl>
            <p
              v-for="warning in imports[egress.id]?.warnings"
              :key="warning"
              class="mt-2 text-amber-700 dark:text-amber-300"
            >
              {{ warning }}
            </p>
          </div>
        </div>
        <p v-if="!config.egresses.length" class="col-span-full text-sm">
          {{ $t('routing.noEgresses') }}
        </p>
        <BaseSecondaryButton
          type="button"
          class="col-span-full justify-center"
          @click="addEgress"
          ><IconsPlus class="mr-2 size-4" />{{
            $t('routing.addEgress')
          }}</BaseSecondaryButton
        >
      </FormGroup>

      <FormGroup>
        <FormHeading>{{ $t('routing.rules') }}</FormHeading>
        <p class="col-span-full text-sm text-gray-500 dark:text-neutral-300">
          {{ $t('routing.rulesDescription') }}
        </p>
        <article
          v-for="(rule, index) in config.rules"
          :key="rule.id"
          class="col-span-full rounded-lg border-2 border-gray-100 p-4 dark:border-neutral-600"
        >
          <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
            <h4 class="text-lg font-medium">
              {{ index + 1 }}. {{ rule.name || $t('routing.newRule') }}
            </h4>
            <div class="flex items-center gap-2">
              <BaseSwitch
                :id="`rule-enabled-${rule.id}`"
                v-model="rule.enabled"
                :aria-label="$t('client.enabled')"
              />
              <BaseSecondaryButton
                type="button"
                :disabled="index === 0"
                :aria-label="$t('routing.moveUp')"
                @click="moveRule(index, -1)"
                ><IconsArrowUp class="size-4"
              /></BaseSecondaryButton>
              <BaseSecondaryButton
                type="button"
                :disabled="index === config.rules.length - 1"
                :aria-label="$t('routing.moveDown')"
                @click="moveRule(index, 1)"
                ><IconsArrowDown class="size-4"
              /></BaseSecondaryButton>
              <BaseSecondaryButton
                type="button"
                :aria-label="$t('routing.removeRule')"
                @click="config.rules.splice(index, 1)"
                ><IconsDelete class="size-4"
              /></BaseSecondaryButton>
            </div>
          </div>
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label :for="`rule-name-${rule.id}`" class="mb-2 block text-sm">{{
                $t('general.name')
              }}</label
              ><BaseInput
                :id="`rule-name-${rule.id}`"
                v-model="rule.name"
                class="w-full px-3 py-2"
                required
              />
            </div>
            <div>
              <label
                :for="`rule-outbound-${rule.id}`"
                class="mb-2 block text-sm"
                >{{ $t('routing.outbound') }}</label
              >
              <select
                :id="`rule-outbound-${rule.id}`"
                v-model="rule.outbound"
                class="w-full rounded-lg border-2 border-gray-100 bg-white px-3 py-2 dark:border-neutral-800 dark:bg-neutral-700"
              >
                <option value="direct">{{ $t('routing.direct') }}</option>
                <option
                  v-for="egress in config.egresses"
                  :key="egress.id"
                  :value="egress.id"
                >
                  {{ egress.name }}
                </option>
              </select>
            </div>
            <div>
              <span class="mb-2 block text-sm">{{
                $t('routing.networks')
              }}</span>
              <div class="flex h-11 items-center gap-4">
                <label class="inline-flex items-center gap-2"
                  ><input
                    v-model="rule.networks"
                    type="checkbox"
                    value="tcp"
                  />TCP</label
                >
                <label class="inline-flex items-center gap-2"
                  ><input
                    v-model="rule.networks"
                    type="checkbox"
                    value="udp"
                  />UDP</label
                >
              </div>
            </div>
            <div>
              <label
                :for="`rule-ports-${rule.id}`"
                class="mb-2 block text-sm"
                >{{ $t('routing.ports') }}</label
              ><BaseInput
                :id="`rule-ports-${rule.id}`"
                :model-value="rule.ports.join(', ')"
                class="w-full px-3 py-2"
                placeholder="80, 443, 8000-8100"
                @update:model-value="rule.ports = lines($event)"
              />
            </div>
            <div v-for="field in selectorFields" :key="field">
              <label
                :for="`rule-${field}-${rule.id}`"
                class="mb-2 block text-sm"
                >{{ $t(`routing.${field}`) }}</label
              >
              <BaseTextArea
                :id="`rule-${field}-${rule.id}`"
                :model-value="rule[field].join('\n')"
                rows="4"
                class="w-full px-3 py-2 font-mono text-sm"
                :placeholder="$t(`routing.${field}Placeholder`)"
                @update:model-value="rule[field] = lines($event)"
              />
            </div>
          </div>
          <div class="mt-4">
            <h5 class="mb-2 font-medium">{{ $t('routing.ruleSets') }}</h5>
            <div
              v-for="(set, setIndex) in rule.ruleSets"
              :key="setIndex"
              class="mb-3 grid grid-cols-1 items-end gap-3 md:grid-cols-[1fr_2fr_auto_auto]"
            >
              <div>
                <label
                  :for="`set-tag-${rule.id}-${setIndex}`"
                  class="mb-1 block text-sm"
                  >{{ $t('routing.identifier') }}</label
                ><BaseInput
                  :id="`set-tag-${rule.id}-${setIndex}`"
                  v-model="set.tag"
                  class="w-full px-3 py-2"
                  placeholder="rules-list"
                />
              </div>
              <div>
                <label
                  :for="`set-url-${rule.id}-${setIndex}`"
                  class="mb-1 block text-sm"
                  >HTTPS URL</label
                ><BaseInput
                  :id="`set-url-${rule.id}-${setIndex}`"
                  v-model="set.url"
                  type="url"
                  class="w-full px-3 py-2"
                  placeholder="https://example.com/rules.srs"
                />
              </div>
              <select
                v-model="set.format"
                :aria-label="$t('routing.ruleSetFormat')"
                class="rounded-lg border-2 border-gray-100 bg-white px-3 py-2 dark:border-neutral-800 dark:bg-neutral-700"
              >
                <option value="binary">SRS</option>
                <option value="source">JSON</option>
              </select>
              <BaseSecondaryButton
                type="button"
                :aria-label="$t('routing.removeRuleSet')"
                @click="rule.ruleSets.splice(setIndex, 1)"
                ><IconsDelete class="size-4"
              /></BaseSecondaryButton>
            </div>
            <BaseSecondaryButton type="button" @click="addRuleSet(rule)"
              ><IconsPlus class="mr-2 size-4" />{{
                $t('routing.addRuleSet')
              }}</BaseSecondaryButton
            >
          </div>
        </article>
        <p v-if="!config.rules.length" class="col-span-full text-sm">
          {{ $t('routing.noRules') }}
        </p>
        <BaseSecondaryButton
          type="button"
          class="col-span-full justify-center"
          @click="addRule"
          ><IconsPlus class="mr-2 size-4" />{{
            $t('routing.addRule')
          }}</BaseSecondaryButton
        >
      </FormGroup>

      <FormGroup>
        <FormHeading>{{ $t('form.actions') }}</FormHeading>
        <p class="col-span-full text-sm text-gray-500 dark:text-neutral-300">
          {{ $t('routing.saveDescription') }}
        </p>
        <BaseSecondaryButton
          type="button"
          class="col-span-full justify-center"
          :disabled="busy"
          @click="preview"
          >{{ $t('routing.preview') }}</BaseSecondaryButton
        >
        <FormPrimaryActionField
          type="submit"
          :label="$t(busy ? 'general.loading' : 'routing.saveOnly')"
          :disabled="busy"
        />
        <BaseSecondaryButton
          type="button"
          class="col-span-full justify-center"
          :disabled="busy"
          @click="save(true)"
          >{{ $t('routing.saveApply') }}</BaseSecondaryButton
        >
        <FormSecondaryActionField
          :label="$t('form.revert')"
          :disabled="busy"
          @click="reload"
        />
      </FormGroup>
    </FormElement>
    <section v-if="previewResult" class="mt-6 space-y-3">
      <h3 class="text-2xl">{{ $t('routing.previewTitle') }}</h3>
      <p class="text-sm text-gray-500 dark:text-neutral-300">
        {{ $t('routing.previewDescription') }}
      </p>
      <p
        v-for="warning in previewResult.warnings"
        :key="warning"
        class="text-sm text-amber-700 dark:text-amber-300"
      >
        {{ warning }}
      </p>
      <details
        class="rounded-lg border-2 border-gray-100 p-3 dark:border-neutral-600"
      >
        <summary class="cursor-pointer">
          {{ $t('routing.previewEgresses') }}
        </summary>
        <BaseCodeBlock
          :code="JSON.stringify(previewResult.egresses, null, 2)"
          class="mt-3"
        />
      </details>
      <details
        class="rounded-lg border-2 border-gray-100 p-3 dark:border-neutral-600"
      >
        <summary class="cursor-pointer">sing-box</summary>
        <BaseCodeBlock
          :code="JSON.stringify(previewResult.singBox, null, 2)"
          class="mt-3"
        />
      </details>
      <details
        class="rounded-lg border-2 border-gray-100 p-3 dark:border-neutral-600"
      >
        <summary class="cursor-pointer">nftables</summary>
        <BaseCodeBlock :code="previewResult.nftables" class="mt-3" />
      </details>
    </section>
  </main>
</template>

<script setup lang="ts">
import { FetchError } from 'ofetch';

import type {
  RoutingConfig,
  RoutingEgress,
  RoutingRule,
  RoutingStatus,
} from '../../../shared/types/routing';

type ImportResult = {
  valid: true;
  summary: {
    address: string;
    endpoint: string;
    mtu: number;
    parameterNames: string[];
    keepalive: string | null;
  };
  warnings: string[];
};
type PreviewResult = {
  valid: true;
  singBox: Record<string, unknown>;
  nftables: string;
  egresses: {
    id: string;
    interfaceName: string;
    address: string;
    endpoint: string;
    mtu: number;
  }[];
  warnings: string[];
};
const { t } = useI18n();
const toast = useToast();
const {
  data: response,
  error: loadError,
  refresh,
} = await useFetch('/api/admin/routing');
const config = ref<RoutingConfig | null>(null);
const status = ref<RoutingStatus | null>(null);
const busy = ref(false);
const acknowledged = reactive<Record<string, boolean>>({});
const revealed = reactive<Record<string, boolean>>({});
const imports = reactive<Record<string, ImportResult>>({});
const previewResult = ref<PreviewResult | null>(null);
const selectorFields = ['domains', 'suffixes', 'cidrs'] as const;

function restore() {
  if (!response.value) return;
  config.value = structuredClone(toRaw(response.value.config));
  status.value = response.value.status;
  for (const egress of config.value.egresses) acknowledged[egress.id] = true;
  for (const id of Object.keys(imports)) Reflect.deleteProperty(imports, id);
  previewResult.value = null;
}
restore();

async function reload() {
  await refresh();
  restore();
}
function identifier(prefix: string) {
  return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
}
function lines(value: unknown) {
  return [
    ...new Set(
      String(value ?? '')
        .split(/[\n,]+/)
        .map((line) => line.trim())
        .filter(Boolean)
    ),
  ];
}
function errorToast(error: unknown) {
  toast.showToast({
    type: 'error',
    message:
      error instanceof FetchError
        ? (error.data?.message ?? error.message)
        : error instanceof Error
          ? error.message
          : t('toast.unknown'),
  });
}

function addEgress() {
  if (!config.value) return;
  const id = identifier('egress');
  config.value.egresses.push({
    id,
    name: t('routing.newEgress'),
    profile: '',
    independentPeer: true,
  });
  acknowledged[id] = false;
  revealed[id] = true;
}
function removeEgress(id: string) {
  if (!config.value) return;
  if (config.value.rules.some((rule) => rule.outbound === id)) {
    errorToast(new Error(t('routing.egressInUse')));
    return;
  }
  config.value.egresses = config.value.egresses.filter(
    (egress) => egress.id !== id
  );
  Reflect.deleteProperty(acknowledged, id);
  Reflect.deleteProperty(revealed, id);
  Reflect.deleteProperty(imports, id);
}
async function uploadProfile(id: string, event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file || !config.value) return;
  try {
    if (file.size > 262144) throw new Error(t('routing.profileTooLarge'));
    const egress = config.value.egresses.find((item) => item.id === id);
    if (egress) {
      egress.profile = await file.text();
      Reflect.deleteProperty(imports, id);
      revealed[id] = false;
    }
  } catch (error) {
    errorToast(error);
  }
  input.value = '';
}
function clearImport(id: string) {
  Reflect.deleteProperty(imports, id);
}
async function validateProfile(egress: RoutingEgress) {
  busy.value = true;
  try {
    imports[egress.id] = await $fetch<ImportResult>(
      '/api/admin/routing/import',
      { method: 'post', body: { profile: egress.profile } }
    );
  } catch (error) {
    Reflect.deleteProperty(imports, egress.id);
    errorToast(error);
  } finally {
    busy.value = false;
  }
}
function makeRule(
  name = t('routing.newRule'),
  outbound = 'direct'
): RoutingRule {
  return {
    id: identifier('rule'),
    name,
    enabled: true,
    networks: ['tcp'],
    ports: ['443'],
    domains: [],
    suffixes: [],
    cidrs: [],
    ruleSets: [],
    outbound,
  };
}
function addRule() {
  config.value?.rules.push(makeRule());
}
function moveRule(index: number, direction: -1 | 1) {
  if (!config.value) return;
  const next = index + direction;
  if (next < 0 || next >= config.value.rules.length) return;
  const [rule] = config.value.rules.splice(index, 1);
  if (rule) config.value.rules.splice(next, 0, rule);
}
function addRuleSet(rule: RoutingRule) {
  rule.ruleSets.push({ tag: identifier('set'), url: '', format: 'binary' });
}
function checkAcknowledgements() {
  const missing = config.value?.egresses.find(
    (egress) => !acknowledged[egress.id]
  );
  if (missing)
    throw new Error(t('routing.independentRequired', { name: missing.name }));
}
async function preview() {
  if (!config.value || busy.value) return;
  busy.value = true;
  try {
    checkAcknowledgements();
    previewResult.value = await $fetch<PreviewResult>(
      '/api/admin/routing/preview',
      { method: 'post', body: { config: config.value } }
    );
  } catch (error) {
    previewResult.value = null;
    errorToast(error);
  } finally {
    busy.value = false;
  }
}
async function save(apply: boolean) {
  if (!config.value || busy.value) return;
  busy.value = true;
  try {
    checkAcknowledgements();
    const result = await $fetch<{ success: true; status: RoutingStatus }>(
      '/api/admin/routing',
      { method: 'post', body: { config: config.value, apply } }
    );
    status.value = result.status;
    await refresh();
    restore();
    toast.showToast({
      type: 'success',
      message: t(apply ? 'routing.applied' : 'routing.saved'),
    });
  } catch (error) {
    errorToast(error);
  } finally {
    busy.value = false;
  }
}
</script>

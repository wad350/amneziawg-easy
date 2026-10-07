<template>
  <main v-if="data">
    <FormElement @submit.prevent="submit">
      <FormGroup>
        <FormNumberField
          id="mtu"
          v-model="data.mtu"
          :label="$t('general.mtu')"
          :description="$t('admin.interface.mtuDesc')"
        />
        <FormNumberField
          id="port"
          v-model="data.port"
          :label="$t('general.port')"
          :description="$t('admin.interface.portDesc')"
        />
        <FormTextField
          id="device"
          v-model="data.device"
          :label="$t('admin.interface.device')"
          :description="$t('admin.interface.deviceDesc')"
        />
        <FormTextField
          id="routingTable"
          v-model="data.routingTable"
          :label="$t('admin.interface.routingTable')"
          :description="$t('admin.interface.routingTableDesc')"
        />
      </FormGroup>
      <FormGroup v-if="globalStore.information?.isAwg">
        <FormHeading>{{ $t('awg.obfuscationParameters') }}</FormHeading>
        <p
          class="col-span-full rounded-lg border border-amber-300 p-3 text-sm dark:border-amber-700"
          role="note"
        >
          {{ $t('awg31.sharedWarning') }}
        </p>
        <BaseSecondaryButton
          type="button"
          class="col-span-full justify-center"
          :disabled="generating"
          @click="generate"
        >
          <IconsSparkles class="mr-2 size-4" />
          {{ $t(generating ? 'general.loading' : 'awg31.generate') }}
        </BaseSecondaryButton>
        <p v-if="generated" class="col-span-full text-sm" role="status">
          {{ $t('awg31.generatedPreview') }}
        </p>

        <FormNullNumberField
          id="jC"
          v-model="data.jC"
          :label="$t('awg.jCLabel')"
          :description="$t('awg.jCDescription')"
        />
        <FormNullNumberField
          id="jMin"
          v-model="data.jMin"
          :label="$t('awg.jMinLabel')"
          :description="$t('awg.jMinDescription')"
        />
        <FormNullNumberField
          id="jMax"
          v-model="data.jMax"
          :label="$t('awg.jMaxLabel')"
          :description="$t('awg.jMaxDescription')"
        />
        <FormNullNumberField
          id="s1"
          v-model="data.s1"
          :label="$t('awg.s1Label')"
          :description="$t('awg.s1Description')"
        />
        <FormNullNumberField
          id="s2"
          v-model="data.s2"
          :label="$t('awg.s2Label')"
          :description="$t('awg.s2Description')"
        />

        <div class="col-span-full text-sm">* {{ $t('awg.mtuNote') }}</div>

        <FormNullNumberField
          id="s3"
          v-model="data.s3"
          :label="$t('awg.s3Label')"
          :description="$t('awg.s3Description')"
        />
        <FormNullNumberField
          id="s4"
          v-model="data.s4"
          :label="$t('awg.s4Label')"
          :description="$t('awg.s4Description')"
        />
        <FormNullTextField
          id="h1"
          v-model="data.h1"
          :label="$t('awg.h1Label')"
          :description="$t('awg.h1Description')"
        />
        <FormNullTextField
          id="h2"
          v-model="data.h2"
          :label="$t('awg.h2Label')"
          :description="$t('awg.h2Description')"
        />
        <FormNullTextField
          id="h3"
          v-model="data.h3"
          :label="$t('awg.h3Label')"
          :description="$t('awg.h3Description')"
        />
        <FormNullTextField
          id="h4"
          v-model="data.h4"
          :label="$t('awg.h4Label')"
          :description="$t('awg.h4Description')"
        />
        <FormNullTextField
          id="i1"
          v-model="data.i1"
          :label="$t('awg.i1Label')"
          :description="$t('awg.i1Description')"
        />
        <FormNullTextField
          id="i2"
          v-model="data.i2"
          :label="$t('awg.i2Label')"
          :description="$t('awg.i2Description')"
        />
        <FormNullTextField
          id="i3"
          v-model="data.i3"
          :label="$t('awg.i3Label')"
          :description="$t('awg.i3Description')"
        />
        <FormNullTextField
          id="i4"
          v-model="data.i4"
          :label="$t('awg.i4Label')"
          :description="$t('awg.i4Description')"
        />
        <FormNullTextField
          id="i5"
          v-model="data.i5"
          :label="$t('awg.i5Label')"
          :description="$t('awg.i5Description')"
        />
      </FormGroup>
      <FormGroup v-if="globalStore.information?.isAwg">
        <AwgSettings v-model="data.awgSettings" prefix="interface-awg31" />
      </FormGroup>
      <FormGroup>
        <FormHeading>{{ $t('admin.interface.firewall') }}</FormHeading>
        <FormSwitchField
          id="firewallEnabled"
          v-model="data.firewallEnabled"
          :label="$t('admin.interface.firewallEnabled')"
          :description="$t('admin.interface.firewallEnabledDesc')"
        />
      </FormGroup>
      <FormGroup>
        <FormHeading>{{ $t('form.actions') }}</FormHeading>
        <FormPrimaryActionField type="submit" :label="$t('form.save')" />
        <FormSecondaryActionField :label="$t('form.revert')" @click="revert" />
        <AdminCidrDialog
          trigger-class="col-span-2"
          :ipv4-cidr="data.ipv4Cidr"
          :ipv6-cidr="data.ipv6Cidr"
          @change="changeCidr"
        >
          <FormSecondaryActionField
            :label="$t('admin.interface.changeCidr')"
            class="inline-block w-full"
            as="span"
          />
        </AdminCidrDialog>
        <AdminRestartInterfaceDialog
          trigger-class="col-span-2"
          @restart="restartInterface"
        >
          <FormSecondaryActionField
            :label="$t('admin.interface.restart')"
            class="inline-block w-full"
            as="span"
          />
        </AdminRestartInterfaceDialog>
      </FormGroup>
    </FormElement>
  </main>
</template>

<script setup lang="ts">
const globalStore = useGlobalStore();

const { t } = useI18n();

const { data: _data, refresh } = await useFetch(`/api/admin/interface`, {
  method: 'get',
});

const data = toRef(_data.value);
const generating = ref(false);
const generated = ref(false);
const toast = useToast();

async function generate() {
  generating.value = true;
  try {
    const preview = await $fetch('/api/admin/interface/generate', {
      method: 'post',
    });
    if (data.value) Object.assign(data.value, preview);
    generated.value = true;
  } catch (error) {
    toast.showToast({
      type: 'error',
      message: error instanceof Error ? error.message : t('toast.unknown'),
    });
  } finally {
    generating.value = false;
  }
}

const _submit = useSubmit(
  (data) =>
    $fetch(`/api/admin/interface`, {
      method: 'post',
      body: data,
    }),
  {
    revert: async (success) => {
      await revert();
      if (success) {
        // Refresh global store information after successful save
        await globalStore.refreshInformation();
      }
    },
  }
);

function submit() {
  return _submit(data.value);
}

async function revert() {
  generated.value = false;
  await refresh();
  data.value = toRef(_data.value).value;
}

const _changeCidr = useSubmit(
  (data) =>
    $fetch(`/api/admin/interface/cidr`, {
      method: 'post',
      body: data,
    }),
  {
    revert,
    successMsg: t('admin.interface.cidrSuccess'),
  }
);

async function changeCidr(ipv4Cidr: string, ipv6Cidr: string) {
  await _changeCidr({ ipv4Cidr, ipv6Cidr });
}

const _restartInterface = useSubmit(
  (data) =>
    $fetch(`/api/admin/interface/restart`, {
      method: 'post',
      body: data,
    }),
  {
    revert,
    successMsg: t('admin.interface.restartSuccess'),
  }
);

async function restartInterface() {
  await _restartInterface(undefined);
}
</script>

import type { ClientType } from '../database/repositories/client/types';
import type { InterfaceType } from '../database/repositories/interface/types';
import type { UserConfigType } from '../database/repositories/userConfig/types';
import type { AwgParameters, AwgSettings } from '../../shared/types/amneziawg';
import type { RoutingConfig, RoutingStatus } from '../../shared/types/routing';
import type { IntegrationClientStatus } from '../../shared/types/integrationApi';

import { resolveClientAwgSettings } from './amneziawg';
import { routingRevision } from './routingRevision';

export type IntegrationClientSource = Omit<
  ClientType,
  'privateKey' | 'preSharedKey' | 'createdAt' | 'updatedAt'
> & {
  createdAt: string | Date;
  updatedAt: string | Date;
} & Partial<IntegrationClientStatus>;

/** Explicit whitelist: future database fields cannot silently become API secrets. */
export function publicAwgSettings(settings: AwgSettings | null) {
  return {
    contentPaddingAddition: settings?.contentPaddingAddition ?? null,
    rekeyAfterTime: settings?.rekeyAfterTime ?? null,
    rekeyTimeout: settings?.rekeyTimeout ?? null,
    rejectAfterTime: settings?.rejectAfterTime ?? null,
    keepaliveTimeout: settings?.keepaliveTimeout ?? null,
    maxHandshakeAttempts: settings?.maxHandshakeAttempts ?? null,
    randomTrailers: settings?.randomTrailers ?? null,
    disableCookies: settings?.disableCookies ?? null,
    persistentKeepaliveRange: settings?.persistentKeepaliveRange ?? null,
  };
}

export function publicAwgParameters(value: AwgParameters) {
  return {
    jC: value.jC,
    jMin: value.jMin,
    jMax: value.jMax,
    s1: value.s1,
    s2: value.s2,
    s3: value.s3,
    s4: value.s4,
    h1: value.h1,
    h2: value.h2,
    h3: value.h3,
    h4: value.h4,
    i1: value.i1,
    i2: value.i2,
    i3: value.i3,
    i4: value.i4,
    i5: value.i5,
    settings: publicAwgSettings(value.awgSettings),
  };
}

export function toIntegrationClient<T extends IntegrationClientSource>(
  client: T,
  iface: InterfaceType,
  defaults: UserConfigType,
  options: { enableIpv6?: boolean } = {}
) {
  const awgSettings = resolveClientAwgSettings(
    iface.awgSettings,
    client.awgSettings
  );
  return {
    id: client.id,
    name: client.name,
    enabled: client.enabled,
    ipv4Address: client.ipv4Address,
    ipv6Address: options.enableIpv6 === false ? null : client.ipv6Address,
    publicKey: client.publicKey,
    expiresAt: client.expiresAt,
    createdAt: client.createdAt,
    updatedAt: client.updatedAt,
    dns: client.dns ?? defaults.defaultDns,
    allowedIps: client.allowedIps ?? defaults.defaultAllowedIps,
    mtu: client.mtu,
    persistentKeepalive:
      awgSettings?.persistentKeepaliveRange ?? client.persistentKeepalive,
    latestHandshakeAt: client.latestHandshakeAt ?? null,
    endpoint: client.endpoint ?? null,
    transferRx: client.transferRx ?? null,
    transferTx: client.transferTx ?? null,
    awg: publicAwgParameters({
      ...iface,
      jC: client.jC,
      jMin: client.jMin,
      jMax: client.jMax,
      i1: client.i1,
      i2: client.i2,
      i3: client.i3,
      i4: client.i4,
      i5: client.i5,
      awgSettings,
    }),
  };
}

export function toIntegrationRouting(
  config: RoutingConfig,
  status: RoutingStatus
) {
  return {
    revision: routingRevision(config),
    enabled: config.enabled,
    rules: config.rules,
    egresses: config.egresses.map(({ id, name }) => ({ id, name })),
    status,
  };
}

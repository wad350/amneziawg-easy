import { setHeader } from 'h3';

import Database from '#server/utils/Database';
import { RELEASE, WG_ENV } from '#server/utils/config';
import { definePermissionEventHandler } from '#server/utils/handler';
import { publicAwgParameters } from '#server/utils/integrationApi';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    const iface = await Database.interfaces.get();
    const defaults = await Database.userConfigs.get();
    return {
      apiVersion: 'v1',
      applicationVersion: RELEASE,
      protocol: WG_ENV.WG_EXECUTABLE === 'awg' ? 'amneziawg' : 'wireguard',
      protocolVersion: WG_ENV.WG_EXECUTABLE === 'awg' ? '3.1' : null,
      endpoint: { host: defaults.host, port: defaults.port },
      interface: {
        name: iface.name,
        enabled: iface.enabled,
        publicKey: iface.publicKey,
        mtu: iface.mtu,
        ipv4Cidr: iface.ipv4Cidr,
        ipv6Cidr: WG_ENV.DISABLE_IPV6 ? null : iface.ipv6Cidr,
        awg: WG_ENV.WG_EXECUTABLE === 'awg' ? publicAwgParameters(iface) : null,
      },
      defaults: {
        dns: defaults.defaultDns,
        allowedIps: defaults.defaultAllowedIps,
        mtu: defaults.defaultMtu,
        persistentKeepalive: defaults.defaultPersistentKeepalive,
      },
    };
  }
);

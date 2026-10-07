import type { RoutingContext } from './routingConfig';

import Database from '#server/utils/Database';

export async function getRoutingContext(): Promise<RoutingContext> {
  const iface = await Database.interfaces.get();
  const clients = await Database.clients.getAll();
  return {
    inboundInterface: iface.name,
    sourceCidr: iface.ipv4Cidr,
    inboundPort: iface.port,
    inboundPrivateKeys: [
      iface.privateKey,
      ...clients.map((client) => client.privateKey),
    ],
  };
}

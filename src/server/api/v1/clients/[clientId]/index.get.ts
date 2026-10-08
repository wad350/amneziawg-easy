import { createError, getValidatedRouterParams, setHeader } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { WG_ENV } from '#server/utils/config';
import { definePermissionEventHandler } from '#server/utils/handler';
import { toIntegrationClient } from '#server/utils/integrationApi';
import { IntegrationClientIdSchema } from '#server/utils/integrationApiSchemas';
import { validateZod } from '#server/utils/types';

export default definePermissionEventHandler(
  'clients',
  'view',
  async ({ event, checkPermissions }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    const { clientId } = await getValidatedRouterParams(
      event,
      validateZod(IntegrationClientIdSchema, event)
    );
    const client = await Database.clients.get(clientId);
    if (!client)
      throw createError({ statusCode: 404, statusMessage: 'Client not found' });
    checkPermissions(client);
    const status = await WireGuard.dumpByPublicKey(client.publicKey);
    const iface = await Database.interfaces.get();
    const defaults = await Database.userConfigs.get();
    return {
      client: toIntegrationClient(
        {
          ...client,
          latestHandshakeAt: status?.latestHandshakeAt ?? null,
          endpoint: status?.endpoint ?? null,
          transferRx: status?.transferRx ?? null,
          transferTx: status?.transferTx ?? null,
        },
        iface,
        defaults,
        { enableIpv6: !WG_ENV.DISABLE_IPV6 }
      ),
    };
  }
);

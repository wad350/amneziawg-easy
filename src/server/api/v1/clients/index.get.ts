import { getValidatedQuery, setHeader } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { WG_ENV } from '#server/utils/config';
import { definePermissionEventHandler } from '#server/utils/handler';
import { toIntegrationClient } from '#server/utils/integrationApi';
import { IntegrationClientQuerySchema } from '#server/utils/integrationApiSchemas';
import { validateZod } from '#server/utils/types';
import { roles } from '#shared/utils/permissions';

export default definePermissionEventHandler(
  'clients',
  'custom',
  async ({ event, user }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    const query = await getValidatedQuery(
      event,
      validateZod(IntegrationClientQuerySchema, event)
    );
    const clients =
      user.role === roles.ADMIN
        ? await WireGuard.getAllClients(query)
        : await WireGuard.getClientsForUser(user.id, query);
    const iface = await Database.interfaces.get();
    const defaults = await Database.userConfigs.get();
    return {
      clients: clients.map((client) =>
        toIntegrationClient(client, iface, defaults, {
          enableIpv6: !WG_ENV.DISABLE_IPV6,
        })
      ),
    };
  }
);

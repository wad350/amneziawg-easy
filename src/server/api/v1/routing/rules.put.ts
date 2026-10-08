import { createError, readValidatedBody, setHeader } from 'h3';

import { IntegrationRulesUpdateSchema } from '#shared/types/integrationApi';
import { definePermissionEventHandler } from '#server/utils/handler';
import { toIntegrationRouting } from '#server/utils/integrationApi';
import { getRoutingContext } from '#server/utils/routingContext';
import { RoutingRevisionConflict } from '#server/utils/routingRevision';
import { saveRoutingRulesWithRevision } from '#server/utils/routingRuntime';
import { validateZod } from '#server/utils/types';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    const update = await readValidatedBody(
      event,
      validateZod(IntegrationRulesUpdateSchema, event)
    );
    try {
      const { config, status } = await saveRoutingRulesWithRevision(
        update,
        await getRoutingContext()
      );
      return { success: true, ...toIntegrationRouting(config, status) };
    } catch (error) {
      if (error instanceof RoutingRevisionConflict)
        throw createError({
          statusCode: 409,
          statusMessage: 'Routing changed; reload before editing',
        });
      throw createError({
        statusCode: 400,
        statusMessage: 'Routing update rejected; private output withheld',
      });
    }
  }
);

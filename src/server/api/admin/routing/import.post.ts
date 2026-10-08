import { createError, readValidatedBody, setHeader } from 'h3';

import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { RoutingImportSchema } from '#shared/types/routing';
import { parseAwgProfile } from '#server/utils/routingConfig';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    const data = await readValidatedBody(
      event,
      validateZod(RoutingImportSchema, event)
    );
    try {
      const profile = parseAwgProfile(data.profile);
      return {
        valid: true,
        summary: {
          address: profile.address,
          endpoint: profile.peer.Endpoint,
          mtu: profile.mtu,
          parameterNames: Object.keys(profile.interface).filter(
            (key) => !['PrivateKey', 'HeaderProtectionKey'].includes(key)
          ),
          keepalive: profile.peer.PersistentKeepalive ?? null,
        },
        warnings: [
          'Use a separately allocated peer; do not import another running VPN profile.',
          ...(profile.interface.DNS
            ? [
                'Imported DNS is preserved as metadata; outbound runtime does not change system DNS.',
              ]
            : []),
        ],
      };
    } catch {
      throw createError({
        statusCode: 400,
        statusMessage: 'AWG outbound import rejected; private values withheld',
      });
    }
  }
);

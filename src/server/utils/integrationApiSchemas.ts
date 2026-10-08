import z from 'zod';

import {
  ClientCreateSchema,
  ClientUpdateSchema,
} from '../database/repositories/client/types';

export const IntegrationClientIdSchema = z.object({
  clientId: z.coerce.number().int().positive(),
});

export const IntegrationClientQuerySchema = z
  .object({
    filter: z.string().max(256).optional(),
    sort: z.enum(['asc', 'desc']).optional(),
  })
  .strict();

export const IntegrationClientCreateSchema = ClientCreateSchema.extend({
  name: ClientCreateSchema.shape.name.refine((value) => value.length <= 120),
  expiresAt: ClientCreateSchema.shape.expiresAt
    .refine((value) => value === null || Number.isFinite(Date.parse(value)), {
      message: 'Expiration must be a valid date or null',
    })
    .default(null),
}).strict();

/** Credentials, tunnel addresses, hooks and shared handshake settings are immutable. */
export const IntegrationClientPatchSchema = z
  .object({
    name: ClientUpdateSchema.shape.name
      .refine((value) => value.length <= 120)
      .optional(),
    enabled: ClientUpdateSchema.shape.enabled.optional(),
    expiresAt: ClientUpdateSchema.shape.expiresAt
      .refine((value) => value === null || Number.isFinite(Date.parse(value)), {
        message: 'Expiration must be a valid date or null',
      })
      .optional(),
    dns: ClientUpdateSchema.shape.dns.optional(),
    allowedIps: ClientUpdateSchema.shape.allowedIps.optional(),
    mtu: ClientUpdateSchema.shape.mtu.int().optional(),
    persistentKeepalive: ClientUpdateSchema.shape.persistentKeepalive
      .int()
      .optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, {
    message: 'At least one editable field is required',
  });

export type IntegrationClientPatch = z.output<
  typeof IntegrationClientPatchSchema
>;

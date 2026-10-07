import z from 'zod';

import { RoutingRuleSchema } from './routing';

export const IntegrationRulesUpdateSchema = z
  .object({
    revision: z.string().regex(/^[a-f0-9]{64}$/),
    rules: z.array(RoutingRuleSchema).max(256),
    enabled: z.boolean().optional(),
    apply: z.boolean().default(false),
  })
  .strict();

export type IntegrationRulesUpdate = z.output<
  typeof IntegrationRulesUpdateSchema
>;

export type IntegrationClientStatus = {
  latestHandshakeAt: Date | null;
  endpoint: string | null;
  transferRx: number | null;
  transferTx: number | null;
};

import z from 'zod';

const id = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/);
const domain = z
  .string()
  .max(253)
  .regex(
    /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i
  );
const port = z
  .string()
  .regex(/^\d{1,5}(?:-\d{1,5})?$/)
  .refine((v) => {
    const [a, b = a] = v.split('-').map(Number);
    return a! >= 1 && b! <= 65535 && a! <= b!;
  }, 'Invalid port or port range');

export const RoutingRuleSetSchema = z
  .object({
    tag: id,
    url: z.url().refine((v) => {
      const u = new URL(v);
      return (
        u.protocol === 'https:' &&
        !u.username &&
        !u.password &&
        !u.hash &&
        !u.search &&
        [
          'raw.githubusercontent.com',
          'github.com',
          'cdn.jsdelivr.net',
        ].includes(u.hostname) &&
        (!u.port || u.port === '443')
      );
    }, 'Rule sets require a public HTTPS URL without credentials'),
    format: z.enum(['binary', 'source']).default('binary'),
  })
  .strict();

export const RoutingRuleSchema = z
  .object({
    id,
    name: z.string().min(1).max(120),
    enabled: z.boolean().default(true),
    networks: z
      .array(z.enum(['tcp', 'udp']))
      .min(1)
      .max(2),
    ports: z.array(port).min(1).max(64),
    domains: z.array(domain).max(40000).default([]),
    suffixes: z.array(domain).max(40000).default([]),
    cidrs: z.array(z.string().max(18)).max(40000).default([]),
    ruleSets: z.array(RoutingRuleSetSchema).max(16).default([]),
    outbound: z.union([z.literal('direct'), id]),
  })
  .strict()
  .refine(
    (v) =>
      v.domains.length +
        v.suffixes.length +
        v.cidrs.length +
        v.ruleSets.length >
      0,
    'A routing rule must have a selector'
  );

export const RoutingEgressSchema = z
  .object({
    id: id.refine((v) => v !== 'direct', 'Reserved outbound name'),
    name: z.string().min(1).max(120),
    profile: z.string().min(1).max(262144),
    // Importing a running peer in another instance causes endpoint roaming.
    independentPeer: z.literal(true),
  })
  .strict();

export const RoutingConfigSchema = z
  .object({
    version: z.literal(1).default(1),
    enabled: z.boolean().default(false),
    egresses: z.array(RoutingEgressSchema).max(16).default([]),
    rules: z.array(RoutingRuleSchema).max(256).default([]),
  })
  .strict()
  .superRefine((config, ctx) => {
    for (const [field, values] of [
      ['egresses', config.egresses],
      ['rules', config.rules],
    ] as const) {
      if (new Set(values.map((v) => v.id)).size !== values.length) {
        ctx.addIssue({
          code: 'custom',
          path: [field],
          message: 'Duplicate identifiers',
        });
      }
    }
    const names = new Set(['direct', ...config.egresses.map((v) => v.id)]);
    config.rules.forEach((rule, index) => {
      if (!names.has(rule.outbound))
        ctx.addIssue({
          code: 'custom',
          path: ['rules', index, 'outbound'],
          message: 'Unknown outbound',
        });
      if (new Set(rule.networks).size !== rule.networks.length)
        ctx.addIssue({
          code: 'custom',
          path: ['rules', index, 'networks'],
          message: 'Duplicate network',
        });
    });
  });

export type RoutingConfig = z.output<typeof RoutingConfigSchema>;
export type RoutingRule = RoutingConfig['rules'][number];
export type RoutingEgress = RoutingConfig['egresses'][number];
export const RoutingSaveSchema = z
  .object({ config: RoutingConfigSchema, apply: z.boolean().default(false) })
  .strict();
export const RoutingImportSchema = z
  .object({ profile: z.string().min(1).max(262144) })
  .strict();

export interface RoutingStatus {
  state: 'stopped' | 'running' | 'failed';
  enabled: boolean;
  pid: number | null;
  appliedAt: string | null;
  error: string | null;
}

export interface RoutingResponse {
  config: RoutingConfig;
  status: RoutingStatus;
}

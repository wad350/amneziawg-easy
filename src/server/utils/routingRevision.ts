import { createHash } from 'node:crypto';

import {
  RoutingConfigSchema,
  type RoutingConfig,
} from '../../shared/types/routing';
import type { IntegrationRulesUpdate } from '../../shared/types/integrationApi';

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export function routingRevision(config: RoutingConfig): string {
  return createHash('sha256').update(canonical(config)).digest('hex');
}

export class RoutingRevisionConflict extends Error {
  constructor() {
    super('Routing configuration changed; reload it before editing');
  }
}

/** Merge rules without accepting or disclosing outbound credentials. */
export function mergeRoutingRules(
  current: RoutingConfig,
  update: IntegrationRulesUpdate
): RoutingConfig {
  if (routingRevision(current) !== update.revision)
    throw new RoutingRevisionConflict();
  return RoutingConfigSchema.parse({
    ...current,
    rules: update.rules,
    enabled: update.enabled ?? current.enabled,
  });
}

import z from 'zod';

import { IntegrationRulesUpdateSchema } from '../../shared/types/integrationApi';
import { RoutingRuleSchema } from '../../shared/types/routing';

import {
  IntegrationClientCreateSchema,
  IntegrationClientPatchSchema,
} from './integrationApiSchemas';

type Schema = Record<string, unknown>;
const string: Schema = { type: 'string' };
const nullableString: Schema = { type: ['string', 'null'] };
const integer: Schema = { type: 'integer' };
const nullableNumber: Schema = { type: ['number', 'null'] };
const boolean: Schema = { type: 'boolean' };
const strings: Schema = { type: 'array', items: string };
const ref = (name: string): Schema => ({
  $ref: `#/components/schemas/${name}`,
});
const object = (properties: Record<string, Schema>): Schema => ({
  type: 'object',
  properties,
  required: Object.keys(properties),
  additionalProperties: false,
});
const input = (schema: z.ZodType) =>
  z.toJSONSchema(schema, { io: 'input', unrepresentable: 'any' });

function clientCreateInput() {
  const schema = input(IntegrationClientCreateSchema);
  // The native schema rejects shared-only fields in a runtime refinement.
  // JSON Schema cannot encode that refinement, so omit those rejected inputs.
  function removeSharedFields(value: unknown): void {
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      value.forEach(removeSharedFields);
      return;
    }
    const item = value as Record<string, unknown>;
    if (item.properties && typeof item.properties === 'object') {
      const properties = item.properties as Record<string, unknown>;
      delete properties.headerProtectionKey;
      delete properties.randomTrailers;
    }
    if (Array.isArray(item.required))
      item.required = item.required.filter(
        (field) => field !== 'headerProtectionKey' && field !== 'randomTrailers'
      );
    Object.values(item).forEach(removeSharedFields);
  }
  removeSharedFields(schema.properties?.awgSettings);
  return schema;
}

const publicAwgSettings = object({
  contentPaddingAddition: nullableString,
  rekeyAfterTime: nullableString,
  rekeyTimeout: nullableString,
  rejectAfterTime: nullableString,
  keepaliveTimeout: nullableString,
  maxHandshakeAttempts: nullableString,
  randomTrailers: { type: ['boolean', 'null'] },
  disableCookies: { type: ['boolean', 'null'] },
  persistentKeepaliveRange: nullableString,
});
const publicAwg = object({
  ...Object.fromEntries(
    ['jC', 'jMin', 'jMax', 's1', 's2', 's3', 's4'].map((key) => [
      key,
      nullableNumber,
    ])
  ),
  ...Object.fromEntries(
    ['h1', 'h2', 'h3', 'h4', 'i1', 'i2', 'i3', 'i4', 'i5'].map((key) => [
      key,
      nullableString,
    ])
  ),
  settings: ref('PublicAwgSettings'),
});
const client = object({
  id: { ...integer, minimum: 1 },
  name: string,
  enabled: boolean,
  ipv4Address: string,
  ipv6Address: nullableString,
  publicKey: string,
  expiresAt: nullableString,
  createdAt: string,
  updatedAt: string,
  dns: strings,
  allowedIps: strings,
  mtu: integer,
  persistentKeepalive: { type: ['integer', 'string'] },
  latestHandshakeAt: nullableString,
  endpoint: nullableString,
  transferRx: nullableNumber,
  transferTx: nullableNumber,
  awg: ref('PublicAwg'),
});
const routing = object({
  revision: { ...string, pattern: '^[a-f0-9]{64}$' },
  enabled: boolean,
  rules: { type: 'array', items: ref('RoutingRule') },
  egresses: {
    type: 'array',
    items: object({ id: string, name: string }),
  },
  status: object({
    state: { type: 'string', enum: ['stopped', 'running', 'failed'] },
    enabled: boolean,
    pid: { type: ['integer', 'null'] },
    appliedAt: nullableString,
    error: nullableString,
  }),
});

const cacheHeader = {
  'Cache-Control': {
    description: 'Sensitive API responses must not be cached.',
    schema: { type: 'string', const: 'no-store' },
  },
};
const response = (schema: Schema, contentType = 'application/json') => ({
  description: 'Success',
  headers: cacheHeader,
  content: { [contentType]: { schema } },
});
const errors = {
  '400': { description: 'Invalid request or rejected routing update' },
  '401': { description: 'Authentication required or invalid credential' },
  '403': { description: 'Account, role, ownership or token operation denied' },
  '404': { description: 'Client not found' },
  '500': {
    description:
      'Operation failed. Read client state before retrying a mutation; runtime synchronization is not a database transaction.',
  },
};
const operation = (
  operationId: string,
  summary: string,
  schema: Schema,
  options: {
    body?: string;
    status?: string;
    contentType?: string;
    extraResponses?: Record<string, { description: string }>;
  } = {}
) => ({
  operationId,
  summary,
  ...(options.body
    ? {
        requestBody: {
          required: true,
          content: {
            'application/json': { schema: ref(options.body) },
          },
        },
      }
    : {}),
  responses: {
    [options.status ?? '200']: response(schema, options.contentType),
    ...errors,
    ...options.extraResponses,
  },
});

/** Schemas contain no live server data, profiles, account names or credentials. */
export function integrationOpenApi() {
  return {
    openapi: '3.1.0',
    info: {
      title: 'AmneziaWG Easy integration API',
      version: '1.0.0',
      description:
        'Versioned client and rule management using existing account permissions. Configuration and QR exports contain credentials; all other responses exclude them. Request refinements are also enforced by the server.',
    },
    servers: [{ url: '/api/v1' }],
    security: [{ BearerToken: [] }, { BasicAuth: [] }, { SessionCookie: [] }],
    components: {
      securitySchemes: {
        BearerToken: {
          type: 'http',
          scheme: 'bearer',
          description:
            'Opt-in awg_ service token configured by SHA-256 digest and existing account. Limited to the versioned operations; verified-TOTP accounts are rejected.',
        },
        BasicAuth: {
          type: 'http',
          scheme: 'basic',
          description: 'Existing account password authentication without 2FA.',
        },
        SessionCookie: {
          type: 'apiKey',
          in: 'cookie',
          name: 'wg-easy',
          description: 'Existing authenticated web session, including 2FA.',
        },
      },
      schemas: {
        ClientCreate: clientCreateInput(),
        ClientPatch: input(IntegrationClientPatchSchema),
        RoutingRulesUpdate: input(IntegrationRulesUpdateSchema),
        RoutingRule: input(RoutingRuleSchema),
        PublicAwgSettings: publicAwgSettings,
        PublicAwg: publicAwg,
        Client: client,
        ClientEnvelope: object({ client: ref('Client') }),
        ClientMutation: object({
          success: { const: true },
          client: ref('Client'),
        }),
        ClientList: object({
          clients: { type: 'array', items: ref('Client') },
        }),
        Success: object({ success: { const: true } }),
        Routing: routing,
        RoutingMutation: {
          ...routing,
          properties: {
            ...(routing.properties as Record<string, Schema>),
            success: { const: true },
          },
          required: [...(routing.required as string[]), 'success'],
        },
        Server: object({
          apiVersion: { const: 'v1' },
          applicationVersion: string,
          protocol: { type: 'string', enum: ['amneziawg', 'wireguard'] },
          protocolVersion: nullableString,
          endpoint: object({ host: string, port: integer }),
          interface: object({
            name: string,
            enabled: boolean,
            publicKey: string,
            mtu: integer,
            ipv4Cidr: string,
            ipv6Cidr: nullableString,
            awg: { anyOf: [ref('PublicAwg'), { type: 'null' }] },
          }),
          defaults: object({
            dns: strings,
            allowedIps: strings,
            mtu: integer,
            persistentKeepalive: integer,
          }),
        }),
      },
    },
    paths: {
      '/server': {
        get: operation(
          'getServer',
          'Get public server settings (administrator)',
          ref('Server')
        ),
      },
      '/clients': {
        get: {
          ...operation(
            'listClients',
            'List permitted clients and traffic status',
            ref('ClientList')
          ),
          parameters: [
            {
              name: 'filter',
              in: 'query',
              schema: { type: 'string', maxLength: 256 },
            },
            {
              name: 'sort',
              in: 'query',
              schema: { type: 'string', enum: ['asc', 'desc'] },
            },
          ],
        },
        post: operation(
          'createClient',
          'Create a client using server defaults',
          ref('ClientMutation'),
          {
            body: 'ClientCreate',
            status: '201',
          }
        ),
      },
      '/clients/{clientId}': {
        parameters: [
          {
            name: 'clientId',
            in: 'path',
            required: true,
            schema: { type: 'integer', minimum: 1 },
          },
        ],
        get: operation(
          'getClient',
          'Get a permitted client without credentials',
          ref('ClientEnvelope')
        ),
        patch: operation(
          'updateClient',
          'Update permitted fields without replacing keys or addresses',
          ref('ClientMutation'),
          {
            body: 'ClientPatch',
            extraResponses: {
              '422': {
                description:
                  'Client cannot be enabled while its expiry is in the past',
              },
            },
          }
        ),
        delete: operation(
          'deleteClient',
          'Delete one permitted client',
          ref('Success')
        ),
      },
      '/clients/{clientId}/configuration': {
        parameters: [
          {
            name: 'clientId',
            in: 'path',
            required: true,
            schema: { type: 'integer', minimum: 1 },
          },
        ],
        get: operation(
          'exportConfiguration',
          'Download the original .conf including every native parameter and client credentials',
          string,
          {
            contentType: 'text/plain',
          }
        ),
      },
      '/clients/{clientId}/qrcode.svg': {
        parameters: [
          {
            name: 'clientId',
            in: 'path',
            required: true,
            schema: { type: 'integer', minimum: 1 },
          },
        ],
        get: operation(
          'exportQrCode',
          'Export the original configuration as SVG QR (contains credentials)',
          string,
          {
            contentType: 'image/svg+xml',
          }
        ),
      },
      '/routing': {
        get: operation(
          'getRouting',
          'Get rules, status and revision without outbound profiles (administrator)',
          ref('Routing')
        ),
      },
      '/routing/rules': {
        put: operation(
          'updateRoutingRules',
          'Replace ordered rules, preserving profiles and checking revision (administrator)',
          ref('RoutingMutation'),
          {
            body: 'RoutingRulesUpdate',
            extraResponses: {
              '409': {
                description:
                  'Stale revision: read current routing before editing',
              },
            },
          }
        ),
      },
      '/openapi.json': {
        get: operation('getOpenApi', 'Get the integration contract', {
          type: 'object',
        }),
      },
    },
  };
}

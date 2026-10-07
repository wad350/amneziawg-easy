import { randomBytes, randomInt } from 'node:crypto';

import z from 'zod';

import type { AwgParameters, AwgSettings } from '../../shared/types/amneziawg';

const UINT16_MAX = 65535;
const UINT32_MAX = 4294967295;
const MAX_UDP_PAYLOAD = 65507;

export function parseAwgRange(value: string, maximum = UINT16_MAX) {
  if (!/^\d+(?:-\d+)?$/.test(value)) return null;
  const [low, high = low] = value.split('-').map(Number);
  if (
    low === undefined ||
    high === undefined ||
    !Number.isSafeInteger(low) ||
    !Number.isSafeInteger(high) ||
    low < 0 ||
    high < low ||
    high > maximum
  ) {
    return null;
  }
  return { low, high };
}

function rangeSchema(maximum: number) {
  return z
    .string()
    .max(21)
    .refine((value) => parseAwgRange(value, maximum) !== null, {
      message: `Expected an ordered integer range between 0 and ${maximum}`,
    })
    .transform((value) => {
      const range = parseAwgRange(value, maximum)!;
      return range.low === range.high
        ? String(range.low)
        : `${range.low}-${range.high}`;
    });
}

export const AwgRangeSchema = rangeSchema(UINT16_MAX);
export const AwgHeaderSchema = rangeSchema(UINT32_MAX).nullable();
export const AwgJcSchema = z.number().int().min(0).max(128).nullable();
export const AwgJunkSizeSchema = z
  .number()
  .int()
  .min(0)
  .max(MAX_UDP_PAYLOAD)
  .nullable();
export const AwgPaddingSchema = z
  .number()
  .int()
  .min(0)
  .max(UINT16_MAX)
  .nullable();

/** Portable CPS tags only; no shell/newline content or unparsed fragments. */
export function cpsPacketSize(value: string): number | null {
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(value)) return null;
  const spec = value.trim();
  if (!spec) return 0;
  const token = /<(?:b +((?:0x)?[0-9a-fA-F]+)|([t])|(?:r|rc|rd) +(\d+))>/y;
  let offset = 0;
  let size = 0;
  while (offset < spec.length) {
    token.lastIndex = offset;
    const match = token.exec(spec);
    if (!match) return null;
    if (match[1]) {
      const hex = match[1].replace(/^0x/, '');
      if (hex.length % 2 !== 0) return null;
      size += hex.length / 2;
    } else if (match[2]) {
      size += 4;
    } else {
      const length = Number(match[3]);
      if (
        !Number.isSafeInteger(length) ||
        length < 0 ||
        length > MAX_UDP_PAYLOAD
      ) {
        return null;
      }
      size += length;
    }
    if (size > MAX_UDP_PAYLOAD) return null;
    offset = token.lastIndex;
    while (spec[offset] === ' ') offset++;
  }
  return size;
}

export const AwgCpsSchema = z
  .string()
  .max(8192)
  .refine((value) => cpsPacketSize(value) !== null, {
    message:
      'Invalid CPS packet; use b, t, r, rc or rd tags without control characters',
  })
  .nullable();

const headerProtectionKey = z.string().refine(
  (value) => {
    if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) return false;
    const decoded = Buffer.from(value, 'base64');
    return (
      decoded.length === 32 &&
      decoded.toString('base64') === value &&
      decoded.some((byte) => byte !== 0)
    );
  },
  { message: 'HeaderProtectionKey must be a nonzero 32-byte base64 key' }
);

const timerRange = AwgRangeSchema.refine(
  (value) => {
    const range = parseAwgRange(value)!;
    return range.high === 0 || range.low > 0;
  },
  { message: 'Use 0 to disable an override, or a range starting above 0' }
);

export const AwgSettingsSchema = z
  .object({
    headerProtectionKey: headerProtectionKey.nullable().optional(),
    contentPaddingAddition: AwgRangeSchema.nullable().optional(),
    rekeyAfterTime: timerRange.nullable().optional(),
    rekeyTimeout: timerRange.nullable().optional(),
    rejectAfterTime: timerRange.nullable().optional(),
    keepaliveTimeout: timerRange.nullable().optional(),
    maxHandshakeAttempts: timerRange.nullable().optional(),
    randomTrailers: z.boolean().nullable().optional(),
    disableCookies: z.boolean().nullable().optional(),
    persistentKeepaliveRange: AwgRangeSchema.nullable().optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    const reject = value.rejectAfterTime
      ? parseAwgRange(value.rejectAfterTime)
      : null;
    if (!reject || reject.high === 0) return;
    for (const field of [
      'rekeyAfterTime',
      'rekeyTimeout',
      'keepaliveTimeout',
    ] as const) {
      const range = value[field] ? parseAwgRange(value[field]!) : null;
      if (range && range.high > 0 && range.high >= reject.low) {
        ctx.addIssue({
          code: 'custom',
          path: [field],
          message: `${field} must stay below RejectAfterTime`,
        });
      }
    }
  });

/** Shared handshake options belong to the interface, never a peer override. */
export const AwgClientSettingsSchema = AwgSettingsSchema.superRefine(
  (value, ctx) => {
    for (const field of ['headerProtectionKey', 'randomTrailers'] as const) {
      if (Object.hasOwn(value, field)) {
        ctx.addIssue({
          code: 'custom',
          path: [field],
          message: `${field} is inherited from the interface`,
        });
      }
    }
  }
);

/** Also remove stale shared values from rows written by an older UI. */
export function stripClientAwgSharedSettings(
  settings: AwgSettings | null
): AwgSettings | null {
  if (!settings) return null;
  const override = { ...settings };
  delete override.headerProtectionKey;
  delete override.randomTrailers;
  return Object.keys(override).length ? override : null;
}

type JunkFields = Pick<AwgParameters, 'jC' | 'jMin' | 'jMax'>;

export function refineAwgJunk(value: JunkFields, ctx: z.RefinementCtx) {
  if ((value.jC ?? 0) > 0 && (value.jMin ?? 0) > (value.jMax ?? 0)) {
    ctx.addIssue({
      code: 'custom',
      path: ['jMin'],
      message: 'Jmin must not exceed Jmax',
    });
  }
}

export function refineAwgParameters(
  value: AwgParameters & { mtu?: number },
  ctx: z.RefinementCtx
) {
  refineAwgJunk(value, ctx);
  const fields = ['h1', 'h2', 'h3', 'h4'] as const;
  const headers = fields.map((field, i) =>
    parseAwgRange(value[field] ?? String(i + 1), UINT32_MAX)
  );
  for (let i = 0; i < headers.length; i++) {
    for (let j = i + 1; j < headers.length; j++) {
      const left = headers[i];
      const right = headers[j];
      if (left && right && left.low <= right.high && right.low <= left.high) {
        ctx.addIssue({
          code: 'custom',
          path: [fields[j]!],
          message: 'H1–H4 ranges must not overlap',
        });
      }
    }
  }
  const paddingFields = ['s1', 's2', 's3', 's4'] as const;
  if (value.awgSettings?.headerProtectionKey) {
    for (const field of paddingFields) {
      if ((value[field] ?? 0) < 12) {
        ctx.addIssue({
          code: 'custom',
          path: [field],
          message: 'Header Protection requires S1–S4 to be at least 12',
        });
      }
    }
  }
  const baseSizes = [148, 92, 64, (value.mtu ?? 1340) + 32];
  for (let i = 0; i < paddingFields.length; i++) {
    if ((value[paddingFields[i]!] ?? 0) + baseSizes[i]! > MAX_UDP_PAYLOAD) {
      ctx.addIssue({
        code: 'custom',
        path: [paddingFields[i]!],
        message: 'Packet exceeds the maximum UDP payload',
      });
    }
  }
}

export const AwgParametersSchema = z
  .object({
    jC: AwgJcSchema,
    jMin: AwgJunkSizeSchema,
    jMax: AwgJunkSizeSchema,
    s1: AwgPaddingSchema,
    s2: AwgPaddingSchema,
    s3: AwgPaddingSchema,
    s4: AwgPaddingSchema,
    h1: AwgHeaderSchema,
    h2: AwgHeaderSchema,
    h3: AwgHeaderSchema,
    h4: AwgHeaderSchema,
    i1: AwgCpsSchema,
    i2: AwgCpsSchema,
    i3: AwgCpsSchema,
    i4: AwgCpsSchema,
    i5: AwgCpsSchema,
    awgSettings: AwgSettingsSchema.nullable().default(null),
    mtu: z.number().int().min(1024).max(9000).optional(),
  })
  .superRefine(refineAwgParameters);

/** Preview only: no database, interface, WireGuard keys or peers are touched. */
export function generateAwg31Parameters(): AwgParameters {
  const padding = randomInt(12, 33);
  return {
    jC: randomInt(4, 9),
    jMin: randomInt(64, 129),
    jMax: randomInt(256, 513),
    s1: padding,
    s2: padding,
    s3: padding,
    s4: padding,
    h1: '1',
    h2: '2',
    h3: '3',
    h4: '4',
    i1: null,
    i2: null,
    i3: null,
    i4: null,
    i5: null,
    awgSettings: {
      headerProtectionKey: randomBytes(32).toString('base64'),
      contentPaddingAddition: '0-31',
      rekeyAfterTime: '90-120',
      rekeyTimeout: '5-8',
      rejectAfterTime: '180-240',
      keepaliveTimeout: '15-25',
      maxHandshakeAttempts: '12-20',
      randomTrailers: true,
      disableCookies: false,
    },
  };
}

const legacyNames = {
  Jc: 'jC',
  Jmin: 'jMin',
  Jmax: 'jMax',
  S1: 's1',
  S2: 's2',
  S3: 's3',
  S4: 's4',
  H1: 'h1',
  H2: 'h2',
  H3: 'h3',
  H4: 'h4',
  I1: 'i1',
  I2: 'i2',
  I3: 'i3',
  I4: 'i4',
  I5: 'i5',
} as const;

const advancedNames = {
  HeaderProtectionKey: 'headerProtectionKey',
  ContentPaddingAddition: 'contentPaddingAddition',
  RekeyAfterTime: 'rekeyAfterTime',
  RekeyTimeout: 'rekeyTimeout',
  RejectAfterTime: 'rejectAfterTime',
  KeepaliveTimeout: 'keepaliveTimeout',
  MaxHandshakeAttempts: 'maxHandshakeAttempts',
  RandomTrailers: 'randomTrailers',
  DisableCookies: 'disableCookies',
} as const;

/** Explicit 0/false are meaningful. Never filter options by truthiness. */
export function serializeAwgParameters(value: AwgParameters): string[] {
  const lines: string[] = [];
  for (const [name, field] of Object.entries(legacyNames)) {
    const setting = value[field];
    if (setting !== null && setting !== undefined && setting !== '') {
      lines.push(`${name} = ${setting}`);
    }
  }
  for (const [name, field] of Object.entries(advancedNames)) {
    const setting = value.awgSettings?.[field];
    if (setting !== null && setting !== undefined && setting !== '') {
      lines.push(
        `${name} = ${typeof setting === 'boolean' ? Number(setting) : setting}`
      );
    }
  }
  return lines;
}

/** Header Protection and RandomTrailers must match both handshake endpoints. */
export function resolveClientAwgSettings(
  interfaceSettings: AwgSettings | null,
  clientSettings: AwgSettings | null
): AwgSettings | null {
  if (!interfaceSettings && !clientSettings) return null;
  return {
    ...interfaceSettings,
    ...stripClientAwgSharedSettings(clientSettings),
    headerProtectionKey: interfaceSettings?.headerProtectionKey ?? null,
    randomTrailers: interfaceSettings?.randomTrailers ?? null,
  };
}

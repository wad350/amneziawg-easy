import type { InferSelectModel } from 'drizzle-orm';
import z from 'zod';
import isCidr from 'is-cidr';

import type { AwgSettings } from '../../../../shared/types/amneziawg';

import type { wgInterface } from './schema';

import {
  AwgCpsSchema,
  AwgHeaderSchema,
  AwgJcSchema,
  AwgJunkSizeSchema,
  AwgPaddingSchema,
  AwgSettingsSchema,
  refineAwgParameters,
} from '#server/utils/amneziawg';
import {
  EnabledSchema,
  MtuSchema,
  PortSchema,
  RoutingTableSchema,
  safeStringRefine,
  schemaForType,
  t,
} from '#server/utils/types';

export type InterfaceType = InferSelectModel<typeof wgInterface>;

export type InterfaceCreateType = Omit<
  InterfaceType,
  'createdAt' | 'updatedAt'
>;

export type InterfaceUpdateType = Omit<
  InterfaceCreateType,
  | 'name'
  | 'createdAt'
  | 'updatedAt'
  | 'privateKey'
  | 'publicKey'
  | 'awgSettings'
> & { awgSettings?: AwgSettings | null };

const device = z
  .string({ message: t('zod.interface.device') })
  .min(1, t('zod.interface.device'))
  .pipe(safeStringRefine);

const cidr = z
  .string({ message: t('zod.interface.cidr') })
  .min(1, { message: t('zod.interface.cidr') })
  .refine((value) => isCidr(value), { message: t('zod.interface.cidrValid') })
  .pipe(safeStringRefine);

export const InterfaceUpdateSchema = schemaForType<InterfaceUpdateType>()(
  z
    .object({
      ipv4Cidr: cidr,
      ipv6Cidr: cidr,
      mtu: MtuSchema,
      routingTable: RoutingTableSchema,
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
      awgSettings: AwgSettingsSchema.nullable().optional(),
      port: PortSchema,
      device: device,
      enabled: EnabledSchema,
      firewallEnabled: EnabledSchema,
    })
    .superRefine((value, ctx) =>
      refineAwgParameters(
        { ...value, awgSettings: value.awgSettings ?? null },
        ctx
      )
    )
);

export type InterfaceCidrUpdateType = {
  ipv4Cidr: string;
  ipv6Cidr: string;
};

export const InterfaceCidrUpdateSchema =
  schemaForType<InterfaceCidrUpdateType>()(
    z.object({
      ipv4Cidr: cidr,
      ipv6Cidr: cidr,
    })
  );

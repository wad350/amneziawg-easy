/** Nullable fields omit an option; a null client object inherits the interface. */
export type AwgSettings = {
  headerProtectionKey?: string | null;
  contentPaddingAddition?: string | null;
  rekeyAfterTime?: string | null;
  rekeyTimeout?: string | null;
  rejectAfterTime?: string | null;
  keepaliveTimeout?: string | null;
  maxHandshakeAttempts?: string | null;
  randomTrailers?: boolean | null;
  disableCookies?: boolean | null;
  /** Client [Peer] setting, separate from the legacy scalar column. */
  persistentKeepaliveRange?: string | null;
};

export type AwgParameters = {
  jC: number | null;
  jMin: number | null;
  jMax: number | null;
  s1: number | null;
  s2: number | null;
  s3: number | null;
  s4: number | null;
  h1: string | null;
  h2: string | null;
  h3: string | null;
  h4: string | null;
  i1: string | null;
  i2: string | null;
  i3: string | null;
  i4: string | null;
  i5: string | null;
  awgSettings: AwgSettings | null;
};

import type { RoutingConfig } from '../../shared/types/routing';

import {
  egressInterface,
  parseAwgProfile,
  validateRoutingConfig,
  type RoutingContext,
} from './routingConfig';

export const ROUTING_TABLE = 'awg_easy_route';
export const ROUTING_GATE_TABLE = 'awg_easy_gate';
export const ROUTING_MARK = '0x574700';
export const ROUTING_POLICY_TABLE = 52000;
export const ROUTING_POLICY_PRIORITY = 18000;
export const ROUTING_TPROXY_PORT = 16080;

export function renderSingBox(
  config: RoutingConfig,
  options: { debug?: boolean } = {}
) {
  const enabled = config.rules.filter((rule) => rule.enabled);
  const ruleSets = new Map(
    enabled.flatMap((rule) =>
      rule.ruleSets.map((set) => [set.tag, set] as const)
    )
  );
  return {
    log: { level: options.debug ? 'debug' : 'warn', timestamp: true },
    // Used for public rule-set downloads; does not change the system resolver.
    dns: { servers: [{ type: 'local', tag: 'local-dns' }] },
    inbounds: [
      {
        type: 'tproxy',
        tag: 'awg-tproxy',
        listen: '0.0.0.0',
        listen_port: ROUTING_TPROXY_PORT,
      },
    ],
    outbounds: [
      { type: 'direct', tag: 'direct' },
      ...config.egresses.map((egress) => {
        const profile = parseAwgProfile(egress.profile);
        return {
          type: 'direct',
          tag: egress.id,
          bind_interface: egressInterface(egress.id),
          inet4_bind_address: profile.address.split('/')[0],
        };
      }),
    ],
    route: {
      default_domain_resolver: 'local-dns',
      rules: [
        {
          inbound: ['awg-tproxy'],
          action: 'sniff',
          sniffer: ['http', 'tls', 'quic'],
          timeout: '1s',
        },
        ...enabled.map((rule) => {
          const scalarPorts = rule.ports
            .filter((port) => !port.includes('-'))
            .map(Number);
          const rangePorts = rule.ports
            .filter((port) => port.includes('-'))
            .map((port) => port.replace('-', ':'));
          return {
            inbound: ['awg-tproxy'],
            network: rule.networks,
            ...(scalarPorts.length ? { port: scalarPorts } : {}),
            ...(rangePorts.length ? { port_range: rangePorts } : {}),
            ...(rule.domains.length ? { domain: rule.domains } : {}),
            ...(rule.suffixes.length ? { domain_suffix: rule.suffixes } : {}),
            ...(rule.cidrs.length ? { ip_cidr: rule.cidrs } : {}),
            ...(rule.ruleSets.length
              ? { rule_set: rule.ruleSets.map((set) => set.tag) }
              : {}),
            action: 'route',
            outbound: rule.outbound,
          };
        }),
      ],
      rule_set: [...ruleSets.values()].map((set) => ({
        type: 'remote',
        tag: set.tag,
        format: set.format,
        url: set.url,
        download_detour: 'direct',
      })),
      final: 'direct',
    },
  };
}

/** Only packets entering this project's AWG interface are intercepted. */
export function renderNftables(
  config: RoutingConfig,
  context: RoutingContext,
  replace = false
): string {
  validateRoutingConfig(config, context);
  const rules = config.rules.filter((rule) => rule.enabled);
  const lines = [
    ...(replace ? [`delete table ip ${ROUTING_TABLE}`] : []),
    `table ip ${ROUTING_TABLE} {`,
    '  chain prerouting {',
    '    type filter hook prerouting priority mangle; policy accept;',
    `    iifname != "${context.inboundInterface}" return`,
    `    ip saddr != ${context.sourceCidr} return`,
    '    fib daddr type local return',
    '    ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return',
    `    ip daddr ${context.sourceCidr} return`,
  ];
  const signatures = new Set<string>();
  for (const rule of rules)
    for (const network of rule.networks) {
      const ports = rule.ports.join(', ');
      const signature = `${network}:${ports}`;
      if (signatures.has(signature)) continue;
      signatures.add(signature);
      lines.push(
        `    ${network} dport { ${ports} } meta mark set ${ROUTING_MARK} tproxy to :${ROUTING_TPROXY_PORT} accept`
      );
    }
  lines.push('  }', '}', '');
  return lines.join('\n');
}

/** Temporary fail-closed gate covers only this project's selected traffic. */
export function renderRoutingGate(
  scopes: Array<{ config: RoutingConfig; context: RoutingContext }>,
  replace = false
): string {
  const lines = [
    ...(replace ? [`delete table ip ${ROUTING_GATE_TABLE}`] : []),
    `table ip ${ROUTING_GATE_TABLE} {`,
    '  chain prerouting {',
    '    type filter hook prerouting priority -151; policy accept;',
  ];
  const seen = new Set<string>();
  for (const { config, context } of scopes) {
    validateRoutingConfig(config, context);
    for (const rule of config.rules.filter((rule) => rule.enabled))
      for (const network of rule.networks) {
        const match = `iifname "${context.inboundInterface}" ip saddr ${context.sourceCidr} ${network} dport { ${rule.ports.join(', ')} }`;
        if (seen.has(match)) continue;
        seen.add(match);
        lines.push(`    ${match} counter drop`);
      }
  }
  lines.push('  }', '}', '');
  return lines.join('\n');
}

export function previewRouting(value: unknown, context: RoutingContext) {
  const config = validateRoutingConfig(value, context);
  return {
    valid: true as const,
    singBox: renderSingBox(config),
    nftables: renderNftables(config, context),
    egresses: config.egresses.map((egress) => {
      const p = parseAwgProfile(egress.profile);
      return {
        id: egress.id,
        interfaceName: egressInterface(egress.id),
        address: p.address,
        endpoint: p.peer.Endpoint,
        mtu: p.mtu,
      };
    }),
    warnings: [
      'Use a separately allocated remote peer. Importing another running peer causes endpoint roaming.',
      'Domain sniffing cannot recover hidden ECH names or arbitrary UDP domains; unmatched traffic uses direct.',
      'Preview does not start processes, change routes or modify existing clients.',
    ],
  };
}

export function youtubeRuPreset(
  outboundId: string,
  openvpn?: { domains: string[]; cidrs: string[] }
) {
  const youtube = [
    'ggpht.com',
    'googlevideo.com',
    'jnn-pa.googleapis.com',
    'returnyoutubedislikeapi.com',
    'wide-youtube.l.google.com',
    'youtu.be',
    'youtube-nocookie.com',
    'youtube-ui.l.google.com',
    'youtube.com',
    'youtubeembeddedplayer.googleapis.com',
    'youtubei.googleapis.com',
    'youtubekids.com',
    'yt-video-upload.l.google.com',
    'yt.be',
    'yt3.googleusercontent.com',
    'ytimg.com',
    'ytimg.l.google.com',
    'yting.com',
  ];
  const rule = (id: string, name: string, target: string) => ({
    id,
    name,
    enabled: true,
    networks: ['tcp'] as Array<'tcp' | 'udp'>,
    ports: ['443'],
    domains: [] as string[],
    suffixes: [] as string[],
    cidrs: [] as string[],
    ruleSets: [] as RoutingConfig['rules'][number]['ruleSets'],
    outbound: target,
  });
  return [
    {
      ...rule('youtube', 'YouTube', outboundId),
      networks: ['tcp', 'udp'] as Array<'tcp' | 'udp'>,
      suffixes: youtube,
    },
    ...(openvpn?.domains.length
      ? [
          {
            ...rule('openvpn-name', 'OpenVPN domain direct', 'direct'),
            domains: openvpn.domains,
          },
        ]
      : []),
    ...(openvpn?.cidrs.length
      ? [
          {
            ...rule('openvpn-address', 'OpenVPN address direct', 'direct'),
            cidrs: openvpn.cidrs,
          },
        ]
      : []),
    {
      ...rule('ru-rf', 'RU and RF domains', outboundId),
      suffixes: ['ru', 'xn--p1ai'],
    },
  ];
}

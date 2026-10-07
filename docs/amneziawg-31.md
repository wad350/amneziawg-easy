# AmneziaWG 3.1 fork

This fork adds AWG 3.1 configuration generation and scoped outbound routing to the wg-easy v15.4 interface. The client list, authentication, charts, `.conf` downloads and QR actions retain the upstream layout.

Use the fork as a separate instance with a new volume, an unused UDP port and its own subnet. Do not mount an existing VPN installation's configuration directory or import its live client database. The supplied [Docker Compose configuration](../docker-compose.yml) uses a separate bridge network and userspace AWG, and publishes the administration port on loopback. It does not attach to existing AWG interfaces or manage a second server.

Existing clients are never automatically migrated. Starting the fork or opening its generator does not change their keys, routes or profiles. Changes made in the fork affect only its own instance and clients.

## Build and initial setup

Create a private `.env` in the project directory with `AWG_ADMIN_USERNAME`, a unique `AWG_ADMIN_PASSWORD`, and `AWG_PUBLIC_IP` set to the server's numeric IPv4 address. Optional `AWG_UDP_PORT` and `AWG_UI_PORT` default to 38472 and 28554. Restrict this file to its owner (`chmod 600 .env`); it must never be committed.

Run `docker compose up -d --build`. The web interface listens at `127.0.0.1:28554` on the host. Publish it through your existing HTTPS reverse proxy, or access it through a protected tunnel. Keep public HTTP access disabled. The initial IPv4 network is `172.31.63.0/24`; the Docker bridge uses `172.30.63.0/24`. Check that neither overlaps your other networks. IPv6 is disabled in the supplied Compose file.

The UDP mapping and initialized interface port use the same `AWG_UDP_PORT`. To change this port later, update the instance's interface/client endpoint settings and Compose mapping together. Existing imported profiles on devices need a corresponding update.

The image pins matching official AWG 3.1 Go/tools commits and sing-box 1.14.2 with download checksums. It requires `/dev/net/tun` and `NET_ADMIN` in its private network namespace, without `SYS_MODULE`, host networking or a kernel-module directory mount.

## Generate and export AWG 3.1 profiles

Open **Admin → Interface → Generate AWG 3.1 parameters**. The generator fills the interface form with a new parameter set and header protection key. It does not save the database, apply interface changes, create peers or alter existing profiles.

Review the generated values, then use **Save** when ready to apply them to this instance. The normal client configuration and QR actions export the current saved values. Use a client implementation that supports the configured AWG 3.1 directives; ordinary WireGuard and older AWG clients cannot interpret every extension.

Shared `S1–S4`, `H1–H4`, `HeaderProtectionKey` and `RandomTrailers` must match between this server and its clients. `HeaderProtectionKey` and `RandomTrailers` are configured only on the interface and inherited automatically. Changing shared parameters requires downloading or importing updated client profiles; it does not silently update already installed profiles on devices.

Other AWG 3.1 fields can be overridden in a client's edit page. Empty client fields inherit the interface settings. The `PersistentKeepalive` range is a client `[Peer]` option, separate from the ordinary scalar keepalive field.

`H1–H4` accept non-overlapping uint32 values or ranges, up to `4294967295`. Header protection requires at least 12 bytes of padding in every `S1–S4`. The generator validates these constraints. Its generated padding and timers are an initial configuration, not a guarantee that a provider's DPI cannot recognize the traffic.

## Import an independent AWG outbound

In **Admin → Domain routing**, add a named AWG outbound. Create a **new, dedicated peer** on the destination server and import its `.conf` file, or show the profile editor and paste it. Confirm that no other device or tunnel uses this peer.

Reusing a currently connected peer makes the destination server learn competing endpoints for the same key. This endpoint roaming can break the existing connection. An imported outbound must therefore use independently allocated keys and an address that does not overlap this instance or another outbound.

The import checker accepts one `[Interface]` and one `[Peer]`, a numeric IPv4 endpoint, a single IPv4 address with its prefix, and `AllowedIPs = 0.0.0.0/0`. It rejects shell hooks, unsupported directives, conflicting local listen ports and `10.0.0.0/8` overlap. MTU must be between 1280 and 1500. `Table=off` is enforced so the imported peer does not install a system default route. Imported client DNS metadata is retained in storage but is not applied as the server's DNS configuration.

The panel hides stored profile text until it is explicitly revealed. **Check profile** shows a summary of the address, endpoint, MTU and parameter names without displaying private or preshared keys. Importing and checking a profile does not modify the remote server or activate the outbound.

## Add routing rules

Rules are evaluated in their displayed order; the first matching rule wins. Move rules up or down to change precedence. Each rule has:

- A name, enabled state and chosen outbound: **Direct** or one imported AWG peer.
- TCP and/or UDP transports and destination ports or ranges.
- Exact domains, domain suffixes, IPv4 destination CIDRs, or public HTTPS rule sets in SRS/JSON format.

Networks and ports constrain a rule; its domain, suffix, CIDR and rule-set selectors provide alternative matches. Unmatched traffic exits directly from this server.

The **YouTube** preset adds its 18 public domain suffixes for TCP and UDP port 443. The **Russian zones** preset adds `.ru` and `.рф` suffixes for TCP port 443. These are explicit templates, not a complete classification of every service or Russian IP network. Use a rule set or CIDRs when the desired policy requires an IP list.

The **OpenVPN → Direct** preset uses the VPN domains and public IPv4/CIDRs entered by the administrator. The inputs are empty by default. This exception is inserted before other rules; it affects only the specified traffic that passes through this AWG instance. It does not modify an OpenVPN profile, install routes on a Mac or router, discover corporate networks, or combine two client VPNs automatically.

For a new client that must also run a corporate OpenVPN connection, exclude the OpenVPN server's public IPv4 `/32` and the required work IPv4 CIDRs from that **new client's Allowed IPs** in the normal client editor. A server-side Direct rule still sends the packet through the AWG tunnel before it exits, so it is not a replacement for client route exclusions. A hostname alone cannot express an AllowedIPs exception. Re-export the new profile after editing; existing clients are not changed. Correct route exclusions may be necessary for coexistence, but do not by themselves resolve macOS VPN-extension or corporate DNS conflicts.

## Preview, save and apply

**Validate and preview** checks the configuration and displays generated sing-box and nftables settings without starting processes or changing routes. Private keys and full outbound profiles are excluded from the preview.

**Save draft** stores the configuration without changing the active routing engine. **Save and apply** activates the saved configuration, or stops it when domain routing is disabled. Routing starts disabled in a new instance.

Applied interception is limited to packets entering this instance's AWG interface from its configured client subnet and using selected transports and ports. Outbound interfaces, nftables tables and policy routing belong to the isolated container namespace. Existing host VPN interfaces, other containers, VLESS, Hysteria2 and remote server configurations are outside this scope.

Apply can briefly interrupt this instance's selected traffic while its routing engine is replaced. If the routing process stops unexpectedly, interception remains in place to prevent selected traffic from silently switching to a direct connection. Check the displayed status; repair and apply the configuration, or disable routing and apply that change to remove this instance's interception.

## Domain matching and OpenVPN limits

The routing engine sniffs visible names in HTTP, TLS and supported QUIC handshakes. It cannot recover arbitrary domain names from every connection. ECH can conceal the useful TLS name, traffic addressed only by IP has no domain to inspect, and many UDP protocols expose no usable hostname. Such traffic needs suitable CIDR rules or rule sets; a domain-only rule may remain unmatched and use the direct default.

This feature does not implement a DNS gateway, Fake-IP service or per-client split DNS. A Mac's corporate OpenVPN DNS policy can still conflict with a router's domain-based proxy service. An unknown set of work domain zones cannot be inferred reliably from an AWG outbound configuration. Correct OpenVPN coexistence requires an appropriate corporate routing/DNS policy, known exceptions, or a separately chosen client/router architecture.

The fork does not inspect, restart or change a remote VPN server. Allocate its dedicated outbound peer using that server's own management tools. Keep client and outbound profiles private; backups of this instance may contain their keys.

## Upstream references

- [wg-easy AmneziaWG integration](./content/advanced/config/amnezia.md)
- [Official AmneziaWG Go implementation](https://github.com/amnezia-vpn/amneziawg-go)
- [Official AmneziaWG tools](https://github.com/amnezia-vpn/amneziawg-tools)
- [sing-box route configuration](https://sing-box.sagernet.org/configuration/route/)
- [sing-box sniffing action](https://sing-box.sagernet.org/configuration/route/rule_action/#sniff)

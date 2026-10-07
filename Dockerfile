FROM docker.io/library/node:krypton-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS build
WORKDIR /app

# update corepack
RUN npm install --global corepack@latest
# Install pnpm
RUN corepack enable pnpm

# Copy Web UI
COPY src/package.json src/pnpm-lock.yaml src/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

# Build UI
COPY src ./
RUN NODE_OPTIONS=--max-old-space-size=1024 pnpm build

FROM docker.io/library/node:krypton-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS build-awg
WORKDIR /app

# renovate: datasource=github-releases depName=amnezia-vpn/amneziawg-tools
ARG AWGTOOLS_BRANCH=v3.1.20260812
# renovate: datasource=github-tags depName=amnezia-vpn/amneziawg-go
ARG AWGGO_BRANCH=v3.1.20260828

COPY scripts/force-userspace.mjs /tmp/force-userspace.mjs

# Build amneziawg-tools
RUN apk add linux-headers build-base go git && \
    git clone --depth 1 --branch ${AWGTOOLS_BRANCH} https://github.com/amnezia-vpn/amneziawg-tools.git && \
    git clone --depth 1 --branch ${AWGGO_BRANCH} https://github.com/amnezia-vpn/amneziawg-go && \
    test "$(git -C amneziawg-tools rev-parse HEAD)" = ee0f0a9aa34ff0a0da4b3433b9512781cfe02843 && \
    test "$(git -C amneziawg-go rev-parse HEAD)" = b5928efb6ca19f0153958460c3d141f04abc5c2e && \
    cd amneziawg-go && \
    make && \
    cd ../amneziawg-tools/src && \
    make && \
    node /tmp/force-userspace.mjs ./wg-quick/linux.bash && \
    sed -i 's|\[\[ $proto == -4 \]\] && cmd sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1|[[ $proto == -4 ]] \&\& [[ $(sysctl -n net.ipv4.conf.all.src_valid_mark) != 1 ]] \&\& cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1|' ./wg-quick/linux.bash

FROM docker.io/library/node:krypton-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS build-libsql
WORKDIR /app
RUN npm install --no-save --omit=dev libsql

FROM docker.io/library/alpine:3.24 AS routing-binary
ARG TARGETARCH
RUN apk add --no-cache ca-certificates wget && \
    case "$TARGETARCH" in \
      amd64) task_checksum=a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6 ;; \
      arm64) task_checksum=b43a1fb1bda131c6653576741ce527eb2bdeab7c9308ca90ee8b972abb7e4a7f ;; \
      *) exit 1 ;; \
    esac && \
    wget -q -O /tmp/sing-box.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-$TARGETARCH.tar.gz" && \
    echo "$task_checksum  /tmp/sing-box.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/sing-box.tar.gz -C /tmp && \
    cp "/tmp/sing-box-1.14.2-linux-$TARGETARCH/sing-box" /sing-box

# Copy build result to a new image.
# This saves a lot of disk space.
FROM docker.io/library/node:krypton-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43
WORKDIR /app

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD /usr/bin/timeout 5s /bin/sh -c "/usr/bin/awg show interfaces | /bin/grep -qw wg0"

# Copy build
COPY --from=build /app/.output /app
# Copy migrations
COPY --from=build /app/server/database/migrations /app/server/database/migrations
# libsql (https://github.com/nitrojs/nitro/issues/3328)
COPY --from=build-libsql /app/node_modules /app/server/node_modules

# cli
COPY --from=build /app/cli/cli.sh /usr/local/bin/cli
RUN chmod +x /usr/local/bin/cli
# Copy amneziawg-go
COPY --from=build-awg /app/amneziawg-go/amneziawg-go /usr/bin/amneziawg-go
RUN chmod +x /usr/bin/amneziawg-go
# Copy amneziawg-tools
COPY --from=build-awg /app/amneziawg-tools/src/wg /usr/bin/awg
COPY --from=build-awg /app/amneziawg-tools/src/wg-quick/linux.bash /usr/bin/awg-quick
COPY --from=routing-binary /sing-box /usr/bin/sing-box
RUN chmod +x /usr/bin/awg /usr/bin/awg-quick

# Install Linux packages
RUN apk add --no-cache \
    dpkg \
    dumb-init \
    bash \
    iproute2 \
    ca-certificates \
    gcompat \
    tzdata \
    iptables \
    ip6tables \
    nftables \
    iptables-legacy \
    wireguard-go \
    wireguard-tools

# Official sing-box release archives use the glibc loader on Linux.
RUN /usr/bin/sing-box version

RUN mkdir -p /etc/amnezia /etc/wireguard && chmod 700 /etc/wireguard
RUN ln -s /etc/wireguard /etc/amnezia/amneziawg

# Use iptables-legacy
RUN update-alternatives --install /usr/sbin/iptables iptables /usr/sbin/iptables-legacy 10 --slave /usr/sbin/iptables-restore iptables-restore /usr/sbin/iptables-legacy-restore --slave /usr/sbin/iptables-save iptables-save /usr/sbin/iptables-legacy-save
RUN update-alternatives --install /usr/sbin/ip6tables ip6tables /usr/sbin/ip6tables-legacy 10 --slave /usr/sbin/ip6tables-restore ip6tables-restore /usr/sbin/ip6tables-legacy-restore --slave /usr/sbin/ip6tables-save ip6tables-save /usr/sbin/ip6tables-legacy-save

# Set Environment
ENV DEBUG=Server,WireGuard,Database,CMD,Firewall
ENV PORT=51821
ENV HOST=0.0.0.0
ENV INSECURE=false
ENV INIT_ENABLED=true
ENV DISABLE_IPV6=false
ENV VPN_PROTOCOL=amneziawg
ENV AWG_FORCE_USERSPACE=true
ENV WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
ENV AWG_ISOLATED=true
ENV INIT_IPV4_CIDR=172.31.63.0/24
ENV INIT_IPV6_CIDR=fd31:63::/64

LABEL org.opencontainers.image.source=https://github.com/wad350/amneziawg-easy

# Run Web UI
CMD ["/usr/bin/dumb-init", "node", "server/index.mjs"]

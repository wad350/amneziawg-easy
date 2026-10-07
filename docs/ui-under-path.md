# Native application under a URL path

The native application can run under a configured base path. Set
`NUXT_APP_BASE_URL` to a path ending in `/` when starting the application:

```sh
NUXT_APP_BASE_URL=/private-panel/ node .output/server/index.mjs
```

Forward `/private-panel/*` to the backend without removing the prefix. The
application serves its pages, assets, login, API and one-time links under that
base. For example, the integration endpoint becomes
`http://127.0.0.1:51821/private-panel/api/v1`; update integration clients to use
that URL. Service tokens, VPN endpoints and client configurations stay the same.

Nuxt navigation and its auto-imported `$fetch`/`useFetch` already use
`app.baseURL`, including server-rendered session requests. Raw browser links,
downloaded configurations, QR images and public assets use `useAppPath`. Do not
prefix fetch arguments a second time. Manifest icons resolve relative to the
manifest URL. With the default base `/`, the original URLs remain unchanged.

The base path does not replace password or two-factor authentication. The reverse
proxy should explicitly reject public paths outside the configured prefix,
including requests carrying an old cookie, if the application should only be
accessible below that prefix. Redirects use the configured base path; session
cookie security settings stay unchanged. If using OAuth, register the prefixed
callback and account link URLs with the provider.

Validate deployment with a disposable instance before changing a running VPN
daemon. Compare client export hashes, saved routing rules and interface settings
before and after a deployment. Keep the previous image and configuration for
rollback. Do not use a live client configuration as a test peer, and do not read
an existing one-time link: that consumes its token.

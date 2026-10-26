# Development loop

The Federation server is one C++17 source tree (`server/`) built two ways: a desktop
binary now (watch and work out the protocol with no device), and the embedded
`libmc5offline.so` later (M0.2+). This is the MCVS approach: get the server right on
the desktop first, then put it in the game.

## Build and test (desktop)

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Needs only a C++17 compiler, CMake and pthreads — no third-party libraries (the core
carries its own JSON, SHA-1 and HTTP/1.1 server so the embedded `.so` stays small and
dependency-free).

## Run the standalone server

```sh
build/mc5-offline-standalone --port 51780 --log-level debug
```

Options: `--bind ADDR`, `--public-host H`, `--scheme http|https`, `--data-center DC`,
`--client-id ID`, `--log-level debug|info|warn|error`.

It logs every request to stderr (and to logcat in the embedded build). Diagnostic
routes: `GET /_mc5/status`, `GET /_mc5/routes`, `GET /_mc5/log?n=500`.

## What answers today (M0.1)

The discovery + auth chain the client runs at boot:

| Step | Request | Response |
|---|---|---|
| eve datacenters | `GET /config/{clientId}/datacenters` | `[{"name":"mc5","status":"active","preferred":true}]` |
| eve urls | `GET /config/{clientId}/datacenters/{dc}/urls` | `{"pandora":"<base>","federation":"<base>"}` |
| pandora locate | `GET /locate/{service}` or `/locate?service=` | `<base><service>/` (text) |
| auth authorize | `POST /auth/authorize` | `{"access_token":"<account>.<n>","scope":"<echoed>"}` |
| auth users/me | `GET /auth/users/me?access_token=` | `{"account":"<id>","credentials":[...]}` |
| auth verify | `POST /auth/verify` | `{"account","credential","client_id"}` |
| auth encrypt_token | `GET/POST /auth/encrypt_token` | the token, as text |

Requests that pandora prefixes with a service name (`/auth/authorize`) and the same
route unprefixed (`/authorize`) both resolve. Account ids are `sha1(credential)[:24]`
(stable across devices, for later P2P); tokens are self-describing (`<account>.<n>`).
Anything not yet implemented is logged in full by the catch-all and answered `200 {}`,
so the first device boot shows exactly what to build next.

## Device dev loop (later)

MC5 has no `args.txt`-style redirect (that was MCVS's Xamarin launcher). To point the
stock client at a desktop server for live protocol work, the redirect is the native
GOT hook (M0.3) in a minimal patched build, or a DNS/hosts redirect of
`*.gameloft.com` to the host. Until M0.3 lands, the server is exercised with the
conformance harness and curl.

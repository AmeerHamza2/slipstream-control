# Slipstream Control

[![ci](https://github.com/ameerhamza2/slipstream-control/actions/workflows/ci.yml/badge.svg)](https://github.com/ameerhamza2/slipstream-control/actions/workflows/ci.yml)

The backend control plane of **Slipstream VPN**. It handles accounts,
subscriptions, WireGuard peer provisioning, fleet health and server selection,
and it issues the exact config the on-device
[TunnelCore](https://github.com/ameerhamza2/tunnelcore) engine connects with.

## Architecture

```
          Slipstream VPN app (TunnelCore engine)
           │ EdDSA JWT                     │ receipts
           ▼                               ▼
┌──────────────────────────┐   ┌───────────────────────────┐
│ api (Go)                 │◄──│ billing-webhooks (Node/TS) │  Stripe · App Store · Google Play
│ auth · devices · IPAM ·  │   └───────────────────────────┘
│ selection · config ·     │◄── HMAC-signed heartbeats ──┐
│ entitlements · OpenAPI   │                             │
└───┬──────────────▲───────┘                  ┌──────────┴──────────┐ probe ┌──────────────────┐
    ▼              │ node-scoped peer sync    │ fleet-prober (Python)│──────►│ VPN node         │
Postgres · Redis   └──────────────────────────┼──────────────────────┼───────│ node-agent (Go): │
                                              └─────────────────────┘       │ wg peers · echo ·│
                                                                            │ /load            │
                                                                            └──────────────────┘
```

| Service | Stack | Responsibility |
|---|---|---|
| [api](cmd/api) | Go, Postgres, Redis | Signup/login (argon2id, EdDSA JWT, rotating refresh tokens), devices and WireGuard IPAM, server ranking, config issuance, entitlements, rate limiting, [OpenAPI 3.1](api/openapi.yaml) |
| [billing-webhooks](services/billing-webhooks) | Node.js, TypeScript, Fastify | Verifies Stripe, App Store and Google Play events, then forwards signed, idempotent entitlement events to the api |
| [fleet-prober](services/fleet-prober) | Python, asyncio | Measures every node's RTT, loss and load, and reports signed heartbeats; can be sharded |
| [node-agent](cmd/node-agent) | Go | Runs on each VPN node: keeps WireGuard's peers equal to who is entitled (incremental sync, drift repair, fails static), serves the UDP echo and `/load` the prober measures |

## Highlights

- **Security:**
  - The device's WireGuard private key never reaches the server.
  - Secrets are stored AES-256-GCM encrypted.
  - Service-to-service calls are HMAC-signed.
  - Reuse of a rotated refresh token revokes the whole token family.
  - Stores' signatures are checked manually: Stripe HMAC, and the Apple x5c chain up to Apple Root CA G3.
  - Each node agent holds a token scoped to its own server, so a compromised node can't read other nodes' peers.
- **Correctness:**
  - Entitlement events are idempotent and order-safe, since stores deliver out of order.
  - Fleet health uses hysteresis.
  - IPAM is race-safe.
- **Scale:** every service is stateless and scales horizontally. On a 2-vCPU box the api handles about 600 req/s on a realistic mix and 1,200+ req/s for logged-in users. Every query is index-backed on a dataset of 1M users and 1.5M devices.
- **Resilience:**
  - When the database or Redis is down, the api returns 503 with `Retry-After`.
  - Login has load shedding.
  - The billing service has a circuit breaker and bulkhead.
  - Node agents fail static: if the api is down, they leave WireGuard as it is.
  - All services shut down gracefully.

## Quick start

```bash
make demo                   # end-to-end: all services, a node agent and simulated VPN nodes
make test                   # Go (unit + Postgres/Redis integration), Node, Python
make up                     # docker compose: full stack
go run ./cmd/loadtest -h    # load generator
```

`make demo` takes you through the whole flow:
1. A node agent starts on the Frankfurt node with a node-scoped token.
2. The prober marks the nodes healthy.
3. A user signs up; a Stripe webhook makes them premium.
4. The phone registers its public key and gets its config.
5. TunnelCore validates the config and measures latency to each server from "the phone".
6. The node agent adds the device's peer.
7. The subscription is cancelled: the node agent removes the peer within seconds, and the config request returns 402.

The demo and tests need Go 1.26, Node 22, Python 3.12+, Postgres 16 and Redis 7
locally (`brew install go node python postgresql@16 redis`).

## Docs

- [docs/CONTRACT.md](docs/CONTRACT.md): every endpoint, payload and auth scheme between the services
- [docs/DESIGN.md](docs/DESIGN.md): security and reliability design
- [docs/SCALABILITY.md](docs/SCALABILITY.md): capacity math for 10M installs, load-test results, query plans
- Per-service READMEs: [billing-webhooks](services/billing-webhooks/README.md), [fleet-prober](services/fleet-prober/README.md)

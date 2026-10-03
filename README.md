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
└────────┬─────────────────┘                  ┌──────────┴──────────┐      ┌───────────┐
         ▼                                    │ fleet-prober (Python)│─────►│ VPN nodes │
   Postgres · Redis                           └─────────────────────┘ probe └───────────┘
```

| Service | Stack | Responsibility |
|---|---|---|
| [api](cmd/api) | Go, Postgres, Redis | Signup/login (argon2id, EdDSA JWT, rotating refresh tokens), devices and WireGuard IPAM, server ranking, config issuance, entitlements, rate limiting, [OpenAPI 3.1](api/openapi.yaml) |
| [billing-webhooks](services/billing-webhooks) | Node.js, TypeScript, Fastify | Verifies Stripe, App Store and Google Play events, then forwards signed, idempotent entitlement events to the api |
| [fleet-prober](services/fleet-prober) | Python, asyncio | Measures every node's RTT, loss and load, and reports signed heartbeats; can be sharded |

## Highlights

- **Security:**
  - The device's WireGuard private key never reaches the server.
  - Secrets are stored AES-256-GCM encrypted.
  - Service-to-service calls are HMAC-signed.
  - Reuse of a rotated refresh token revokes the whole token family.
  - Stores' signatures are checked manually: Stripe HMAC, and the Apple x5c chain up to Apple Root CA G3.
- **Correctness:**
  - Entitlement events are idempotent and order-safe, since stores deliver out of order.
  - Fleet health uses hysteresis.
  - IPAM is race-safe.
- **Scale:** every service is stateless and scales horizontally. On a 2-vCPU box the api handles about 600 req/s on a realistic mix and 1,200+ req/s for logged-in users. Every query is index-backed on a dataset of 1M users and 1.5M devices.
- **Resilience:**
  - When the database or Redis is down, the api returns 503 with `Retry-After`.
  - Login has load shedding.
  - The billing service has a circuit breaker and bulkhead.
  - All services shut down gracefully.

## Quick start

```bash
make demo                   # end-to-end: all 3 services plus simulated VPN nodes
make test                   # Go (unit + Postgres/Redis integration), Node, Python
make up                     # docker compose: full stack
go run ./cmd/loadtest -h    # load generator
```

`make demo` takes you through the whole flow:
1. The prober marks the nodes healthy.
2. A user signs up.
3. A Stripe webhook makes the user premium.
4. The phone registers its public key.
5. The api issues the config.
6. TunnelCore validates that config with its own parser.

The demo and tests need Go 1.26, Node 22, Python 3.12+, Postgres 16 and Redis 7
locally (`brew install go node python postgresql@16 redis`).

## Docs

- [docs/CONTRACT.md](docs/CONTRACT.md): every endpoint, payload and auth scheme between the services
- [docs/DESIGN.md](docs/DESIGN.md): security and reliability design
- [docs/SCALABILITY.md](docs/SCALABILITY.md): capacity math for 10M installs, load-test results, query plans
- Per-service READMEs: [billing-webhooks](services/billing-webhooks/README.md), [fleet-prober](services/fleet-prober/README.md)

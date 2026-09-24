# SurfaceWatch

Attack surface management for security teams. Point it at a domain, and it
enumerates what you have exposed, fingerprints the services, correlates known
CVEs against them, and tells you what changed since last time.

Built for people doing authorised security work — internal security engineers
and pentesters with a scope agreement. See [Authorised use](#authorised-use).

---

## What it does

A scan runs as a pipeline of Celery tasks, each streaming progress to the
browser over a WebSocket:

| Stage | Module | What it does |
|---|---|---|
| Subdomain enumeration | `subdomain_enum.py` | Certificate transparency, DNS bruteforce, zone-transfer attempts |
| Port scanning | `port_scanner.py` | Open ports and service banners |
| Fingerprinting | `fingerprinter.py` | Technology stack, versions, HTTP headers |
| CVE correlation | `cve_correlator.py` | Matches detected versions against known vulnerabilities |
| Change detection | `change_detector.py` | Diffs against the previous scan of the same target |
| AI remediation | `ai_remediation.py` | Drafts remediation guidance for findings |
| Reporting | `report_builder.py` | PDF/CSV/JSON export |
| Notification | `notifier.py` | Slack webhook on completion |

Findings carry a stable fingerprint, so a nightly scan updates one row per
issue rather than creating a duplicate every night.

## Stack

- **Backend** — FastAPI, SQLAlchemy 2 (async), Celery, PostgreSQL, Redis
- **Frontend** — Next.js 14 (App Router), React 18, TypeScript
- **Auth** — JWT access/refresh tokens, bcrypt hashing, organisation isolation
  enforced on every query

---

## Running it

You need Docker and Docker Compose. Everything else is in the images.

```bash
git clone git@github.com:wahab09033/surfacewatch.git
cd surfacewatch

cp .env.example .env
cp backend/.env.example backend/.env
```

**Now edit both files.** They ship with `change-me` placeholders. The API
refuses to start in production while `JWT_SECRET` still contains `change-me`,
and you should replace it in development too:

```bash
# A long random string. Anyone who has it can mint valid tokens for any account.
JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')

# Any strong value; it only has to match between the two files.
POSTGRES_PASSWORD=...
```

Then:

```bash
docker compose up --build
```

- Frontend — http://localhost:3000
- API docs — http://localhost:8000/docs *(development only)*
- Health — http://localhost:8000/health

Register the first account through the UI. That bootstraps an organisation and
makes you its owner.

### Running the backend directly

```bash
cd backend
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn main:app --reload
```

Postgres and Redis still need to be running — `docker compose up postgres redis`
is enough.

---

## Configuration

Everything is environment variables; `.env.example` documents all of them. The
ones worth knowing about:

| Variable | Default | Why you'd change it |
|---|---|---|
| `JWT_SECRET` | insecure dev placeholder | The app refuses to start in production while this still contains `change-me`. Set it anyway in development. |
| `ALLOW_ARBITRARY_TARGETS` | `false` | When false, you can only scan domains verified against your org. Leave it false. |
| `TRUSTED_PROXY_COUNT` | `0` | Number of reverse proxies in front of the app. See below. |
| `RATE_LIMIT_*` | varies | Per-IP and per-account throttles on auth endpoints. |
| `PASSWORD_HIBP_CHECK_ENABLED` | `false` | Check new passwords against Have I Been Pwned. Opt-in — it makes registration depend on a third party. |
| `POSTGRES_BIND` / `REDIS_BIND` | `127.0.0.1` | Interface the datastores publish on. |

## Deploying for free

SurfaceWatch splits into two halves that deploy very differently:

- The **frontend** is nine static pages. Every one is a Client Component, so
  there is no server-side rendering, no dynamic route, and no API route. A CDN
  serves it.
- The **backend** needs processes that stay resident — Celery workers, a port
  scanner holding hundreds of sockets, WebSockets streaming for minutes. No
  serverless platform runs those.

Scanning is the product, so the backend is not optional. A frontend-only deploy
gives you a dashboard that loads and then fails every request.

**Frontend — Netlify.** `netlify.toml` at the repository root configures the
whole build, including pointing at the `frontend/` subdirectory. Connect the
repo and set one environment variable:

```
NEXT_PUBLIC_API_URL = https://<api-host>
```

It is compiled into the browser bundle at build time, so changing it requires a
redeploy. Leave it unset and every request falls back to `http://localhost:8000`
— the *visitor's* machine, not your server. It must be `https://`: an `https://`
page cannot call `http://` or open `ws://`.

**Backend — one small VM.** Everything else runs there as a single Compose
stack:

```bash
git clone <your-repo> && cd surfacewatch
cp .env.prod.example .env.prod && chmod 600 .env.prod
# fill in API_DOMAIN, ACME_EMAIL, CORS_ORIGINS, JWT_SECRET, POSTGRES_PASSWORD
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

`docker-compose.prod.yml` is standalone rather than an override of the
development file — Compose merges lists by appending, so layering them would
keep the dev bind mounts and the published Postgres/Redis ports. Caddy is the
only container that publishes a port; it obtains and renews Let's Encrypt
certificates automatically, which is what makes the browser able to reach the
API at all.

Point `API_DOMAIN`'s A record at the VM **before** starting the stack, or Caddy
cannot complete the ACME challenge. A free subdomain from a dynamic-DNS provider
works if you do not own a domain.

Any VM with ~1 GB of RAM runs this; the sizing defaults in `.env.prod.example`
are tuned for that. Providers' free tiers move, so check current offers rather
than trusting a list here.

**What does not work:** serverless Postgres and Redis (Neon, Upstash) have real
perpetual free tiers, but they only replace the datastores. The Celery workers
still need a machine. A frontend-plus-serverless-database stack cannot scan.

**Two settings that must agree.** `CORS_ORIGINS` on the backend must contain the
frontend's origin — the browser's `Origin` header is what is checked, never the
API's own address. Netlify gives every branch and pull-request deploy its own
origin, and those are not covered by the production one; add them or previews
fail CORS.

### `TRUSTED_PROXY_COUNT`

Rate limiting keys on client IP, which is read from `X-Forwarded-For`. That
header is trivially forged, so it is only trusted when this is set above zero,
and the client is taken as the Nth entry from the right.

**Set it to the number of proxies you actually run.** If the app is directly
exposed, leave it at `0` — otherwise anyone can bypass rate limiting by sending
a fake header.

### Datastore binding

Postgres and Redis bind to `127.0.0.1` by default. Docker inserts its publish
rules *ahead* of ufw and firewalld, so binding to `0.0.0.0` exposes them to your
whole network even with the host firewall enabled. Redis has no password at all,
so this matters.

---

## Security notes

- **Organisation isolation** is enforced in SQL on every query, and tested in
  `tests/test_org_isolation.py` — including a case that plants a cross-tenant
  row directly in the database and asserts the API refuses to resolve it.
- **Passwords** are checked against breach patterns, keyboard walks, and the
  account's own identifying strings, not just length and character classes. A
  12-character password with a letter and a digit is `password1234`.
- **Auth endpoints are rate limited** per-IP and per-account, so a single source
  brute-forcing one account and a distributed spray against many are both
  covered. Redis-backed, shared across API replicas, and fails *open* — a
  limiter that fails closed is a cheaper denial of service than the one it
  prevents.
- **SSRF guards** on every outbound fetch: scanners refuse to resolve to link-local
  or private ranges. See `workers/safe_http.py` and `tests/test_ssrf_guard.py`.
- **Tokens live in localStorage**, which is a deliberate trade-off documented in
  `frontend/SECURITY-NOTES.md`. It is XSS-readable; the CSP is set accordingly.

Never commit `.env`. It holds the JWT signing key and database password, and is
excluded in `.gitignore` at every directory level. If one is ever pushed,
deleting it later does not remove it from history — rotate the secret.

---

## Tests

```bash
cd backend
docker run -d --rm --name surfacewatch-testdb \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres \
  -p 127.0.0.1:55432:5432 postgres:16-alpine

.venv/bin/python -m pytest tests/ -q --ignore=tests/e2e_live.py
```

The suite needs a real PostgreSQL because the isolation guarantees under test
are enforced in SQL. It runs on port **55432** deliberately: `conftest.py` drops
and recreates its database on every run, so it must never point at your
development instance.

Redis and Celery are faked in-process — no broker needed.

---

## Authorised use

Port scanning, subdomain enumeration, and service fingerprinting against
infrastructure you do not own or have written permission to test is illegal in
most jurisdictions.

`ALLOW_ARBITRARY_TARGETS` defaults to `false`, which restricts scanning to
domains verified against your organisation. That guard is there on purpose.
Disabling it is your decision and your liability.

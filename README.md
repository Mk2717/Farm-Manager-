# Farm Manager SaaS

Offline-first livestock farm management platform for layers, broilers, goats, cattle, sheep and other farm animals.

## Current milestone

Phase 0A Step 6: owner onboarding, authenticated multi-tenant farm accounts, offline-first browser storage, sync API, normalized PostgreSQL projections for daily records, flock population, production and stock movements, audit history, and domain integrity rules.

## Development login

When running with the local file store:

- Email: `owner@farm.local`
- Password: `farm12345`

Do not use the development credentials in production.

## Run locally

```bash
npm install
npm run build
npm start
```

Open `http://localhost:4173`.

## Tests

```bash
npm test
npm run test:production
npm run test:step6
```

## Production configuration

Copy `.env.example` and configure `DATABASE_URL` and a strong `FARM_MANAGER_SECRET`. Apply migrations using `npm run db:migrate`, then seed only when appropriate.

## Architecture

The browser uses IndexedDB and a service worker for offline operation. The cloud API authenticates users, separates organizations, accepts idempotent sync commands, detects version conflicts, projects accepted farm commands into normalized PostgreSQL tables, and retains audit/sync history.

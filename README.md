# Farm Manager SaaS

Offline-first livestock operations app for layers, broilers, goats, cattle, sheep and extensible species.

## Current deployment milestone

Phase 0A foundation plus early operational UI modules.

Implemented in the deployed app:

- Device-local administrator workspace while production authentication is deferred
- Flocks and ledger-derived population
- Individual animal register
- Daily mortality, egg, feed and water entry
- Multi-species production records
- Inventory items and ledger-derived stock balances
- Receipts, issues, wastage and stock adjustments
- Health, vaccination, treatment and follow-up records
- Farm profile, operational locations, and extensible species/breed master data
- Breeding, pregnancy, birth and weaning event register
- Compact phone layout with bottom navigation and denser field-work cards
- Swipeable bottom navigation with forward and back controls
- Supplier directory and purchase tracking
- Customer directory, sales revenue and credit tracking
- Categorized expense and cash-outflow tracking
- Farm tasks, priorities, due dates and completion alerts
- IndexedDB persistence, service worker, offline queue and audit history
- Mobile-first responsive interface

## Blueprint invariants preserved

- Flock population is derived from population events.
- Stock balance is derived from stock movements.
- Corrections use new ledger events; records are not silently deleted.
- Offline commands use unique IDs for future idempotent synchronization.
- Cloud failure never removes local records.

## Phase 0A hardening priorities

The next work must strengthen the foundation before adding more broad modules:

1. Restore secure owner authentication and role/permission enforcement.
2. Project every new operational command into hosted normalized tables.
3. Add organization context to every tenant-owned record.
4. Implement per-entity conflict resolution and visible sync recovery.
5. Add reversal workflows for population and inventory ledger corrections.
6. Seed roles and permissions, building on the implemented species and breed catalog.
7. Add domain tests for every browser workflow and its server projection.

## Deferred blueprint modules

- Reporting
- Multi-farm switching and nested locations

The historical Phase 0A handoff remains the architecture authority; this deployment adapts its runtime to ChatGPT Sites without changing the ledger and offline-first principles.

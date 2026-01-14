## Project Snapshot
- Core orchestration lives in [bootstrap/server.py](bootstrap/server.py), mixing Flask endpoints, SQLAlchemy models, ML analytics, and defensive middleware; expect cross-cutting concerns in one file.
- Security/AI helpers under [pisecure/api/](pisecure/api) (Sentinel, DDoS, Validation) are imported into the server module and mutated at runtime, so changes here ripple immediately into request handling.
- Configuration loads from [config.json](config.json) plus environment overrides; `load_node_config()` assigns primary vs secondary roles and runtime domains, so avoid duplicating this logic when adding env-dependent behavior.
- SQLite state is stored in `pisecure_bootstrap.db` via SQLAlchemy models defined near the top of [bootstrap/server.py](bootstrap/server.py); migrations are implicit, so schema edits must stay backward compatible or add defensive guards.

## Runtime & Workflows
- Install deps with `pip install -r requirements.txt`; heavy ML libs (scikit-learn, scipy, numpy) require a working compiler toolchain on macOS.
- Run the service locally via `python bootstrap/server.py`; it binds to `PORT` (default 8080) and auto-loads configuration, caches, and ML models.
- Railway deployments rely on the same entrypoint plus env vars such as `BOOTSTRAP_ROLE`, `PRIMARY_BOOTSTRAP_DOMAIN`, and `RAILWAY_PUBLIC_DOMAIN`; document any new env knob in [README.md](README.md) and ensure defaults keep secondary nodes safe.
- Tests only cover the legacy `BootstrapNode` shim in [tests/test_bootstrap.py](tests/test_bootstrap.py); keep `_parse_bootstrap_peers()` and related helpers intact or update the tests alongside changes.
- Use `pytest` from the repo root; no tox or makefile exists, so spell out custom commands inside PRs or doc updates.

## Architecture & Data Flow
- Incoming requests pass through `ddos_protection_middleware` in [bootstrap/server.py](bootstrap/server.py#L520-L570); health endpoints are whitelisted, all others feed into `pisecure/api/ddos_protection.py`.
- `NodeTracker`, `MiningStatsAggregator`, `PeerDiscoveryService`, and `NetworkIntelligence` (same file) form the in-memory model; they also persist critical slices to SQLite, so any new mutating path should update both memory and DB.
- Geolocation lookups hit ip-api.com and are cached in [GeoCache](bootstrap/server.py), meaning new code should reuse `geo_locator.geolocate_ip()` rather than issuing raw HTTP requests.
- Sentinel coordination, DEX orchestration, and rewards management each maintain internal queues/deques; avoid long blocking operations in route handlers because they already juggle background threads (cleanup, ML training).
- Primary/secondary federation flows depend on `_discover_runtime_domain()`, `_get_primary_domains()`, and `_register_with_primary_bootstrap()`; hook into these helpers when exposing new clustering metadata.

## API & Security Patterns
- Every API route logs via `logger`, calls `network_intelligence.record_connection()` with client IP/UA, and often references `_process_node_intelligence()` or `_get_node_recommendations()`; mirror that pattern for new endpoints to keep telemetry consistent.
- User payloads must run through `validation_engine` from [pisecure/api/validation.py](pisecure/api/validation.py), especially for anything touching wallets, hashes, or token amounts.
- Sentinel-facing endpoints expect requester reputation checks handled by [pisecure/api/sentinel.py](pisecure/api/sentinel.py); never bypass these guards when introducing new reputation or defense flows.
- DDoS decisions come from `ddos_protection.analyze_request()` defined in [pisecure/api/ddos_protection.py](pisecure/api/ddos_protection.py); if you add long-running handlers, consider early exits for blocked clients to avoid holding Flask workers.
- When coordinating bootstrap federation or peer lists, prefer helper functions like `_get_registered_bootstrap_nodes()` and `peer_discovery.get_bootstrap_peers()` rather than re-querying the database manually.

## Domain-Specific Modules
- Sentinel service keeps reputations, threat signatures, defense actions, and blockchain alerts in memory with RLock protection; any cross-thread calls must acquire locks via the service methods rather than mutating attributes directly.
- DDoS protection maintains `ClientProfile` objects plus fingerprint deques; tune thresholds via class attributes instead of module globals to preserve thread safety.
- Validation engine layers sanitization (HTML/XSS/SQL/path), schema enforcement, blockchain-specific checks, and behavior scoring; prefer extending `_load_schemas()` or helper validators instead of stacking ad-hoc regexes in routes.
- The `/nodes` dashboard is a static template ([bootstrap/templates/nodes.html](bootstrap/templates/nodes.html)) that fetches JSON metrics; when adding new dashboard cards, surface the data through JSON APIs first, then update the template.
- Reward analytics and DEX orchestration live in the lower half of [bootstrap/server.py](bootstrap/server.py); both expect `pisecure_dex` and `bootstrap_rewards` singletons to hold state, so inject dependencies there if integrating new financial flows.

## Testing & Quality
- No linting is enforced; keep functions short and add targeted comments (e.g., before complex ML scoring) to help future agents reason about the logic.
- Because SQLite tables auto-create at import time, add defensive checks before altering schemas or long-running migrations to keep Railway boot times low.
- When touching background threads (cleanup loops in Sentinel/DDoS), ensure they remain daemonized and idempotent; leaked threads will hang pytest and Railway deploys.

## Collaboration
- Document any new env vars, API shapes, or operational steps in [README.md](README.md) immediately; the file doubles as the ops runbook.
- Coordinate significant security changes with Sentinel, DDoS, and Validation owners by updating the respective modules plus their integration touchpoints in [bootstrap/server.py](bootstrap/server.py).

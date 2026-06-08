# OpenMaskit E2E tests

Browser-driven end-to-end tests that boot a real OpenMaskit subprocess on dedicated ports, install marketplace servers, and drive the dashboard with Playwright.

## What's covered

- `test_postgres_flow.py` — install PostgreSQL from the marketplace, hide a tool, run a SQL query, mask `email` (via the hover-to-Mask tree button) and `phone_number` (via the manual path entry), verify both fields render as aliases, add an argument guardrail on `sql`, and confirm a dangerous query is blocked.

## Prerequisites

- A running container runtime (Docker / Podman / nerdctl / Finch) so the `crystaldba/postgres-mcp` image can be pulled and launched by the proxy.
- A Postgres database with a `users` table containing `email` and `phone_number` columns.
  ```sql
  CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      name TEXT,
      email TEXT,
      phone_number TEXT
  );
  INSERT INTO users VALUES
      (1, 'John Krasinsky', 'user1@yahoo.com', NULL),
      (2, 'John Doe', 'john.doe@gmail.com', '+31611119987');
  ```
- Reachable from the container — on macOS that means `host.containers.internal` (Podman) or `host.docker.internal` (Docker Desktop), not `localhost`.
- Network access to `api.maskitmcp.com` (the marketplace catalog).
- Ports `19473` / `19474` free.

## Run

```bash
# Install Playwright deps + the browser (one-time)
uv sync --group e2e
uv run --group e2e playwright install chromium

# Run the e2e suite
OM_E2E_PG_URI=postgresql://user:pass@host.containers.internal:5432/dbname \
    uv run --group e2e pytest tests/e2e -m e2e -v

# Headed (watch it click through):
OM_E2E_PG_URI=... uv run --group e2e pytest tests/e2e -m e2e -v --headed --slowmo 200

# Dump the OpenMaskit subprocess stderr on shutdown (debugging startup):
OM_E2E_PG_URI=... OM_E2E_DUMP_LOGS=1 uv run --group e2e pytest tests/e2e -m e2e -v
```

E2E tests are excluded from the default `uv run pytest tests/` run via the `-m 'not e2e'` default in `pyproject.toml`, so they never run accidentally in CI's unit-test stage.

## Notes

- Each run spawns a fresh OpenMaskit subprocess against a per-session tmp store dir, so tests never touch your real `~/.openmaskit/` data and runs are independent.
- The proxy must download the postgres-mcp container image on first run — the install step's timeout is set to 60s to accommodate this; if you're on a slow link, pre-pull with `docker pull crystaldba/postgres-mcp` (or your runtime's equivalent).

# Infrastructure

Infrastructure assets are intentionally lightweight for local development.

The main deployment entry point is the repository-level `docker-compose.yml`, which can start:

- PostgreSQL for case persistence
- the FastAPI backend
- the optional Next.js dashboard profile

See `docs/DEPLOYMENT.md` for the full setup guide.

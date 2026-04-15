# vulnman-platform

## Architecture

vuln-mgmt-platform/
├── app/
│   ├── main.py              # FastAPI app & Router setup
│   ├── config.py            # Configuration (Pydantic V2)
│   ├── database.py          # Async Engine & Session management
│   ├── models.py            # SQLAlchemy Schemas (Scan, Vulnerability)
│   ├── schemas.py           # Pydantic Schemas (Validation)
│   ├── deps.py              # Dependencies (Auth - ready for expansion)
│   ├── tasks.py             # Celery Tasks & Worker Logic
│   ├── services/            # Business Logic (RiskCalculator)
│   │   └── scoring.py
│   └── routers/
│       ├── webhooks.py      # Ingestion endpoints
│       └── vulns.py         # Query endpoints
├── alembic/                  # Database Migrations
├── tests/                    # Integration Tests
├── Dockerfile               # Container definition
└── docker-compose.yml       # Orchestration

## Key Features

1. Asynchronous Webhook Ingestion

- Endpoint: POST /api/v1/webhooks/ingest
- Logic: Accepts raw JSON from scanners, creates a Scan record with status pending, and immediately returns 202 Accepted.
- Benefit: Decouples the ingestion speed (API) from processing speed (Worker).


2. Intelligent Risk Scoring

- Logic: We don't just store the CVSS score. We calculate a Calculated Risk Score (0-10) based on:
- Technical Severity: Base CVSS score.
- Asset Context: Is the target prod or dev?
- Threat Intelligence: Does the vulnerability have a known exploit?
- Benefit: Prioritizes vulnerabilities that actually matter to the business (e.g., a 9.0 in prod is riskier than a 9.0 in dev).


3. Normalization Pipeline

- Logic: Converts disparate scanner outputs (Trivy, Snyk, etc.) into a unified Vulnerability schema.
- Benefit: Standardizes data for consistent querying and dashboard visualization across different tools.

## Stack

| Technology | Why We Used It |
| ----------- | ---------------- |
| **FastAPI (Async)** | **High Concurrency:** Webhooks can arrive in bursts. Async/await allows the API to handle thousands of concurrent ingestion requests without blocking threads. It's I/O bound (network/DB), making async the optimal choice over traditional threaded servers. |
| **PostgreSQL** | **Data Integrity:** Vulnerability data is relational (Scans have many Vulnerabilities). We need ACID transactions to ensure data consistency. We utilize JSONB for storing raw scan payloads and complex window functions for analytics. |
| **Redis** | **The Glue:** Acts as both a Message Broker (Queue) and Cache. As a broker, it provides the low-latency pub/sub mechanism needed for Celery. It ensures that no scan jobs are lost if the workers are temporarily busy. |
| **Celery** | **Reliable Background Processing:** Normalization and risk scoring are CPU-intensive. Running these in the API thread would block user requests. Celery offloads this work to dedicated worker processes, ensuring the API returns `202 Accepted` immediately. |
| **Docker Compose** | **Infrastructure as Code:** Orchestrates the complex interaction between App, Worker, DB, and Redis. Ensures the development environment matches production (Parity). |
| **SQLAlchemy 2.0 (Async)** | **ORM Abstraction:** Provides a clean Python interface for database interactions while allowing us to write efficient SQL. We use the async engine to avoid blocking the event loop during DB transactions. |


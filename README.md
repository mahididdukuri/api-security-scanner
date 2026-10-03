# API Security Scanner

A FastAPI-based API security scanner for detecting common OWASP API vulnerabilities, with JWT-authenticated scan history stored in PostgreSQL.

## Overview

API Security Scanner is a backend security tool that automatically tests REST APIs for common OWASP API vulnerabilities — things like broken object-level authorization, weak authentication, and missing security headers.

Given a target API's URL, it discovers all available endpoints via the OpenAPI spec, runs a configurable set of security checks against them, and generates a risk score and detailed findings report. Scans are authenticated and private — each user only sees their own scan history, stored in PostgreSQL.

Built as a hands-on project applying backend engineering (FastAPI, PostgreSQL, JWT auth) to practical cybersecurity testing.

## Features

* **OpenAPI-based endpoint discovery** — automatically discovers available API endpoints from the target API's OpenAPI specification.
* **Configurable security checks** — individual checks can be enabled or disabled through the scanner configuration.
* **JWT-based authentication** — protects the scanner API and ensures each user can access only their own scan history.
* **Background scan execution** — starts scans as background tasks so the API can respond without waiting for the entire scan to finish.
* **Risk scoring** — calculates a per-scan risk score based on the severity and status of detected findings.
* **Automated testing** — includes a pytest test suite that runs automatically through GitHub Actions.
* **Docker support** — provides a Dockerfile for a consistent application environment.

## Vulnerability Checks

The scanner currently includes checks for:

* **Broken Object-Level Authorization (BOLA)** — tests whether authenticated users can access objects belonging to other users.
* **Broken Authentication** — checks for weak authentication behavior, including weak password acceptance.
* **Sensitive Data Exposure** — checks API responses for potentially sensitive information.
* **Rate Limiting** — tests whether endpoints appropriately limit repeated requests.
* **Broken Function-Level Authorization** — checks whether protected functionality can be accessed without the required authorization.
* **Security Headers** — checks API responses for recommended security-related HTTP headers.
* **Invalid Token Handling** — verifies that invalid authentication tokens are rejected.
* **Expired Token Handling** — verifies that expired authentication tokens are rejected.

## Tech Stack

* **Backend:** FastAPI, Python 3.13
* **Database:** PostgreSQL, SQLAlchemy ORM, Alembic for migrations
* **Authentication:** JWT (`python-jose`), bcrypt for password hashing
* **Testing:** pytest
* **CI/CD:** GitHub Actions
* **Containerization:** Docker
* **Version Control:** Git, GitHub

## Architecture

                ┌─────────────────────┐
                │    Client / User    │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │    Scanner API      │
                │      FastAPI        │
                │  JWT Authentication │
                └──────────┬──────────┘
                           │
                       Start Scan
                           │
                           ▼
                ┌─────────────────────┐
                │   Scanner Engine    │
                │                     │
                │  OpenAPI Discovery  │
                │         ↓           │
                │  Security Checks    │
                │         ↓           │
                │  Findings           │
                │         ↓           │
                │  Risk Scoring       │
                └──────┬───────┬──────┘
                       │       │
                ┌──────▼───┐ ┌─▼────────────────┐
                │ Target   │ │    PostgreSQL     │
                │   API    │ │ Scan History &    │
                │          │ │ Findings          │
                └──────────┘ └───────────────────┘


The Scanner API handles authenticated scan requests. Once a scan starts, the Scanner Engine discovers the target's endpoints through its OpenAPI specification, runs the configured security checks against them, records the findings, and calculates a risk score. Scan results are stored in PostgreSQL and scoped to the user who initiated the scan.

## Project Structure

api-security-scanner/
│
├── .github/
│ └── workflows/
│ └── tests.yml # GitHub Actions CI workflow
│
├── alembic/
│ └── versions/
│ └── c229d54c5bc5_initial_schema.py
│
├── api.py # Scanner API and authentication
├── scanner.py # Scan orchestration and result processing
├── openapi_parser.py # OpenAPI endpoint discovery
├── findings.py # Common finding structure
├── risk_score.py # Risk score calculation
│
├── checker.py # BOLA checks
├── broken_auth_checker.py # Authentication checks
├── sensitive_data_checker.py # Sensitive data checks
├── rate_limit_checker.py # Rate-limit checks
├── security_headers_checker.py # Security header checks
│
├── config.py # Scanner configuration
├── db.py # Database connection
├── db_models.py # SQLAlchemy database models
│
├── vulnerable_api.py # Vulnerable API used for testing
│
├── test_checker.py # Tests for BOLA checker
├── test_delete_scan.py # Tests for scan deletion
├── test_findings.py # Tests for finding structure
├── test_openapi_parser.py # Tests for endpoint discovery
├── test_report.py # Tests for report generation
├── test_risk_score.py # Tests for risk scoring
├── test_scanner.py # Tests for scan orchestration
│
├── Dockerfile
├── alembic.ini
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore


The scanner is organized into separate modules for API management, endpoint discovery, vulnerability checks, result processing, and database access.

## Getting Started

### Prerequisites

Before running the project, make sure the following are installed:

* Python 3.13
* PostgreSQL
* Git
* Docker Desktop (optional, for running the project with Docker)

### Installation

Clone the repository and navigate into the project directory:

```bash
git clone https://github.com/mahididdukuri/api-security-scanner.git
cd api-security-scanner
```

Create and activate a virtual environment:

**Windows PowerShell:**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install the project dependencies:

```powershell
pip install -r requirements.txt
```

### Configuration & Environment Variables

Create a `.env` file in the project root:

```env
DB_PASSWORD=your_postgresql_password
JWT_SECRET=your_jwt_secret
```

These values are used for PostgreSQL database access and JWT authentication.

The `.env` file is excluded from version control through `.gitignore`. Never commit real passwords or secret keys to the repository.

### Database Setup

Create a PostgreSQL database named:

```text
api_security_scanner
```

Make sure PostgreSQL is running and that the credentials in `.env` are correct.

Run the database migrations:

```powershell
alembic upgrade head
```

This creates the required database tables using the project's Alembic migration history.

## Running the Application

### Run the Scanner API

Start the FastAPI scanner API with:

```powershell
uvicorn api:app --reload --port 8002
```

The Scanner API will be available at:

```text
http://127.0.0.1:8002
```

Interactive API documentation is available at:

```text
http://127.0.0.1:8002/docs
```

### Run the Vulnerable Test API

For local testing, the project includes a deliberately vulnerable FastAPI application.

Start it with:

```powershell
uvicorn vulnerable_api:app --reload --port 8004
```

The vulnerable API will be available at:

```text
http://127.0.0.1:8004
```

Its OpenAPI specification can be accessed at:

```text
http://127.0.0.1:8004/openapi.json
```

The vulnerable API is provided only as a local testing target for the scanner.

## Running Tests

Run the complete test suite with:

```powershell
pytest
```

The test suite covers core components including:

* Risk score calculation
* Finding generation
* OpenAPI endpoint discovery
* Vulnerability checks
* Scanner execution
* Report generation
* Database operations
* Scan deletion

The same test suite is automatically executed by GitHub Actions on pushes and pull requests.

## Example Scan & Screenshots

The scanner can be used to start a security scan against a target API and retrieve the resulting findings and risk score through the FastAPI interface.

Example scan flow:

```text
Authenticate
     ↓
Provide target API URL
     ↓
Start scan
     ↓
OpenAPI endpoint discovery
     ↓
Security checks
     ↓
Findings + risk score
     ↓
Scan history stored in PostgreSQL
```

Screenshots demonstrating the scanner API, scan results, findings, and risk score will be included here.

## API Endpoints

The Scanner API provides endpoints for authentication, scan management, and retrieving scan results.

| Method   | Endpoint          | Description                                   | Authentication |
| -------- | ----------------- | --------------------------------------------- | -------------- |
| `POST`   | `/register`       | Register a new scanner user                   | No             |
| `POST`   | `/login`          | Authenticate a user and obtain a JWT          | No             |
| `POST`   | `/scan`           | Start a security scan for a target API        | JWT            |
| `GET`    | `/scan/{scan_id}` | Retrieve a scan and its findings              | JWT            |
| `GET`    | `/scans`          | List the authenticated user's scans           | JWT            |
| `DELETE` | `/scan/{scan_id}` | Delete a scan owned by the authenticated user | JWT            |

Interactive API documentation is available at:

```text
http://127.0.0.1:8002/docs
```

## Risk Scoring System

Each failed security check contributes to the overall risk score based on its severity.

| Finding       | Score |
| ------------- | ----: |
| PASS          |     0 |
| FAIL — Low    |    +1 |
| FAIL — Medium |    +3 |
| FAIL — High   |    +5 |

The final risk score is calculated by adding the scores of all failed findings in a scan.

```text
Risk Score = Sum of scores for all FAIL findings
```

Passing checks do not contribute to the risk score.

## CI/CD (GitHub Actions & Docker)

### GitHub Actions

The project uses GitHub Actions to automatically run the test suite whenever changes are pushed or a pull request is created.

The CI workflow:

1. Checks out the repository.
2. Sets up Python.
3. Installs project dependencies.
4. Starts a PostgreSQL service.
5. Runs Alembic database migrations.
6. Starts the vulnerable test API.
7. Runs the pytest test suite.

### Docker

The project includes a `Dockerfile` to provide a consistent environment for running the application.

Docker support helps reduce differences between development environments and makes the project easier to set up and deploy.

## Future Improvements

* Expand vulnerability coverage to include additional OWASP API security risks.
* Improve OpenAPI parsing and endpoint discovery for more complex API specifications.
* Add more advanced authentication and authorization testing.
* Add background job management for long-running scans.
* Improve risk scoring with confidence and contextual factors.
* Add richer report generation and export formats.
* Expand automated test coverage and CI checks.
* Improve Docker-based deployment and configuration.

## Known Limitations

* The scanner currently covers a subset of common OWASP API security vulnerabilities rather than the complete OWASP API Top 10.
* Vulnerability checks are currently rule-based and may require additional API-specific context for more complex applications.
* The vulnerable API included in the project is intended for local testing and demonstration purposes.
* Scan execution currently runs as a FastAPI background task and is not managed by a dedicated job queue.
* Risk scoring is based on predefined severity weights and does not currently account for contextual factors.
* Report generation currently supports JSON output.

## License

This project is licensed under the MIT License.

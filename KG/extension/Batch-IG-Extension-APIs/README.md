# Batch-IG-Extension-APIs

FastAPI service that acts as the API layer between the **Batch KG VS Code extension** and the **Neo4j information graph**.  
All graph communication goes through this service — the extension never talks to Neo4j directly.

---

## Project structure

```
Batch-IG-Extension-APIs/
├── app/
│   ├── main.py              ← FastAPI app + lifespan hooks
│   ├── config.py            ← Settings loaded from .env
│   ├── models/
│   │   └── schemas.py       ← Pydantic response models
│   ├── routers/
│   │   └── graph.py         ← All API endpoints
│   └── services/
│       └── neo4j_service.py ← Async Neo4j queries + grey-area keyword logic
├── requirements.txt
├── .env.example
└── README.md
```

---

## Setup

### 1. Create a virtual environment

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|---|---|---|
| `NEO4J_URI` | Neo4j bolt URI | `bolt://localhost:7687` |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | *(required)* |
| `NEO4J_DATABASE` | Neo4j database name | `information_graph` |
| `API_HOST` | Host to bind the server | `0.0.0.0` |
| `API_PORT` | Port to bind the server | `8000` |

---

## Running the server

```bash
# From the Batch-IG-Extension-APIs directory
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Or via the entry point:

```bash
python -m app.main
```

---

## API endpoints

All endpoints are prefixed with `/api/v1`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Test Neo4j connectivity |
| `GET` | `/api/v1/jobs` | List all jobs with gap counts |
| `GET` | `/api/v1/jobs/{job_name}/steps` | List steps for a job |
| `GET` | `/api/v1/steps/{step_name}/gaps` | Get gaps (db / procedure / shell) for a step |
| `GET` | `/api/v1/methods/java-file?fqn={fqn}` | Resolve Java source file for a method FQN |

Interactive docs are available at `http://localhost:8000/docs` once the server is running.

---

## VS Code extension configuration

In VS Code settings (`batchKg` namespace), set:

```json
{
  "batchKg.apiUrl": "http://localhost:8000"
}
```

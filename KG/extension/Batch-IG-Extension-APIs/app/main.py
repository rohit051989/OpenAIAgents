import logging
import uvicorn
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import graph
from app.services.neo4j_service import close_driver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Batch-IG-Extension-APIs starting up …")
    yield
    logger.info("Batch-IG-Extension-APIs shutting down — closing Neo4j driver …")
    await close_driver()


app = FastAPI(
    title="Batch-IG Extension APIs",
    description=(
        "REST API layer between the Batch KG VS Code extension and Neo4j. "
        "All graph queries are executed here so the extension stays thin."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Allow the VS Code extension (which runs as a local process, not a browser) and
# any local dev tools to call the API without CORS issues
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(graph.router, prefix="/api/v1")


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
    )

from fastapi import APIRouter, HTTPException
from typing import List, Optional

from app.models.schemas import (
    HealthResponse,
    GapsResponse,
    JavaMethodInfo,
    Job,
    Repository,
    Step,
)
from app.services import neo4j_service

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check():
    """Test connectivity to Neo4j."""
    connected = await neo4j_service.test_connection()
    if not connected:
        raise HTTPException(
            status_code=503,
            detail="Neo4j connection failed. Check server settings.",
        )
    return HealthResponse(status="ok", message="Neo4j connection successful.")


@router.get("/jobs", response_model=List[Job], tags=["graph"])
async def get_jobs():
    """Return all jobs with their gap counts."""
    try:
        return await neo4j_service.get_all_jobs()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/jobs/{job_name}/steps", response_model=List[Step], tags=["graph"])
async def get_steps(job_name: str):
    """Return all steps for a given job with their gap counts."""
    try:
        return await neo4j_service.get_steps_for_job(job_name)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/steps/{step_name}/gaps", response_model=GapsResponse, tags=["graph"])
async def get_gaps(step_name: str):
    """Return categorised gaps (db / procedure / shell) for a given step."""
    try:
        return await neo4j_service.get_gaps_for_step(step_name)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/methods/java-file", response_model=Optional[JavaMethodInfo], tags=["graph"])
async def get_java_file(fqn: str):
    """Return method details and owning class info (source code, git metadata) for a method FQN."""
    try:
        result = await neo4j_service.get_java_file_for_method(fqn)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"No Java method found for FQN: {fqn}",
            )
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/repositories", response_model=List[Repository], tags=["graph"])
async def get_repositories():
    """Return all Repository nodes from the information graph (up to 25)."""
    try:
        return await neo4j_service.get_all_repositories()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

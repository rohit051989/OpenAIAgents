from pydantic import BaseModel
from typing import List, Optional


class Job(BaseModel):
    name: str
    jobId: str


class Step(BaseModel):
    name: str
    stepId: str
    stepKind: Optional[str] = None
    gap_count: int = 0


class GapInfo(BaseModel):
    category: str          # 'db' | 'procedure' | 'shell'
    operation: str
    methodFqn: str
    furtherAnalysisRequired: bool


class GapsResponse(BaseModel):
    db: List[GapInfo] = []
    procedure: List[GapInfo] = []
    shell: List[GapInfo] = []


class JavaMethodInfo(BaseModel):
    # From JavaMethod node
    methodFqn: str
    methodName: Optional[str] = None
    javaLineCount: Optional[int] = None
    sourceCode: Optional[str] = None
    # From JavaClass node
    filePath: Optional[str] = None
    classFqn: Optional[str] = None
    gitBranchName: Optional[str] = None
    gitRepoName: Optional[str] = None


class Repository(BaseModel):
    name: str
    repoName: Optional[str] = None
    repoUrl: Optional[str] = None
    branchName: Optional[str] = None
    path: Optional[str] = None
    repoType: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    message: str

from pydantic import BaseModel, Field


class Finding(BaseModel):

    rule_id: str

    category: str

    severity: str

    file_path: str

    line_number: int

    title: str

    description: str

    remediation: str

    confidence: float = Field(
        ge=0,
        le=1
    )

    evidence: str


class ReviewReport(BaseModel):

    summary: str

    overall_score: int = Field(
        ge=0,
        le=100
    )

    risk_level: str

    findings: list[Finding]

    retrieved_policies: list[str]

    latency_ms: float

    structured_output_valid: bool
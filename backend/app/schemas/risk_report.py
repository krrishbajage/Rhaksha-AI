"""Risk report schema."""

from pydantic import BaseModel, Field


class RiskReport(BaseModel):
    risk_score: float = Field(ge=0, le=100)
    risk_level: str
    scam_category: str
    explanation: str
    recommended_action: str

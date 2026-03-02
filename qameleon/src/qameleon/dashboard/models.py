"""Pydantic response models for the dashboard API."""

from typing import Optional
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    c_acceleration: bool


class NodeStatusResponse(BaseModel):
    node_id: str
    classification_level: int
    active_sessions: int
    keys_stored: int
    default_kem: str
    default_sig: str


class ThreatSnapshotResponse(BaseModel):
    sca_score: float
    network_score: float
    quantum_score: float
    unified_score: float
    timestamp: float
    recommendation: str


class SessionInfoResponse(BaseModel):
    session_id: str
    messages_sent: int
    messages_received: int
    bytes_sent: int
    bytes_received: int
    created_at: float
    expires_at: Optional[float]

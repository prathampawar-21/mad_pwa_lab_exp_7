"""QAMELEON management dashboard FastAPI application."""

import time
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from qameleon.crypto_primitives.c_accel import is_accelerated
from qameleon.dashboard.auth import APIKeyMiddleware, APIKeyStore
from qameleon.dashboard.models import (
    HealthResponse,
    NodeStatusResponse,
    ThreatSnapshotResponse,
)
from qameleon.dashboard.rate_limiter import RateLimiterMiddleware
from qameleon.key_management.key_store import KeyState, KeyStore
from qameleon.threat_intel.unified_threat_score import UnifiedThreatScorer

_START_TIME = time.time()

_DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>QAMELEON Dashboard</title>
    <meta http-equiv="refresh" content="10">
    <style>
        body { font-family: monospace; background: #0a0a0a; color: #00ff41; margin: 20px; }
        h1 { color: #00ff41; border-bottom: 1px solid #00ff41; }
        .card { border: 1px solid #00ff41; padding: 15px; margin: 10px 0; }
        .metric { display: flex; justify-content: space-between; margin: 5px 0; }
        .value { color: #ffffff; }
        .status-ok { color: #00ff41; }
        .status-warn { color: #ffff00; }
        .status-crit { color: #ff4141; }
    </style>
</head>
<body>
    <h1>🔐 QAMELEON Post-Quantum Security Dashboard</h1>
    <div class="card">
        <h2>System Status</h2>
        <div class="metric"><span>Status</span><span class="value status-ok">OPERATIONAL</span></div>
        <div class="metric"><span>Version</span><span class="value">1.0.0</span></div>
        <div class="metric"><span>C Acceleration</span>
            <span class="value">{c_accel}</span></div>
    </div>
    <div class="card">
        <h2>Endpoints</h2>
        <div class="metric"><span>Health</span><span class="value"><a href="/health" style="color:#00ff41">/health</a></span></div>
        <div class="metric"><span>Status</span><span class="value"><a href="/status" style="color:#00ff41">/status</a></span></div>
        <div class="metric"><span>Threat</span><span class="value"><a href="/threat" style="color:#00ff41">/threat</a></span></div>
        <div class="metric"><span>Sessions</span><span class="value"><a href="/sessions" style="color:#00ff41">/sessions</a></span></div>
    </div>
    <p style="color:#555">Auto-refreshes every 10 seconds</p>
</body>
</html>"""


def create_dashboard_app(
    auth_enabled: bool = True,
    rate_limit_enabled: bool = True,
) -> FastAPI:
    """Create and configure the QAMELEON dashboard FastAPI application."""
    app = FastAPI(
        title="QAMELEON Dashboard",
        description="Post-Quantum Cryptographic Framework Management Dashboard",
        version="1.0.0",
    )

    # Initialize services
    key_store = KeyStore()
    threat_scorer = UnifiedThreatScorer()
    api_key_store = APIKeyStore()

    # Add middleware
    if rate_limit_enabled:
        app.add_middleware(RateLimiterMiddleware, capacity=60.0, refill_rate=10.0)
    if auth_enabled:
        app.add_middleware(APIKeyMiddleware, key_store=api_key_store, enabled=auth_enabled)

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_home():
        """HTML dashboard."""
        c_accel = "✅ ENABLED" if is_accelerated() else "❌ Python fallback"
        return HTMLResponse(_DASHBOARD_HTML.format(c_accel=c_accel))

    @app.get("/health", response_model=HealthResponse)
    async def health():
        """Health check endpoint."""
        return HealthResponse(
            status="healthy",
            version="1.0.0",
            uptime_seconds=time.time() - _START_TIME,
            c_acceleration=is_accelerated(),
        )

    @app.get("/status", response_model=NodeStatusResponse)
    async def status():
        """Node status endpoint."""
        active_keys = key_store.list_keys(KeyState.ACTIVE)
        return NodeStatusResponse(
            node_id="qameleon-node-01",
            classification_level=0,
            active_sessions=0,
            keys_stored=len(active_keys),
            default_kem="ML-KEM-768",
            default_sig="ML-DSA-65",
        )

    @app.get("/threat", response_model=ThreatSnapshotResponse)
    async def threat():
        """Current threat assessment."""
        snapshot = threat_scorer.compute()
        return ThreatSnapshotResponse(
            sca_score=snapshot.sca_score,
            network_score=snapshot.network_score,
            quantum_score=snapshot.quantum_score,
            unified_score=snapshot.unified_score,
            timestamp=snapshot.timestamp,
            recommendation=snapshot.recommendation,
        )

    @app.get("/sessions")
    async def sessions():
        """Active sessions list."""
        return {"sessions": [], "total": 0}

    @app.get("/audit")
    async def audit():
        """Audit log entries."""
        return {"entries": [], "total": 0}

    @app.get("/crypto/acceleration")
    async def crypto_acceleration():
        """C acceleration status."""
        return {
            "accelerated": is_accelerated(),
            "message": "C shared libraries loaded" if is_accelerated() else "Using pure Python",
        }

    return app

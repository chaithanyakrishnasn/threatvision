"""
Shared test fixtures for Phase 5 tests.
Uses the real async PostgreSQL session (database must be running).
"""
from __future__ import annotations

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
async def db():
    """Provide a real async DB session; rolls back after each test."""
    from app.database import async_session_factory
    async with async_session_factory() as session:
        yield session
        await session.rollback()

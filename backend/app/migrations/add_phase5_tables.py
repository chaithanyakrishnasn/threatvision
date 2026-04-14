"""
Migration: Add Phase 5 tables — analysts, tickets, ticket_activities, projects.
Safe to run on existing DBs — uses create_all which is additive only.
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))


async def migrate() -> None:
    from app.database import engine
    from app.models import Base
    # Import new models to ensure they register with metadata
    import app.models.analyst       # noqa: F401
    import app.models.ticket        # noqa: F401
    import app.models.ticket_activity  # noqa: F401
    import app.models.project       # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✓ Phase 5 tables created (analysts, tickets, ticket_activities, projects)")


if __name__ == "__main__":
    asyncio.run(migrate())

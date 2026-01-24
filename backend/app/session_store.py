"""
Persistent session storage using SQLite.
Stores sanitized analysis results for sharing and historical review.
"""

import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from sqlalchemy import select, delete, func, update
from .models import AnalyzeResponse, AnalysisSession
from .database import async_session

logger = logging.getLogger(__name__)


class SessionStore:
    """
    Persistent session storage using SQLite.
    - Stores results in analysis_sessions table
    - Auto-expires after 24 hours (via cleanup)
    - Capacity limit of 100 sessions (LRU-like eviction)
    """

    def __init__(self, max_size: int = 100, ttl_hours: int = 24):
        self.max_size = max_size
        self.ttl = timedelta(hours=ttl_hours)

    async def save(self, analysis: AnalyzeResponse, user_ip: str = None, 
                   user_agent: str = None, request_metadata: Dict = None) -> str:
        """
        Save an analysis result and return a session ID.
        """
        session_id = str(uuid.uuid4())
        
        async with async_session() as session:
            try:
                # Create ORM record with audit metadata
                record = AnalysisSession.from_analyze_response(
                    analysis, 
                    session_id,
                    user_ip=user_ip,
                    user_agent=user_agent,
                    request_metadata=request_metadata
                )
                session.add(record)
                
                # Check for capacity and evict oldest if necessary
                # Count current sessions
                result = await session.execute(select(func.count()).select_from(AnalysisSession))
                count = result.scalar() or 0
                
                if count >= self.max_size:
                    # Find and delete oldest by accessed_at
                    oldest = await session.execute(
                        select(AnalysisSession.session_id)
                        .order_by(AnalysisSession.accessed_at.asc())
                        .limit(1)
                    )
                    oldest_id = oldest.scalar()
                    if oldest_id:
                        await session.execute(
                            delete(AnalysisSession).where(AnalysisSession.session_id == oldest_id)
                        )
                
                await session.commit()
                return session_id
            except Exception as e:
                logger.error(f"Failed to save session: {e}")
                await session.rollback()
                raise

    async def get(self, session_id: str) -> Optional[AnalyzeResponse]:
        """
        Retrieve an analysis result by session ID.
        Returns None if not found or expired.
        """
        async with async_session() as session:
            try:
                result = await session.execute(
                    select(AnalysisSession).where(AnalysisSession.session_id == session_id)
                )
                record = result.scalar_one_or_none()
                
                if not record:
                    return None

                # Check if expired
                age = datetime.utcnow() - record.created_at
                if age > self.ttl:
                    await session.delete(record)
                    await session.commit()
                    return None

                # Update access time
                record.accessed_at = datetime.utcnow()
                await session.commit()
                
                return record.to_analyze_response()
            except Exception as e:
                logger.error(f"Failed to get session {session_id}: {e}")
                return None

    async def get_by_plan_hash(self, plan_hash: str) -> Optional[AnalyzeResponse]:
        """
        Retrieve the latest analysis result for a given plan hash.
        Returns None if not found or expired.
        """
        async with async_session() as session:
            try:
                # Find most recent analysis with this hash
                result = await session.execute(
                    select(AnalysisSession)
                    .where(AnalysisSession.plan_hash == plan_hash)
                    .order_by(AnalysisSession.created_at.desc())
                    .limit(1)
                )
                record = result.scalar_one_or_none()
                
                if not record:
                    return None

                # Check if expired
                age = datetime.utcnow() - record.created_at
                if age > self.ttl:
                    return None

                # Update access time
                record.accessed_at = datetime.utcnow()
                await session.commit()
                
                return record.to_analyze_response()
            except Exception as e:
                logger.error(f"Failed to get session by hash {plan_hash}: {e}")
                return None

    async def get_all(self, limit: int = 20) -> List[AnalyzeResponse]:
        """
        Retrieve latest analysis results.
        """
        async with async_session() as session:
            try:
                result = await session.execute(
                    select(AnalysisSession)
                    .order_by(AnalysisSession.created_at.desc())
                    .limit(limit)
                )
                records = result.scalars().all()
                return [r.to_analyze_response() for r in records]
            except Exception as e:
                logger.error(f"Failed to get history: {e}")
                return []

    async def cleanup_expired(self) -> int:
        """
        Remove all expired entries.
        """
        now = datetime.utcnow()
        expiry_limit = now - self.ttl
        
        async with async_session() as session:
            try:
                result = await session.execute(
                    delete(AnalysisSession).where(AnalysisSession.created_at < expiry_limit)
                )
                deleted_count = result.rowcount
                await session.commit()
                return deleted_count
            except Exception as e:
                logger.error(f"Failed to cleanup sessions: {e}")
                await session.rollback()
                return 0

    async def stats(self) -> Dict:
        """
        Get storage statistics.
        """
        async with async_session() as session:
            try:
                count_result = await session.execute(select(func.count()).select_from(AnalysisSession))
                total_sessions = count_result.scalar() or 0
                
                oldest_result = await session.execute(select(func.min(AnalysisSession.created_at)))
                oldest_date = oldest_result.scalar()
                
                now = datetime.utcnow()
                oldest_age_hours = 0
                if oldest_date:
                    oldest_age_hours = (now - oldest_date).total_seconds() / 3600

                return {
                    "total_sessions": total_sessions,
                    "max_size": self.max_size,
                    "ttl_hours": self.ttl.total_seconds() / 3600,
                    "oldest_age_hours": oldest_age_hours,
                }
            except Exception as e:
                logger.error(f"Failed to get stats: {e}")
                return {
                    "total_sessions": 0,
                    "max_size": self.max_size,
                    "ttl_hours": self.ttl.total_seconds() / 3600,
                    "oldest_age_hours": 0,
                    "error": str(e)
                }


# Global session store instance (singleton)
session_store = SessionStore(max_size=1000, ttl_hours=720)

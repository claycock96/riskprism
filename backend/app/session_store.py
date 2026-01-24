"""
In-memory session storage for analysis results.
Stores sanitized analysis results (no raw plans) for sharing and CLI→web workflow.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional
from collections import OrderedDict
from .models import AnalyzeResponse


class SessionStore:
    """
    Simple in-memory LRU cache for analysis results.
    - Stores last 100 results
    - Auto-expires after 24 hours
    - Thread-safe for single-process use
    """

    def __init__(self, max_size: int = 100, ttl_hours: int = 24):
        self.max_size = max_size
        self.ttl = timedelta(hours=ttl_hours)
        self._store: OrderedDict[str, Dict] = OrderedDict()

    def save(self, analysis: AnalyzeResponse) -> str:
        """
        Save an analysis result and return a session ID.
        """
        session_id = str(uuid.uuid4())

        # Store with metadata
        self._store[session_id] = {
            "analysis": analysis,
            "created_at": datetime.utcnow(),
            "accessed_at": datetime.utcnow(),
        }

        # Move to end (most recently used)
        self._store.move_to_end(session_id)

        # Evict oldest if over size limit
        if len(self._store) > self.max_size:
            # Remove oldest (first item)
            self._store.popitem(last=False)

        return session_id

    def get(self, session_id: str) -> Optional[AnalyzeResponse]:
        """
        Retrieve an analysis result by session ID.
        Returns None if not found or expired.
        """
        if session_id not in self._store:
            return None

        entry = self._store[session_id]

        # Check if expired
        age = datetime.utcnow() - entry["created_at"]
        if age > self.ttl:
            # Remove expired entry
            del self._store[session_id]
            return None

        # Update access time and move to end
        entry["accessed_at"] = datetime.utcnow()
        self._store.move_to_end(session_id)

        return entry["analysis"]

    def cleanup_expired(self):
        """
        Remove all expired entries.
        Called periodically or on-demand.
        """
        now = datetime.utcnow()
        expired_keys = [
            session_id
            for session_id, entry in self._store.items()
            if now - entry["created_at"] > self.ttl
        ]

        for key in expired_keys:
            del self._store[key]

        return len(expired_keys)

    def stats(self) -> Dict:
        """
        Get storage statistics.
        """
        now = datetime.utcnow()

        return {
            "total_sessions": len(self._store),
            "max_size": self.max_size,
            "ttl_hours": self.ttl.total_seconds() / 3600,
            "oldest_age_hours": (
                (now - min(e["created_at"] for e in self._store.values())).total_seconds() / 3600
                if self._store else 0
            ),
        }


# Global session store instance
session_store = SessionStore(max_size=100, ttl_hours=24)

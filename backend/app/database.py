import os
import logging
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from .models import Base

logger = logging.getLogger(__name__)

# Use /data/sessions.db inside container, which will be mapped to a volume
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:////app/data/sessions.db")

engine = create_async_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

async_session = async_sessionmaker(
    engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)

async def init_db():
    """Initialize database and create tables if they don't exist"""
    try:
        # Ensure directory exists
        db_path = DATABASE_URL.replace("sqlite+aiosqlite:///", "")
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"Created database directory: {db_dir}")

        async with engine.begin() as conn:
            # Import models to register them with Base
            from .models import AnalysisSession
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables initialized")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        # In a real app we might want to fail hard, but for MVP we might allow fallback
        # though since we are moving to persistence, database is required.
        raise

import logging
import os

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .models import Base

logger = logging.getLogger(__name__)

# Use /data/sessions.db inside container, which will be mapped to a volume
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:////app/data/sessions.db")

engine = create_async_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        "timeout": 5.0,  # 5 second busy timeout
    }
    if "sqlite" in DATABASE_URL
    else {},
)


# SQLite optimization: Enable WAL mode for concurrency
@event.listens_for(engine.sync_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if "sqlite" in DATABASE_URL:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


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
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        # In a real app we might want to fail hard, but for MVP we might allow fallback
        # though since we are moving to persistence, database is required.
        raise

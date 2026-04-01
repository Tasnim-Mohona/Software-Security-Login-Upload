import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
READONLY_DATABASE_URL = os.getenv("READONLY_DATABASE_URL")

if not DATABASE_URL or not READONLY_DATABASE_URL:
    raise ValueError("Missing architectural DATABASE_URL environment variables structurally.")

# Create an async database engine ensuring strong isolation and specific connection handling
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)

# Secondary Trust Distinction System Engine (Read-Only)
readonly_engine = create_async_engine(
    READONLY_DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True
)
ReadonlyAsyncSessionLocal = async_sessionmaker(
    readonly_engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

# Dependency for FastAPI to get DB sessions
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

# Dependency explicitly enforcing Read-Only Trust Credentials
async def get_readonly_db():
    async with ReadonlyAsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

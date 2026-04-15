from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.config import settings
from app.models import Base

engine = create_async_engine(settings.database_url, echo=False, pool_size=10) # Turn off echo in prod
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            # REMOVED auto-commit. Let the route decide when to commit.
        except Exception:
            await session.rollback()
            raise
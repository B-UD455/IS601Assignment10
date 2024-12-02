from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class Database:
    """Manages database connections and async sessions."""
    
    _engine = None
    _session_factory = None

    @classmethod
    def initialize(cls, database_url: str, echo: bool = False):
        """Initializes the database engine and session factory."""
        if cls._engine is None:
            cls._engine = create_async_engine(database_url, echo=echo, future=True)
            cls._session_factory = sessionmaker(
                bind=cls._engine, 
                class_=AsyncSession, 
                expire_on_commit=False, 
                future=True
            )

    @classmethod
    def get_session_factory(cls) -> sessionmaker:
        """Returns the session factory, ensuring it's initialized."""
        if cls._session_factory is None:
            raise ValueError("Database not initialized. Call `initialize()` first.")
        return cls._session_factory

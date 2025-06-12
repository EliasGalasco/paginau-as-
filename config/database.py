import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Replace with your actual database credentials
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@host:port/database_name")
# Example for individual components if not using a full URL:
# DB_USER = os.environ.get("DB_USER", "your_username")
# DB_PASSWORD = os.environ.get("DB_PASSWORD", "your_password")
# DB_HOST = os.environ.get("DB_HOST", "localhost")
# DB_PORT = os.environ.get("DB_PORT", "5432")
# DB_NAME = os.environ.get("DB_NAME", "your_database_name")
# DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

load_dotenv()

password = os.getenv("DB_PASSWORD")

db_url = f"postgresql://postgres:{password}@localhost:5432/api_security_scanner"

engine = create_engine(db_url)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

from db_models import Base



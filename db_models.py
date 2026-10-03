from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base,relationship
from datetime import datetime, UTC

Base=declarative_base()
class Scan(Base):
    __tablename__='scans'
    id=Column(Integer,primary_key=True)
    target_url=Column(String)
    status=Column(String)
    risk_score=Column(Integer)
    created_at=Column(DateTime,default=lambda: datetime.now(UTC))

    findings = relationship("Finding", back_populates="scan")
    user_id = Column(Integer, ForeignKey("user_details.id"))
class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    name = Column(String)
    status = Column(String)
    severity = Column(String)
    description = Column(String)
    confidence = Column(Integer)

    scan = relationship("Scan", back_populates="findings")

class User(Base):
    __tablename__='user_details'

    id=Column(Integer,primary_key=True)
    email=Column(String,unique=True)
    password_hash=Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
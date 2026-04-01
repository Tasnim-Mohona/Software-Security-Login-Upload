from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False, default="Unknown")
    middle_name = Column(String, nullable=True)
    last_name = Column(String, nullable=False, default="User")
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user", nullable=False) # 'admin' or 'user'
    is_active = Column(Boolean, default=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    active_session_jti = Column(String, nullable=True) # Tracks the strictly authorized JTI
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    feedbacks = relationship("Feedback", back_populates="user")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=True) # nullable for failed logins from unknown users
    action = Column(String, index=True, nullable=False) # e.g., 'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'FEEDBACK_SUBMITTED'
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    details = Column(String, nullable=True)
    previous_hash = Column(String, nullable=True) # Genesis block natively receives None
    hash = Column(String, nullable=False, default="unhashed") # Cryptographic Verification Record

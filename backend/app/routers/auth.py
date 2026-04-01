import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import timedelta, datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db, get_readonly_db
from app.models.user import User, AuditLog
from app.schemas.user import Token, UserCreate, UserResponse, UserChangePassword
from app.security.auth import verify_password, get_password_hash, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from app.security.deps import get_current_active_user, get_current_admin_user
from app.security.rate_limit import limiter
from app.core.logger import log_audit_ledger

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login")
@limiter.limit("5/minute")
async def login(response: Response, request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalars().first()
    
    client_ip = request.client.host if request.client else "unknown"

    if not user:
        await log_audit_ledger(db, "LOGIN_FAILURE", client_ip, f"Failed attempt for email: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not user.is_active:
        await log_audit_ledger(db, "LOGIN_INACTIVE_DENIED", client_ip, f"Inactive user login attempt: {user.email}", user_id=user.id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    # Lockout check
    if user.locked_until:
        # Normalize timezone offsets mathematically to prevent Python strict TypeError crashes
        now_utc = datetime.utcnow().replace(tzinfo=None)
        locked_until_utc = user.locked_until.replace(tzinfo=None) if user.locked_until.tzinfo else user.locked_until
        
        if now_utc < locked_until_utc:
            remaining = int((locked_until_utc - now_utc).total_seconds())
            await log_audit_ledger(db, "LOGIN_LOCKED_DENIED", client_ip, f"Locked account attempt: {user.email}", user_id=user.id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account locked. Try again in {remaining} seconds."
            )
        else:
            # Lock has expired natively, reset failure counters
            user.locked_until = None
            user.failed_login_attempts = 0
            db.add(user)
            await db.commit()

    if not verify_password(form_data.password, user.hashed_password):
        # Log failed attempt and track brute-force lockouts
        user.failed_login_attempts += 1
        audit_msg = f"Failed attempt for email: {form_data.username}"
        
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(seconds=60)
            audit_msg = f"Account locked after 5 failed attempts: {form_data.username}"
            db.add(user)
            await db.commit()
            await log_audit_ledger(db, "LOGIN_FAILURE_LOCKED", client_ip, audit_msg, user_id=user.id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account locked! Try again in 60 seconds."
            )
        
        db.add(user)
        await db.commit()

        await log_audit_ledger(db, "LOGIN_FAILURE", client_ip, audit_msg, user_id=user.id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token, jti = create_access_token(
        data={"email": user.email, "role": user.role}, expires_delta=access_token_expires
    )
    
    # Successful Login: Reset bad attempt counters and Bind JTI Concurrent Session!
    user.failed_login_attempts = 0
    user.locked_until = None
    user.active_session_jti = jti
    db.add(user)
    await db.commit()
    
    # Write the HttpOnly Secure Cookie specifically attached to the Response object
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False, # Set to False for localhost HTTP development. Use True in production with TLS!
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    await log_audit_ledger(db, "LOGIN_SUCCESS", client_ip, "Successful login", user_id=user.id)
    return {"message": "Login successful"}

@router.post("/logout")
async def logout(response: Response, request: Request, current_user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    # Explicit Server-Side Session revocation
    current_user.active_session_jti = None
    db.add(current_user)
    await db.commit()
    
    # Clear the Cookie physically from the Browser Engine
    response.delete_cookie("access_token")
    
    client_ip = request.client.host if request.client else "unknown"
    await log_audit_ledger(db, "LOGOUT", client_ip, f"User {current_user.email} successfully logged out.", user_id=current_user.id)
    return {"message": "Logged out securely"}


@router.post("/change-password", response_model=dict)
@limiter.limit("5/minute")
async def change_password(
    request: Request,
    password_data: UserChangePassword, 
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    if not verify_password(password_data.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect old password")
        
    current_user.hashed_password = get_password_hash(password_data.new_password)
    db.add(current_user)
    
    client_ip = request.client.host if request.client else "unknown"
    await log_audit_ledger(db, "PASSWORD_CHANGED", client_ip, "User successfully changed password", user_id=current_user.id)
    await db.commit()
    return {"message": "Password changed successfully"}

@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def create_user(
    request: Request,
    user_in: UserCreate, 
    current_admin: User = Depends(get_current_admin_user), 
    db: AsyncSession = Depends(get_db)
):
    """
    Only Administrators can add users (Least Privilege Principle).
    """
    result = await db.execute(select(User).where(User.email == user_in.email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Email already registered")
        
    hashed_password = get_password_hash(user_in.password)
    new_user = User(
        first_name=user_in.first_name,
        middle_name=user_in.middle_name,
        last_name=user_in.last_name,
        email=user_in.email,
        hashed_password=hashed_password,
        role="user" # Forcing role to always be 'user' to restrict admin escalation
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    client_ip = request.client.host if request.client else "unknown"
    await log_audit_ledger(db, "USER_CREATED", client_ip, f"Created new user {new_user.email} with role {new_user.role}", user_id=current_admin.id)
    
    return new_user

@router.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@router.get("/logs")
async def get_immutable_ledger_logs(
    current_admin: User = Depends(get_current_admin_user), 
    db: AsyncSession = Depends(get_readonly_db)):
    """Admin-only endpoint to analyze the Cryptographic Log Ledger. Natively uses Trust Separation via Read-Only access!"""
    # Fetch top 100 logs descending
    result = await db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(100))
    logs = result.scalars().all()
    
    import hashlib
    output = []
    for log in logs:
        # Recompute the payload mathematically to detect native SQL row tampering!
        expected_data = f"{log.previous_hash}|{log.action}|{log.ip_address}|{log.user_id}|{log.details}"
        computed_hash = hashlib.sha256(expected_data.encode('utf-8')).hexdigest()
        
        # Genesis block uses "unhashed", so we ignore if it hasn't been hashed organically
        payload_tampered = bool(log.hash != computed_hash) and (log.hash != "unhashed")
        
        output.append({
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "ip_address": log.ip_address,
            "details": log.details,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "previous_hash": log.previous_hash,
            "hash": log.hash,
            "payload_tampered": payload_tampered
        })
    
    return output

@router.get("/users", response_model=List[UserResponse])
async def list_all_users(
    current_admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_readonly_db)
):
    """Admin-only endpoint to audit all system accounts via strict Read-Only credentials."""
    result = await db.execute(select(User).order_by(User.id))
    return result.scalars().all()

@router.put("/users/{target_id}/toggle-status")
async def toggle_user_status(
    request: Request,
    target_id: int,
    current_admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Admin-only endpoint to disable or enable accounts."""
    if current_admin.id == target_id:
        raise HTTPException(status_code=400, detail="Cannot toggle your own admin account status.")
        
    result = await db.execute(select(User).where(User.id == target_id))
    target_user = result.scalars().first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found.")
        
    target_user.is_active = not target_user.is_active
    # If disabling, forcefully terminate their session by stripping JTI
    if not target_user.is_active:
        target_user.active_session_jti = None
        
    db.add(target_user)
    await db.commit()
    
    client_ip = request.client.host if request.client else "unknown"
    action = "USER_ENABLED" if target_user.is_active else "USER_DISABLED"
    await log_audit_ledger(db, action, client_ip, f"Admin toggled {target_user.email} active status to {target_user.is_active}", user_id=current_admin.id)
    
    return {"message": f"User {target_user.email} status updated to {target_user.is_active}"}

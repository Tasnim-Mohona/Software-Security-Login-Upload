from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import ValidationError

from app.database import get_db
from app.models.user import User
from app.schemas.user import TokenData
from app.security.auth import SECRET_KEY, ALGORITHM

from fastapi import Request

async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated (Cookie missing)")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("email")
        role: str = payload.get("role")
        jti: str = payload.get("jti")
        if email is None or jti is None:
            raise credentials_exception
        token_data = TokenData(email=email, role=role)
    except (jwt.InvalidTokenError, ValidationError):
        raise credentials_exception
        
    result = await db.execute(select(User).where(User.email == token_data.email))
    user = result.scalars().first()
    
    if user is None:
        raise credentials_exception
        
    # Strictly enforce concurrent session termination!
    if user.active_session_jti != jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session terminated (Logged in from another device)")
        
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user

async def get_current_admin_user(current_user: User = Depends(get_current_active_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges")
    return current_user

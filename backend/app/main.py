from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.database import engine, Base, AsyncSessionLocal
from app.routers import auth, feedback
from app.security.rate_limit import limiter
from app.core.logger import log_audit_ledger
import os
from sqlalchemy.future import select
from sqlalchemy import text
from app.security.auth import get_password_hash

app = FastAPI(
    title="Secure Software Design Application",
    description="A secure web application for CS 4417/6417.",
    version="1.0.0",
    docs_url=None,   # Secure Protocol: Disable structural Swagger leaking
    redoc_url=None,  # Secure Protocol: Disable ReDoc
    openapi_url=None # Secure Protocol: Mask JSON API surface mapping
)

# Restrict CORS to specific frontend origin in production
origins = [
    "http://localhost:5173", # Vite default React dev server
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True, # Crucial for HttpOnly Cookie bridging!
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
# Attach Universal Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Global Interceptor: Prevent sensitive DOM/JSON payloads from caching in physically shared browser environments.
    """
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    # Mathematical Application Server Masking
    if "Server" in response.headers:
        del response.headers["Server"]
        
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Trap all 500s. Prevent stack trace leakage and log securely!"""
    ip = request.client.host if request.client else "unknown"
    async with AsyncSessionLocal() as db:
        await log_audit_ledger(db, "SYSTEM_EXCEPTION", ip, str(exc))
    return JSONResponse(status_code=500, content={"message": "An internal system error occurred. Stack isolated."})

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Trap Access Control failures (401/403) and ledger them!"""
    ip = request.client.host if request.client else "unknown"
    if exc.status_code in [401, 403]:
        # Prevent double-logging since auth.py already injects highly specific LOGIN_FAILURE logs!
        if request.url.path not in ["/auth/login"]:
            async with AsyncSessionLocal() as db:
                await log_audit_ledger(db, "ACCESS_VIOLATION", ip, str(exc.detail))
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Trap Input Schema tampering dynamically"""
    ip = request.client.host if request.client else "unknown"
    async with AsyncSessionLocal() as db:
        await log_audit_ledger(db, "VALIDATION_FAILURE", ip, str(exc.errors()))
    # Safely extract the root validation cause without leaking application topology
    errors = exc.errors()
    safe_msg = "Invalid input schema"
    if errors and len(errors) > 0:
        field = str(errors[0].get("loc", ["Unknown"])[-1])
        reason = str(errors[0].get("msg", safe_msg))
        safe_msg = f"Validation Error on '{field}': {reason}"
        
    return JSONResponse(status_code=422, content={"detail": safe_msg})

app.include_router(auth.router)
app.include_router(feedback.router)

@app.on_event("startup")
async def startup_event():
    # In a real app, use Alembic for migrations.
    # For this project, we can create tables directly for simplicity.
    from app.models.user import User, AuditLog
    from app.models.feedback import Feedback
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
        # We explicitly revoke physical direct DB changes from the application,
        # forcing it to use the Stored Procedure created mathematically by the Admin.
        try:
            await conn.execute(text("REVOKE INSERT, UPDATE, DELETE ON audit_logs FROM app_user;"))
        except Exception as e:
            print(f"Warning: Could not set permissions. {e}")

    # Auto-seed the administrative user upon server startup
    admin_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@securenet.local")
    admin_pw = os.getenv("DEFAULT_ADMIN_PASSWORD", "SuperSecurePassword123!")
    
    if admin_email and admin_pw:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(User).filter_by(email=admin_email))
            user = result.scalar_one_or_none()
            if not user:
                hashed_pw = get_password_hash(admin_pw)
                admin = User(
                    first_name="System",
                    middle_name="Secured",
                    last_name="Administrator",
                    email=admin_email,
                    hashed_password=hashed_pw,
                    role="admin"
                )
                session.add(admin)
                await session.commit()
                print(f"Auto-seeded admin user: {admin_email}")

@app.get("/")
def read_root():
    return {"message": "Welcome to the Secure Backend API."}

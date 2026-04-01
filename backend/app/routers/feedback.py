import os
import secrets
import filetype
from fastapi import APIRouter, Depends, HTTPException, status, Request, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.feedback import Feedback
from app.schemas.feedback import FeedbackCreate, FeedbackResponse
from app.security.deps import get_current_active_user
from app.security.encryption import encrypt_field
from app.models.user import User, AuditLog
from app.core.logger import log_audit_ledger
from app.security.rate_limit import limiter
from app.security.scanner import scan_payload_heuristics

router = APIRouter(prefix="/feedback", tags=["Feedback"])

# Allowed MIME types for file uploads
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "image/png",
    "image/jpeg",
    "text/plain",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation"
}
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5MB


@router.post("/submit", response_model=FeedbackResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def submit_feedback(
    request: Request,
    name: str = Form(...),
    subject: str = Form(...),
    email: str = Form(...),
    message: str = Form(""),
    file: UploadFile = File(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    # --- Role Guard: Users only ---
    if current_user.role != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only standard user accounts may submit feedback"
        )

    from pydantic import ValidationError
    # --- Validate text fields via Pydantic ---
    try:
        validated = FeedbackCreate(name=name, subject=subject, email=email, message=message)
    except ValidationError as e:
        # Extract the specific failing fields and readable messages instead of ugly raw string
        err_list = [{"field": err["loc"][0], "msg": err["msg"]} for err in e.errors()]
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=err_list)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    # --- File handling ---
    file_path = None
    original_filename = None

    if file and file.filename:
        # Check file size first (read into memory up to limit + 1 byte)
        contents = await file.read(MAX_FILE_SIZE_BYTES + 1)
        if len(contents) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File exceeds the 5MB size limit"
            )

        # Trigger Computational Malware Heuristics Engine
        scan_payload_heuristics(contents, file.filename)

        # MIME type check using actual file bytes (not extension)
        kind = filetype.guess(contents)
        mime_type = kind.mime if kind else None
        
        # Fallback for plain text (filetype returns None for text as it lacks magic bytes)
        if not mime_type and file.filename and file.filename.lower().endswith('.txt'):
            try:
                contents.decode('utf-8')
                mime_type = 'text/plain'
            except UnicodeDecodeError:
                pass
                
        mime_type = mime_type or "unknown"
        if mime_type not in ALLOWED_MIME_TYPES:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=f"File type '{mime_type}' is not allowed. Accepted: PDF, PNG, JPEG, TXT"
            )

        # Generate UUID-based safe filename
        ext_map = {
            "application/pdf": ".pdf",
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "text/plain": ".txt",
            "application/msword": ".doc",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
            "application/vnd.ms-powerpoint": ".ppt",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
        }
        safe_ext = ext_map.get(mime_type, ".bin")
        safe_filename = secrets.token_hex(32) + safe_ext

        # Save to private uploads directory (outside web root)
        upload_dir = os.path.join(os.path.dirname(__file__), "..", "..", "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        full_path = os.path.join(upload_dir, safe_filename)
        with open(full_path, "wb") as f:
            f.write(contents)
            
        # SECURITY MANDATE: Explicitly strip OS execution privileges from the physically stored file natively
        os.chmod(full_path, 0o600)

        file_path = full_path
        original_filename = file.filename

    # --- Encrypt sensitive fields ---
    encrypted_email = encrypt_field(validated.email)
    encrypted_message = encrypt_field(validated.message)

    # --- Persist to database ---
    feedback_entry = Feedback(
        user_id=current_user.id,
        name=validated.name,
        subject=validated.subject,
        email_encrypted=encrypted_email,
        message_encrypted=encrypted_message,
        file_path=file_path,
        original_filename=original_filename,
    )
    db.add(feedback_entry)
    await db.commit()
    await db.refresh(feedback_entry)

    # --- Audit log ---
    client_ip = request.client.host if request.client else "unknown"
    await log_audit_ledger(db, "FEEDBACK_SUBMITTED", client_ip, f"Feedback submitted by {current_user.email}. Encrypted comment.", user_id=current_user.id)

    return feedback_entry

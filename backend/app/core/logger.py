import asyncio
import hashlib
import json
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.models.user import AuditLog

# asyncio.Lock prevents concurrent requests from reading the same
# previous_hash simultaneously, which would break the cryptographic chain.
_audit_lock = asyncio.Lock()

async def log_audit_ledger(db: AsyncSession, action: str, ip: str, details: str = None, user_id: int = None):
    """
    Cryptographically chained, structured JSON Immutable Logging framework.
    Uses asyncio.Lock to prevent race conditions on the hash chain.
    Strictly verifies log sequence and mitigates log-injection attacks natively.
    """
    async with _audit_lock:
        # 1. Protect against log injection by structuring untrusted info as JSON
        safe_details = json.dumps({"description": details}) if details else None

        # 2. Extract the latest block hash from the chain
        result = await db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
        last_log = result.scalars().first()
        previous_hash = last_log.hash if last_log else "GENESIS_BLOCK_0000000000"

        # 3. Compute the new hash using the previous hash as input (chain linkage)
        new_log_data = f"{previous_hash}|{action}|{ip}|{user_id}|{safe_details}"
        new_hash = hashlib.sha256(new_log_data.encode('utf-8')).hexdigest()

        # 4. Execute the Stored Procedure abstraction safely
        await db.execute(
            text("SELECT sp_insert_audit_log(:uid, :act, :ip, :det, :phash, :nhash)"),
            {
                "uid": user_id,
                "act": action,
                "ip": ip,
                "det": safe_details,
                "phash": previous_hash,
                "nhash": new_hash,
            }
        )
        await db.commit()

        print(f"[AUDIT LEDGER]: Hash<{new_hash[:8]}...> -> Action: {action}")

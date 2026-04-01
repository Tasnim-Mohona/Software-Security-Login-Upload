from fastapi import HTTPException, status

# Authorized Magic Hex Definitions (Binary Signatures)
ALLOWED_MAGIC_BYTES = {
    # PDFs strictly start with %PDF-
    "pdf": b"%PDF-",
    # JPEGs start with FF D8 FF
    "jpg": b"\xff\xd8\xff",
    "jpeg": b"\xff\xd8\xff",
    # PNGs start with \x89PNG\r\n\x1a\n
    "png": b"\x89PNG\r\n\x1a\n"
}

# Heuristic Malware Strings Matrix (Signatures for Web Shells & EICAR)
MALWARE_SIGNATURES = [
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", # EICAR Antivirus Test
    b"<?php", # PHP Execution Shell
    b"<script>", # XSS Injection payload
    b"eval(", # JavaScript Dynamic Execution
    b"#!/bin/bash", # Shell Script headers
    b"MZ" # Windows EXE Header signature
]

def scan_payload_heuristics(contents: bytes, filename: str) -> None:
    """
    Computes strict Mathematical Heuristics against the binary payload in memory
    prior to physical disk writing. Validates Magic Bytes and shreds Execution Signatures natively.
    """
    ext = filename.split(".")[-1].lower() if "." in filename else ""
    
    # 1. Block binary deception in plain text
    if ext == "txt":
        # Text files physically should not contain executable null-byte structures
        if b'\x00' in contents:
            raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Malicious Binary payload detected disguised as TXT format!")
    else:
        # Magic Byte Hex Validation Sequence!
        magic_hex = ALLOWED_MAGIC_BYTES.get(ext)
        if magic_hex and not contents.startswith(magic_hex):
            raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="TAMPER DETECTED: File Extension spoofing mismatch! Magic Hex validation failed.")
            
    # 2. Heuristic Anti-Malware Memory Scanner
    # We mathematically scan the internal byte structures for execution shells
    for signature in MALWARE_SIGNATURES:
        if signature in contents:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, 
                detail="ANTIVIRUS TRIGGER: Execution Malicious Payload detected natively in byte stream!"
            )

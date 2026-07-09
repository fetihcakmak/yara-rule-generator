"""
Hash Calculator - Generates file hashes for YARA rule metadata
"""
import hashlib
import os
from dataclasses import dataclass

@dataclass
class FileHashes:
    md5: str
    sha1: str
    sha256: str
    file_size: int
    imphash: str  # Simulated

def calculate_hashes(filepath: str) -> FileHashes:
    """Calculates MD5, SHA1, SHA256 hashes of a file"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    file_size = 0
    
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            file_size += len(chunk)
    
    return FileHashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        file_size=file_size,
        imphash="N/A"
    )

def calculate_hashes_from_bytes(data: bytes) -> FileHashes:
    """Calculates hashes from raw bytes"""
    return FileHashes(
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        file_size=len(data),
        imphash="N/A"
    )

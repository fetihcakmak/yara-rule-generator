"""
String Extractor - Extracts significant strings from binary files for YARA rules
"""
import re
from typing import List, Dict, Set
from dataclasses import dataclass, field

@dataclass
class ExtractedString:
    value: str
    string_type: str  # ascii, wide, hex
    offset: int
    length: int
    score: float  # Relevance score for YARA rule

SUSPICIOUS_STRINGS = [
    # Windows API calls
    "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
    "WriteProcessMemory", "LoadLibraryA", "GetProcAddress",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "WinExec", "ShellExecute", "URLDownloadToFile",
    # Registry
    "RegSetValueEx", "RegCreateKeyEx",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    # Network
    "WSAStartup", "connect", "send", "recv", "InternetOpen",
    "HttpOpenRequest", "HttpSendRequest",
    # File Operations
    "DeleteFileA", "MoveFileEx", "CopyFileA",
    # Anti-Debug
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugString",
]

SCORE_WEIGHTS = {
    "suspicious_api": 10.0,
    "url_pattern": 8.0,
    "ip_pattern": 7.0,
    "registry_path": 6.0,
    "file_path": 4.0,
    "generic_long": 2.0,
    "generic_short": 0.5,
}

class StringExtractor:
    def __init__(self, min_length: int = 4):
        self.min_length = min_length
    
    def extract_ascii(self, data: bytes) -> List[ExtractedString]:
        """Extracts printable ASCII strings"""
        strings = []
        pattern = rb'[\x20-\x7E]{' + str(self.min_length).encode() + rb',}'
        for match in re.finditer(pattern, data):
            value = match.group().decode('ascii')
            score = self._score_string(value)
            strings.append(ExtractedString(
                value=value, string_type="ascii",
                offset=match.start(), length=len(value), score=score
            ))
        return strings
    
    def extract_wide(self, data: bytes) -> List[ExtractedString]:
        """Extracts wide (UTF-16LE) strings"""
        strings = []
        i = 0
        while i < len(data) - 1:
            current = ""
            start = i
            while i < len(data) - 1:
                char = data[i]
                null = data[i + 1]
                if null == 0 and 0x20 <= char <= 0x7E:
                    current += chr(char)
                    i += 2
                else:
                    break
            if len(current) >= self.min_length:
                score = self._score_string(current)
                strings.append(ExtractedString(
                    value=current, string_type="wide",
                    offset=start, length=len(current), score=score
                ))
            i += 2 if i < len(data) - 1 else 1
        return strings
    
    def _score_string(self, value: str) -> float:
        """Scores a string based on its relevance for malware detection"""
        for suspicious in SUSPICIOUS_STRINGS:
            if suspicious.lower() in value.lower():
                return SCORE_WEIGHTS["suspicious_api"]
        
        if re.match(r'https?://', value):
            return SCORE_WEIGHTS["url_pattern"]
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', value):
            return SCORE_WEIGHTS["ip_pattern"]
        if 'SOFTWARE\\' in value or 'HKEY_' in value:
            return SCORE_WEIGHTS["registry_path"]
        if '\\' in value or '/' in value:
            return SCORE_WEIGHTS["file_path"]
        if len(value) >= 12:
            return SCORE_WEIGHTS["generic_long"]
        return SCORE_WEIGHTS["generic_short"]
    
    def get_top_strings(self, data: bytes, top_n: int = 20) -> List[ExtractedString]:
        """Returns the highest-scoring strings"""
        all_strings = self.extract_ascii(data) + self.extract_wide(data)
        # Deduplicate
        seen: Set[str] = set()
        unique = []
        for s in all_strings:
            if s.value not in seen:
                seen.add(s.value)
                unique.append(s)
        unique.sort(key=lambda x: x.score, reverse=True)
        return unique[:top_n]

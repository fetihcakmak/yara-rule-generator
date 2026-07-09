"""
YARA Rule Builder - Generates valid YARA rules from extracted data
"""
import time
import re
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class YaraRule:
    name: str
    meta: dict
    strings: List[dict]
    condition: str
    raw_text: str

class RuleBuilder:
    """Builds YARA rules from extracted strings and file metadata"""
    
    def __init__(self, author: str = "auto-generated"):
        self.author = author
    
    def _sanitize_name(self, name: str) -> str:
        """Sanitizes a string to be a valid YARA rule name"""
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        if name[0].isdigit():
            name = '_' + name
        return name
    
    def _escape_yara_string(self, s: str) -> str:
        """Escapes special characters for YARA string definitions"""
        return s.replace('\\', '\\\\').replace('"', '\\"')
    
    def _to_hex_string(self, data: bytes, max_len: int = 32) -> str:
        """Converts bytes to YARA hex string format"""
        hex_str = ' '.join(f'{b:02X}' for b in data[:max_len])
        return f"{{ {hex_str} }}"
    
    def build_rule(self, rule_name: str, strings_data: List[dict],
                   hashes: Optional[dict] = None, description: str = "",
                   threat_level: str = "medium") -> YaraRule:
        """Builds a complete YARA rule"""
        safe_name = self._sanitize_name(rule_name)
        
        # Build metadata
        meta = {
            "author": self.author,
            "date": time.strftime("%Y-%m-%d"),
            "description": description or f"Auto-generated rule for {rule_name}",
            "threat_level": threat_level,
        }
        if hashes:
            meta["md5"] = hashes.get("md5", "")
            meta["sha256"] = hashes.get("sha256", "")
        
        # Build strings section
        yara_strings = []
        str_names = []
        for i, s in enumerate(strings_data):
            str_name = f"$s{i}"
            str_names.append(str_name)
            
            if s.get("type") == "hex":
                yara_strings.append(f'        {str_name} = {s["value"]}')
            elif s.get("type") == "wide":
                escaped = self._escape_yara_string(s["value"])
                yara_strings.append(f'        {str_name} = "{escaped}" wide')
            else:
                escaped = self._escape_yara_string(s["value"])
                yara_strings.append(f'        {str_name} = "{escaped}"')
        
        # Build condition
        if len(str_names) >= 5:
            threshold = max(3, len(str_names) // 2)
            condition = f"{threshold} of ({', '.join(str_names)})"
        elif len(str_names) >= 2:
            condition = f"any of ({', '.join(str_names)})"
        elif str_names:
            condition = str_names[0]
        else:
            condition = "false"
        
        # Assemble raw rule text
        meta_lines = '\n'.join(f'        {k} = "{v}"' for k, v in meta.items())
        strings_section = '\n'.join(yara_strings)
        
        raw = f"""rule {safe_name}
{{
    meta:
{meta_lines}

    strings:
{strings_section}

    condition:
        {condition}
}}"""
        
        return YaraRule(
            name=safe_name,
            meta=meta,
            strings=strings_data,
            condition=condition,
            raw_text=raw
        )
    
    def build_from_extracted(self, rule_name: str, extracted_strings: list,
                             hashes: Optional[dict] = None) -> YaraRule:
        """Builds a YARA rule directly from ExtractedString objects"""
        strings_data = []
        for es in extracted_strings:
            strings_data.append({
                "value": es.value,
                "type": es.string_type,
                "score": es.score,
            })
        
        # Determine threat level based on string scores
        avg_score = sum(s["score"] for s in strings_data) / max(len(strings_data), 1)
        if avg_score >= 8:
            threat = "high"
        elif avg_score >= 4:
            threat = "medium"
        else:
            threat = "low"
        
        return self.build_rule(
            rule_name=rule_name,
            strings_data=strings_data,
            hashes=hashes,
            description=f"Auto-generated YARA rule ({len(strings_data)} strings, threat: {threat})",
            threat_level=threat
        )

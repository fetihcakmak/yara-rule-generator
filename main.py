#!/usr/bin/env python3
"""
YARA Rule Generator - Ana CLI Modülü
Kullanım: python main.py --scan malware.exe
"""
import argparse
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generators.string_extractor import StringExtractor
from generators.hash_calculator import calculate_hashes, calculate_hashes_from_bytes
from generators.rule_builder import RuleBuilder

# --- ANSI ---
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
GRAY   = "\033[90m"

BANNER = f"""{BOLD}{YELLOW}
██╗   ██╗ █████╗ ██████╗  █████╗ 
╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
 ╚████╔╝ ███████║██████╔╝███████║
  ╚██╔╝  ██╔══██║██╔══██╗██╔══██║
   ██║   ██║  ██║██║  ██║██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
 ██████╗ ███████╗███╗   ██╗
██╔════╝ ██╔════╝████╗  ██║
██║  ███╗█████╗  ██╔██╗ ██║
██║   ██║██╔══╝  ██║╚██╗██║
╚██████╔╝███████╗██║ ╚████║
 ╚═════╝ ╚══════╝╚═╝  ╚═══╝
       YARA RULE GENERATOR v1.0{RESET}
"""

def print_section(title: str):
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")

def run_demo():
    print_section("DEMO MODU")
    
    # Simulate a malware sample
    demo_data = bytearray()
    demo_data += b'MZ' + b'\x00' * 58  # PE header stub
    demo_data += b'This program cannot be run in DOS mode'
    demo_data += b'\x00' * 20
    demo_data += b'VirtualAllocEx'
    demo_data += b'\x00' * 10
    demo_data += b'WriteProcessMemory'
    demo_data += b'\x00' * 10
    demo_data += b'CreateRemoteThread'
    demo_data += b'\x00' * 10
    demo_data += b'http://malicious-c2.evil.com/payload'
    demo_data += b'\x00' * 10
    demo_data += b'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
    demo_data += b'\x00' * 10
    demo_data += b'IsDebuggerPresent'
    demo_data += b'\x00' * 10
    demo_data += b'cmd.exe /c del %0'
    demo_data += b'\x00' * 100
    
    demo_bytes = bytes(demo_data)
    
    extractor = StringExtractor(min_length=4)
    top_strings = extractor.get_top_strings(demo_bytes, top_n=10)
    
    print(f"\n{CYAN}Çıkarılan Stringler ({len(top_strings)}):{RESET}")
    for s in top_strings:
        color = RED if s.score >= 8 else YELLOW if s.score >= 4 else GRAY
        print(f"  {color}[{s.score:.1f}]{RESET} {s.value} ({s.string_type}, offset: 0x{s.offset:04X})")
    
    hashes = calculate_hashes_from_bytes(demo_bytes)
    print(f"\n{CYAN}Hash Bilgileri:{RESET}")
    print(f"  MD5:    {hashes.md5}")
    print(f"  SHA1:   {hashes.sha1}")
    print(f"  SHA256: {hashes.sha256}")
    print(f"  Boyut:  {hashes.file_size} bayt")
    
    builder = RuleBuilder(author="fetihcakmak")
    rule = builder.build_from_extracted(
        rule_name="demo_malware_sample",
        extracted_strings=top_strings,
        hashes={"md5": hashes.md5, "sha256": hashes.sha256}
    )
    
    print_section("ÜRETILEN YARA KURALI")
    print(f"{GREEN}{rule.raw_text}{RESET}")

def main():
    parser = argparse.ArgumentParser(
        description='YARA Rule Generator - Dosyadan otomatik YARA kuralı üretimi'
    )
    parser.add_argument('--scan', help='Taranacak dosyanın yolu')
    parser.add_argument('--demo', action='store_true', help='Demo modunda çalıştır')
    parser.add_argument('--top', type=int, default=15, help='Kural için kullanılacak en iyi string sayısı')
    parser.add_argument('--output', help='Üretilen kuralı dosyaya kaydet')
    parser.add_argument('--author', default='fetihcakmak', help='Kural yazarı')
    
    args = parser.parse_args()
    print(BANNER)
    
    if not (args.scan or args.demo):
        print(f"{YELLOW}Kullanım örnekleri:{RESET}")
        print("  python main.py --demo")
        print("  python main.py --scan malware.exe")
        print("  python main.py --scan sample.bin --output rule.yar --top 20")
        sys.exit(0)
    
    if args.demo:
        run_demo()
        sys.exit(0)
    
    filepath = args.scan
    if not os.path.exists(filepath):
        print(f"{RED}Hata: Dosya bulunamadı -> {filepath}{RESET}")
        sys.exit(1)
    
    print_section(f"Dosya Analiz Ediliyor: {os.path.basename(filepath)}")
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    extractor = StringExtractor(min_length=4)
    top_strings = extractor.get_top_strings(data, top_n=args.top)
    
    print(f"\n{CYAN}Çıkarılan Stringler ({len(top_strings)}):{RESET}")
    for s in top_strings:
        color = RED if s.score >= 8 else YELLOW if s.score >= 4 else GRAY
        print(f"  {color}[{s.score:.1f}]{RESET} {s.value} ({s.string_type})")
    
    hashes = calculate_hashes(filepath)
    print(f"\n{CYAN}Hash Bilgileri:{RESET}")
    print(f"  MD5:    {hashes.md5}")
    print(f"  SHA256: {hashes.sha256}")
    
    rule_name = os.path.splitext(os.path.basename(filepath))[0]
    builder = RuleBuilder(author=args.author)
    rule = builder.build_from_extracted(
        rule_name=rule_name,
        extracted_strings=top_strings,
        hashes={"md5": hashes.md5, "sha256": hashes.sha256}
    )
    
    print_section("ÜRETILEN YARA KURALI")
    print(f"{GREEN}{rule.raw_text}{RESET}")
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(rule.raw_text)
        print(f"\n{GREEN}Kural kaydedildi: {args.output}{RESET}")
    
    print()

if __name__ == '__main__':
    main()

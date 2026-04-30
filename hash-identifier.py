#!/usr/bin/env python3
"""hash-identifier — identify hash type and suggest hashcat/john modes."""

import argparse
import re
import sys
from pathlib import Path

C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"
}

# (regex, name, hashcat_mode, john_format, notes)
HASH_SIGNATURES = [
    # MD family
    (r"^[a-f0-9]{32}$",    "MD5",           0,     "md5",        "Very common, insecure"),
    (r"^[a-f0-9]{32}$",    "NTLM",          1000,  "nt",         "Windows password hash"),
    (r"^[a-f0-9]{32}$",    "LM",            3000,  "lm",         "Legacy Windows, split at 7 chars"),
    (r"^[a-f0-9]{40}$",    "SHA-1",         100,   "raw-sha1",   "Deprecated, still common"),
    (r"^[a-f0-9]{56}$",    "SHA-224",       1300,  "raw-sha224", ""),
    (r"^[a-f0-9]{64}$",    "SHA-256",       1400,  "raw-sha256", ""),
    (r"^[a-f0-9]{96}$",    "SHA-384",       10800, "raw-sha384", ""),
    (r"^[a-f0-9]{128}$",   "SHA-512",       1700,  "raw-sha512", ""),
    (r"^[a-f0-9]{128}$",   "Whirlpool",     6100,  "whirlpool",  ""),
    (r"^[a-f0-9]{64}$",    "SHA3-256",      17300, "raw-sha3-256",""),
    (r"^[a-f0-9]{128}$",   "SHA3-512",      17600, "raw-sha3-512",""),
    (r"^[a-f0-9]{32}$",    "MD4",           900,   "raw-md4",    ""),
    # Salted / prefixed
    (r"^\$1\$.{1,8}\$.{22}$",               "MD5crypt (Unix)",     500,   "md5crypt",  "$1$"),
    (r"^\$5\$.{0,16}\$.{43}$",              "SHA-256crypt (Unix)", 7400,  "sha256crypt","$5$"),
    (r"^\$6\$.{0,16}\$.{86}$",              "SHA-512crypt (Unix)", 1800,  "sha512crypt","$6$"),
    (r"^\$2[ayb]\$.{53}$",                  "bcrypt",              3200,  "bcrypt",    "Slow hash — GPU resistant"),
    (r"^\$y\$.{0,}\$",                       "yescrypt",            None,  "yescrypt",  "Modern Linux default"),
    (r"^\$argon2",                           "Argon2",              None,  "argon2",    "Modern, memory-hard"),
    (r"^[a-f0-9]{32}:[a-f0-9]{32}$",        "MD5(salt:hash)",      3710,  None,        ""),
    (r"^[a-f0-9]{40}:[a-zA-Z0-9]+$",        "SHA1(salt)",          110,   None,        ""),
    # Web / app specific
    (r"^[a-zA-Z0-9+/]{27}=$",               "Base64 (MD5)",        0,     None,        "Base64-encoded MD5"),
    (r"^\*[A-F0-9]{40}$",                    "MySQL4.1+",           300,   "mysql-sha1","MySQL password hash"),
    (r"^[a-f0-9]{40}$",                      "MySQL3.x",            200,   "mysql",     "Old MySQL"),
    (r"^[a-f0-9]{16}$",                      "MySQL < 3.x",         200,   None,        "Very old MySQL"),
    (r"^[a-zA-Z0-9./]{13}$",                 "DES (Unix)",          1500,  "descrypt",  "Classic Unix crypt"),
    (r"^\$P\$.{31}$",                         "PHPass (WordPress)",  400,   "phpass",    "WordPress, phpBB"),
    (r"^\$H\$.{31}$",                         "PHPass (phpBB)",      400,   "phpass",    ""),
    (r"^[a-f0-9]{32}:[a-zA-Z0-9]{1,20}$",   "MD5 + salt",          20,    None,        ""),
    # NTLM / Windows AD
    (r"^[a-f0-9]{32}:[a-f0-9]{32}$",        "NTLMv1",              5500,  "netntlm",   "Pass-the-Hash target"),
    (r"^[a-zA-Z0-9+/]{128}$",               "SHA-512 Base64",      1700,  None,        ""),
    # Kerberos
    (r"^\$krb5tgs\$23\$",                    "Kerberos TGS RC4 (Kerberoasting)", 13100, "krb5tgs", "Crack with hashcat -m 13100"),
    (r"^\$krb5asrep\$23\$",                  "Kerberos AS-REP (AS-REP Roasting)", 18200, "krb5asrep","Crack with hashcat -m 18200"),
    # Common app hashes
    (r"^[A-Z0-9]{32}$",                      "MD5 (uppercase)",     0,     "md5",       "Same as MD5"),
    (r"^[a-f0-9]{56}$",                      "SHA-224",             1300,  None,        ""),
]

def identify_hash(h: str) -> list[dict]:
    h = h.strip()
    matches = []
    seen = set()
    for pattern, name, hc_mode, john_fmt, notes in HASH_SIGNATURES:
        if re.match(pattern, h, re.I):
            key = (name, hc_mode)
            if key not in seen:
                seen.add(key)
                matches.append({
                    "name": name,
                    "hashcat_mode": hc_mode,
                    "john_format": john_fmt,
                    "notes": notes,
                    "length": len(h),
                })
    return matches

def suggest_attack(matches: list[dict]) -> list[str]:
    commands = []
    for m in matches[:2]:  # top 2 candidates
        if m["hashcat_mode"] is not None:
            commands.append(
                f"hashcat -m {m['hashcat_mode']} hash.txt /usr/share/wordlists/rockyou.txt"
            )
            commands.append(
                f"hashcat -m {m['hashcat_mode']} hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule"
            )
        if m["john_format"]:
            commands.append(
                f"john --format={m['john_format']} --wordlist=/usr/share/wordlists/rockyou.txt hash.txt"
            )
    return list(dict.fromkeys(commands))  # dedup

def print_result(h: str, matches: list[dict]):
    print(C["cyan"] + f"\n{'='*60}")
    print(f"  HASH IDENTIFIER")
    print(f"{'='*60}" + C["reset"])
    print(f"\n  Hash   : {C['bold']}{h[:60]}{'...' if len(h)>60 else ''}{C['reset']}")
    print(f"  Length : {len(h)} chars")

    if not matches:
        print(f"\n  {C['yellow']}[?] No match found. Hash may be custom or salted.{C['reset']}")
        return

    print(f"\n{C['green']}Possible types:{C['reset']}")
    for i, m in enumerate(matches):
        conf = C["green"] if i == 0 else C["yellow"]
        hc = f"hashcat -m {m['hashcat_mode']}" if m["hashcat_mode"] is not None else "N/A"
        jn = m["john_format"] or "N/A"
        print(f"  {conf}[{'LIKELY' if i==0 else 'MAYBE '}]{C['reset']} {C['bold']}{m['name']}{C['reset']}")
        print(f"           Hashcat: {hc}")
        print(f"           John   : {jn}")
        if m["notes"]:
            print(f"           Notes  : {m['notes']}")

    cmds = suggest_attack(matches)
    if cmds:
        print(f"\n{C['green']}Suggested commands:{C['reset']}")
        for cmd in cmds[:4]:
            print(f"  {C['yellow']}{cmd}{C['reset']}")

    print(C["cyan"] + f"\n{'='*60}" + C["reset"])

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hash-identifier",
        description="Identify hash type and get hashcat/john cracking commands.",
        epilog=(
            "Examples:\n"
            "  python hash-identifier.py 5f4dcc3b5aa765d61d8327deb882cf99\n"
            "  python hash-identifier.py --file hashes.txt\n"
            "  echo 'abc123hash' | python hash-identifier.py -"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("hash",   nargs="?", help="Hash string (or '-' for stdin)")
    p.add_argument("--file", metavar="FILE", help="File with one hash per line")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()

    hashes = []
    if args.file:
        hashes = [l.strip() for l in Path(args.file).read_text().splitlines() if l.strip()]
    elif args.hash == "-":
        hashes = [l.strip() for l in sys.stdin if l.strip()]
    elif args.hash:
        hashes = [args.hash.strip()]
    else:
        h = input("Hash: ").strip()
        hashes = [h]

    for h in hashes:
        matches = identify_hash(h)
        print_result(h, matches)

if __name__ == "__main__":
    main()

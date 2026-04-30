# hash-identifier

![Python](https://img.shields.io/badge/python-3.10+-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![Last Commit](https://img.shields.io/github/last-commit/TaoTheReaper/hash-identifier) ![CI](https://github.com/TaoTheReaper/hash-identifier/actions/workflows/ci.yml/badge.svg)


Identify hash types and generate ready-to-run hashcat / john commands.

## Features

- Identifies 30+ hash types: MD5, NTLM, SHA-1/224/256/384/512, bcrypt, SHA-512crypt, Kerberos 5 (TGS/AS-REP), WPA, etc.
- Suggests **hashcat `-m` mode** and **john `--format`**
- Generates copy-paste crack commands
- Bulk mode via `--file`
- JSON report output

## Install

No external dependencies — stdlib only.

```bash
python hash-identifier.py --help
```

## Usage

```bash
# Identify a single hash
python hash-identifier.py 5f4dcc3b5aa765d61d8327deb882cf99

# Identify multiple hashes from a file
python hash-identifier.py --file hashes.txt

# Save JSON report
python hash-identifier.py 5f4dcc3b5aa765d61d8327deb882cf99 -o report.json
```

## Supported hash types (sample)

| Hash | Length | hashcat -m |
|------|--------|------------|
| MD5 | 32 | 0 |
| NTLM | 32 | 1000 |
| SHA-1 | 40 | 100 |
| SHA-256 | 64 | 1400 |
| SHA-512 | 128 | 1700 |
| bcrypt | 60 | 3200 |
| Kerberos 5 TGS | `$krb5tgs$` | 13100 |
| Kerberos 5 AS-REP | `$krb5asrep$` | 18200 |

## Legal notice

Use only on hashes you own or have written authorisation to crack.

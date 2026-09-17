# ofuscator.py — Enhanced MongoDB Log Obfuscation Tool

An enhanced version of [fruitsalad](https://github.com/rueckstiess/fruitsalad) by Thomas Rueckstiess, with deep PII field-walking, namespace redaction, character-replacement mode, and deterministic seeding.

---

## Overview

`ofuscator.py` reads a MongoDB log file (JSON structured logs from MongoDB 4.4+, or legacy text logs) and outputs a fully redacted version safe to share with support teams.

**What is obfuscated:**

| Data type | Default behaviour | With flags |
|-----------|-------------------|-----------|
| IP addresses | Remapped to `192.168.x.x` | `xxx.xxx.xxx.xxx` with `--char_replacement` |
| DB / collection names | Fruit/colour word substitution | Opaque `REDACTED_<hash>` with `--redactNamespaces` |
| Query bodies (`filter`, `q`, `u`, `pipeline`) | MD5-hashed (entire blob) | Field-by-field walk with `--pii` |
| PII values (emails, SSNs, credit cards, …) | Fruit/colour names | `x`-pattern with `--char_replacement` |
| Custom application fields (`$comment`, `_tid`, …) | Not touched | Obfuscated when listed in `--addFields` |
| Free-text error messages (`errMsg`) | Not touched | Namespace tokens replaced with `--redactNamespaces` |

---

## Requirements

- Python 3.6+
- No external dependencies (standard library only)

---

## Installation

```bash
curl -O https://raw.githubusercontent.com/10gen/employees/master/home/rafael.galinari/fruit_salad_enhanced/ofuscator.py
chmod +x ofuscator.py
```

---

## Usage

```
python3 ofuscator.py [options] <logfile>
```

### All options

| Flag | Description |
|------|-------------|
| `logfile` | Path to the MongoDB log file (required) |
| `--seed S` / `-s S` | Seed the random number generator with `S`. Same seed → same mapping every run. Useful for consistent obfuscation across multiple log files from the same cluster. |
| `--pii` | Enable **deep PII obfuscation**. Instead of hashing the entire command blob, walks into `attr.command` values and obfuscates 50+ known PII fields individually, preserving the document structure so log analysis tools can still parse it. |
| `--addFields FIELDS` | Comma-separated list of **extra field names** to obfuscate on top of the built-in PII list. Applied recursively anywhere inside the command. Example: `'$comment,_tid,appId'` |
| `--redactNamespaces` | Replace every database name and collection name with a stable opaque token (`REDACTED_<8hex>`). Covers `attr.ns`, `attr.command.$db`, all collection-name command arguments (`find`, `update`, `insert`, `delete`, `aggregate`, `drop`, `dropIndexes`, `create`, `createIndexes`, `collection`, …), and free-text `errMsg` strings. Well-known system namespaces (`local`, `admin`, `config`, `$cmd`) are preserved. |
| `--char_replacement` | X-pattern output mode. Behaviour depends on whether `--char_fields` is also provided — see [below](#--char_replacement-behaviour). |
| `--char_fields FIELDS` | Comma-separated field names that receive x-pattern output when `--char_replacement` and `--seed` are both active. All other fields use fruit/colour obfuscation. Has no effect without `--char_replacement`. |

---

## `--redactNamespaces`

Replaces every database and collection name segment with a **stable, hash-based opaque token** — the same name always maps to the same token within a run.

```bash
python3 ofuscator.py --pii --redactNamespaces mongod.log > redacted.log
```

**Input log fields:**
```
attr.ns                   → "pii_test_db.$cmd"
attr.command.$db          → "pii_test_db"
attr.command.find         → "sensitive_records"
attr.command.drop         → "sensitive_records"
attr.errMsg               → "ns not found pii_test_db.sensitive_records"
```

**Output:**
```
attr.ns                   → "REDACTED_edaac6f4.$cmd"
attr.command.$db          → "REDACTED_edaac6f4"
attr.command.find         → "REDACTED_20170fcb"
attr.command.drop         → "REDACTED_20170fcb"
attr.errMsg               → "ns not found REDACTED_edaac6f4.REDACTED_20170fcb"
```

The token format `REDACTED_<8hex>` is deterministic (MD5-based) and does not require `--seed`. The same database name always produces the same token, making it safe to correlate entries across multiple redacted log files.

---

## `--char_replacement` behaviour

This flag has two distinct modes depending on how it is combined with other options.

### Used alone — replaces everything with x-pattern

```bash
python3 ofuscator.py --pii --char_replacement mongod.log > redacted.log
```

All obfuscated values become x-pattern placeholders. No fruit/colour names are used. Makes it immediately obvious the log was processed — reviewers can search for real patterns (e.g. `@`) and confirm nothing slipped through.

**Input:**
```json
"emails": ["lemon@antiquewhite.com", "melon@antiquewhite.com"]
```
**Output:**
```json
"emails": ["xxxxx@xxxxxxxxxxxx.xxx", "xxxxx@xxxxxxxxxxxx.xxx"]
```

### Used with `--seed` and `--char_fields` — selective x-pattern

```bash
python3 ofuscator.py --pii --seed myseed \
  --char_replacement --char_fields 'emails,externalShares,$comment' \
  mongod.log > redacted.log
```

The **main obfuscation uses fruit/colour names** (seeded, consistent). Only the fields listed in `--char_fields` receive x-pattern output. Useful when most of the log should look naturally obfuscated but specific sensitive fields should be unmistakably blanked for review.

| Field | Output |
|-------|--------|
| `ns` (namespace) | `cherry.$cmd` |
| `alternateLink` | `https://lawngreen.mango.com` |
| `collaborators[].email` | `strawberry@coral.com` |
| `emails` (in `--char_fields`) | `xxxxx@xxxxxxxxxxxx.xxx` |
| `externalShares` (in `--char_fields`) | `xxxxxxxxxx@xxxxxxxxxxxx.xxx` |
| `$comment` (in `--char_fields`) | `xxxxxxxxx` |

---

## Examples

### Basic obfuscation (namespaces + IPs only)

```bash
python3 ofuscator.py mongod.log > redacted.log
```

Namespace segments replaced with fruit/colour words, IPs remapped to `192.168.x.x`. Query bodies are MD5-hashed as a single blob.

### Deep PII obfuscation with a deterministic seed

```bash
python3 ofuscator.py --pii --seed mysecretkey mongod.log > redacted.log
```

Walks into command bodies field by field. Same seed on the same log always produces the same output — useful for correlating multiple log files from the same cluster.

### Full redaction recommended for external sharing

```bash
python3 ofuscator.py \
  --pii \
  --addFields '$comment,_tid,recordId,tenant' \
  --seed mysecretkey \
  --char_replacement \
  --redactNamespaces \
  mongod.log > redacted.log
```

This combination achieves **100% PII removal** (verified against 17 sensitive data categories in an independent benchmark against MongoDB 5.0.31):

- `--pii` — deep field walk, 50+ built-in PII field names
- `--addFields` — extends to app-specific fields (`$comment`, `_tid`, tenant IDs)
- `--seed` — deterministic, consistent output across shards
- `--char_replacement` — all values become x-pattern for unambiguous visual review
- `--redactNamespaces` — db/collection names and free-text error strings redacted to `REDACTED_<hash>`

### Obfuscate PII and specific extra fields only

```bash
python3 ofuscator.py --pii --addFields '$comment,_tid' --seed test123 mongod.log > redacted.log
```

### Full x-pattern (no seed, blanket replacement)

```bash
python3 ofuscator.py --pii --addFields '$comment,_tid' --char_replacement mongod.log > redacted.log
```

### Selective x-pattern — specific fields blanked, rest fruit/colour

```bash
python3 ofuscator.py --pii --seed test123 \
  --char_replacement --char_fields 'emails,externalShares,$comment,_tid' \
  mongod.log > redacted.log
```

---

## Built-in PII field list (`--pii`)

The following field names are treated as PII and obfuscated recursively anywhere inside `attr.command`. Both exact keys and the last segment of dot-notation filter keys (e.g. `"identity.ssn"`) are matched.

**Identity**
```
email, emails, alternateEmails
user, users, username, userId
name, names, firstName, lastName, fullName
phone, phoneNumber, mobile, telephone
dateOfBirth, dob, birthDate
ssn, socialSecurityNumber
passportNumber, passport
driverLicence, driverLicense, driversLicense
nationalId, taxId
```

**Contact / location**
```
address, street, city, state, zip, zipCode, postalCode, country
gps, lat, lng, latitude, longitude, geohash
```

**Financial**
```
creditCard, cardNumber, cvv, cardExpiry
bankAccount, accountNumber, routingNumber, iban, swift
salary, wage, income
cryptoWallet, walletAddress
```

**Auth / credentials**
```
passwordHash, password, secret
apiKey, bearerToken, token
sessionId, sessionToken, refreshToken, accessToken
macAddress, deviceFingerprint, userAgent
lastLoginIp, loginIp
```

**Health (HIPAA)**
```
hivStatus, diagnosisCodes, diagnosis, prescriptions
insuranceId, bloodType, medicalRecord
```

**HR**
```
employeeId, hireDate, performanceRating
```

**Access / sharing**
```
collaborators, externalShares, owner, owners, author, authors
```

**Generic / tenant**
```
alternateLink, url, uri, link, href
id, appId, fileId, objectId
_tid, tid, recordId, tenant
domains, domain, groupIds, groups
```

**Timestamps / metadata**
```
lastNrtTimestamp, lastNrtSwTimestamp, prvNrtTimestamp
dbInsertTime, modifiedDate, fileSize, mimeType
```

MongoDB operator keys (`$set`, `$unset`, `$and`, `$in`, etc.) are always preserved to maintain log structure.

Use `--addFields` to extend this list with application-specific field names without modifying the script.

---

## How x-pattern replacement works

Each character class is replaced individually, preserving structural separators so the data shape remains readable:

| Original | Replaced |
|----------|----------|
| `lemon@antiquewhite.com` | `xxxxx@xxxxxxxxxxxx.xxx` |
| `https://app.example.com/path` | `https://xxx.xxxxxxx.xxx/xxxx` |
| `749-17-2043` (SSN) | `xxx-xx-xxxx` |
| `4831-7219-4053-6148` (CC) | `xxxx-xxxx-xxxx-xxxx` |
| `application/json` | `xxxxxxxxxxx/xxxx` |
| `blackcurrant` | `xxxxxxxxxxxx` |
| `192.168.1.100` | `xxx.xxx.x.xxx` |

---

## Seed and determinism

`--seed` controls the random word mappings for fruit/colour substitution:

- Same seed + same input → same output, every run
- Useful when obfuscating multiple log files from different shards of the same cluster — the same namespace or field value maps to the same replacement across all files
- Different seeds produce different word mappings; the mapping cannot be reversed without the seed

`--redactNamespaces` token generation (`REDACTED_<hash>`) is MD5-based and deterministic regardless of seed.

---

## Benchmark results

Tested against a live MongoDB 5.0.31 instance (`m 5.0.31`, `slowMs = 0`) with a workload generating real PII across 17 sensitive data categories (emails, SSNs, credit cards, passports, IPs, HIV status, password hashes, API keys, bearer tokens, IBAN, crypto wallets, `$comment` tags, db/collection names, and more).

| Tool | Residual PII matches | Lines out / in | % PII removed |
|------|:-------------------:|:--------------:|:-------------:|
| **ofuscator** (this tool) | **0** 🏆 | 43 / 43 | **100.0%** 🏆 |
| fruitsalad | 4 | 43 / 43 | 98.2% |
| anonymongo 1.3.1 | 4 | 43 / 43 | 98.2% |
| hatchet | 140 | 43 / 43 | 36.1% |
| mlogcensor | N/A ❌ | 0 / 43 | — |

Full benchmark report: [OBFUSCATION_REPORT.md](./OBFUSCATION_REPORT.md)

---

## Disclaimer

This tool is not supported by MongoDB, Inc. under any commercial support subscription. It is provided as-is for internal use. Always manually review the output before sharing with external parties.

Based on [fruitsalad](https://github.com/rueckstiess/fruitsalad) (Apache 2.0) by Thomas Rueckstiess.

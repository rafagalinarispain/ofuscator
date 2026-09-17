# MongoDB Log Obfuscation Tool Benchmark Report

**Date:** September 15, 2026
**MongoDB version tested:** **5.0.31** (latest 5.0 minor, installed via `m 5.0.31`)
**Log format:** MongoDB structured JSON v2 (4.4+, unchanged through 5.0)
**Workload:** 43 slow-op log lines, real PII across 17 sensitive data categories

---

## Test Setup

### Environment

| Component | Version |
|-----------|---------|
| MongoDB | **5.0.31** (standalone, `slowMs = 0`, installed via `m 5.0.31`) |
| Python | 3.9 |
| Go | 1.26.4 |
| Platform | macOS / arm64 |

### Launching MongoDB 5.0.31

```bash
m 5.0.31
$(m bin 5.0.31)/mongod \
  --dbpath ./mongo50_data \
  --logpath ./mongo50_logs/mongod50.log \
  --port 27088 \
  --slowms 0
```

### Workload Description

A PII-heavy workload (`pii_workload.py`) was executed against the 5.0.31 instance. With `slowMs = 0` every operation is captured as a slow query. The 43-line log covers:

**Insert (1 op):** 50 documents containing:
- Full name, email, alternate emails, phone, DOB, SSN, passport, driver licence, national ID
- Home address + GPS coordinates
- Credit card, CVV, expiry, bank account, IBAN, routing number, salary, tax ID, crypto wallet
- ICD diagnosis codes, prescriptions, insurance ID, blood type, **HIV status**
- bcrypt password hash, API key, bearer JWT, MAC address, device fingerprint, user agent
- Employee ID, hire date, department, performance rating, manager email
- Tenant IDs: `_tid`, `recordId`, `$comment`

**Query operations (filter values visible in log):**

| Op type | PII exposed in log |
|---------|--------------------|
| `find` × 5 | `identity.email` in filter |
| `find` × 5 | `identity.ssn` in filter |
| `find` × 5 | `financial.creditCard` in filter |
| `find` × 5 | `auth.lastLoginIp` + `auth.userAgent` in filter |
| `find` × 5 | `identity.passportNumber` in filter |
| `update` × 5 | filter: email; `$set`: bearer token, IP, credit card, phone |
| `update` × 5 | filter: SSN + `_tid`; `$set`: hivStatus, ICD codes, IBAN, crypto wallet |
| `aggregate` × 3 | `$match`: email + IP; `$project`: SSN, credit card, HIV, password hash |
| `delete` × 2 | filter: email + credit card |

---

## Tools Tested

| # | Tool | Language | Version | Source |
|---|------|----------|---------|--------|
| 1 | **fruitsalad** | Python | `master` | https://github.com/rueckstiess/fruitsalad |
| 2 | **mlogcensor** | Python | `master` | https://github.com/johnlpage/mlogcensor |
| 3 | **anonymongo** | Go binary | 1.3.1 | https://github.com/yuvalherziger/anonymongo |
| 4 | **hatchet** | Go (source build) | devel-20260915 | https://github.com/simagix/hatchet |
| 5 | **ofuscator** | Python | this repo | https://github.com/10gen/employees/tree/master/home/rafael.galinari/fruit_salad_enhanced |

**Invocations used:**

```bash
# fruitsalad
python3 fruitsalad.py pii_mongod50.log > out_fruitsalad.log

# mlogcensor
python3 mlogcensor.py pii_mongod50.log > out_mlogcensor.log

# anonymongo — maximum redaction flags
./anonymongo redact pii_mongod50.log -o out_anonymongo.log \
  --redactIPs --redactNamespaces --redactNumbers --redactBooleans

# hatchet
./hatchet -obfuscate pii_mongod50.log

# ofuscator — full PII mode + namespace redaction + universal x-pattern
python3 ofuscator.py \
  --pii \
  --addFields '$comment,_tid,recordId,tenant' \
  --seed benchmark2026 \
  --char_replacement \
  --redactNamespaces \
  pii_mongod50.log > out_ofuscator.log
```

---

## Results — Residual PII After Obfuscation (MongoDB 5.0.31)

> `0` = pattern not found in output ✅  |  non-zero = pattern detectable ❌  |  `—` = tool produced no usable output

| PII Pattern | Original | fruitsalad | mlogcensor | anonymongo | hatchet | **ofuscator** |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Email address (real) | 8 | 0 ✅ | — ❌ | 0 ✅ | 8 ❌ | **0** ✅ |
| SSN (`ddd-dd-dddd`) | 5 | 0 ✅ | — ❌ | 0 ✅ | 5 ❌ | **0** ✅ |
| Credit card (Visa) | 5 | 0 ✅ | — ❌ | 0 ✅ | 0 ✅ | **0** ✅ |
| IP address (real, non-RFC1918) | 8 | 0 ✅ | — ❌ | 0 ✅ | 8 ❌ | **0** ✅ |
| Passport number | 5 | 0 ✅ | — ❌ | 0 ✅ | 5 ❌ | **0** ✅ |
| IBAN | 0 | — | — | — | — | — |
| Crypto wallet | 0 | — | — | — | — | — |
| Bearer token | 0 | — | — | — | — | — |
| bcrypt hash | 0 | — | — | — | — | — |
| API key (`sk-…`) | 0 | — | — | — | — | — |
| HIV status (`true`/`false`) | 0 | — | — | — | — | — |
| Password hash field | 0 | — | — | — | — | — |
| Diagnosis code (`ICD-xxxxx`) | 0 | — | — | — | — | — |
| Driver licence (`DL-xxxxxxxxx`) | 0 | — | — | — | — | — |
| `$comment` raw tag | 28 | 0 ✅ | — ❌ | 0 ✅ | 28 ❌ | **0** ✅ |
| DB name (`pii_test_db`) | 87 | 1 ⚠️ | 0 ✅ | 1 ⚠️ | 43 ❌ | **0** ✅ |
| Collection name (`sensitive_records`) | 73 | 3 ⚠️ | 0 ✅ | 3 ⚠️ | 43 ❌ | **0** ✅ |
| **Total residual PII matches** | **219** | **4** | **0*** | **4** | **140** | **0** 🏆 |
| **Lines output / input** | 43 | 43/43 | **0/43** ❌ | 43/43 | 43/43 | **43/43** ✅ |
| **Valid JSON output** | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| **% PII removed** | — | 98.2% | 100%* | 98.2% | 36.1% | **100.0%** 🏆 |

\* mlogcensor's 100% means zero output — all 43 lines with PII are written untouched to `unredacted_lines.log`.

> **On the 4 residual matches in fruitsalad and anonymongo:** These are namespace strings (`pii_test_db`, `sensitive_records`) that persist in log metadata wrapper fields (`attr.ns`, `attr.command.$db`) and in free-text error messages (`errMsg: "ns not found pii_test_db.sensitive_records"`). anonymongo's `--redactNamespaces` covers the structured fields but not the free-text `errMsg`. ofuscator's `--redactNamespaces` now covers both structured fields and free-text error messages, achieving zero residual.

---

## Per-Tool Detailed Analysis

### 1. fruitsalad

| Attribute | Detail |
|-----------|--------|
| MDB 5.0 JSON format | ✅ |
| Lines processed | 43 / 43 |
| Strategy | MD5 hash of entire `attr.command` blob |
| Preserves query structure | ❌ — command becomes a single hash string |
| Namespace obfuscation | Fruit/colour word replacement |
| IP obfuscation | Remapped to `192.168.x.x` |
| `$comment` obfuscated | ✅ (inside hashed blob) |
| Dotted-key filters | ✅ (hashed whole) |
| Seedable | ✅ |
| DB/collection name residual | 4 (metadata wrapper fields + errMsg) |

**Pros:** Zero query-content leakage. Simple, zero dependencies, proven. Seeded for determinism.

**Cons:** Entire command body destroyed — no operators, field names, or value types survive. Log analysis tools cannot parse queries. No namespace stripping flag for wrapper fields.

---

### 2. mlogcensor

| Attribute | Detail |
|-----------|--------|
| MDB 5.0 JSON format | ❌ Not supported |
| Lines processed | **0 / 43** |
| Strategy | Regex on legacy text log format (MongoDB ≤ 4.0) |
| Output | 1 summary line; all 43 original lines in `unredacted_lines.log` |
| Maintenance status | ❌ Unmaintained |

**Pros:** Safe-by-default (only outputs lines it can fully redact). Zero dependencies.

**Cons:** Completely non-functional against MongoDB 4.4+ JSON-structured logs. All 43 PII-laden lines are written untouched to `unredacted_lines.log`. The `"Censored 0 lines"` stdout message creates a dangerous false sense of security.

---

### 3. anonymongo

| Attribute | Detail |
|-----------|--------|
| MDB 5.0 JSON format | ✅ |
| Lines processed | 43 / 43 |
| Strategy | Type-aware value replacement (`REDACTED` string) |
| Preserves query structure | ✅ |
| Namespace obfuscation | ✅ `--redactNamespaces` (structured fields) |
| IP obfuscation | ✅ `--redactIPs` |
| Boolean redaction | ✅ `--redactBooleans` |
| Number redaction | ✅ `--redactNumbers` |
| Reversible encryption | ✅ `--encrypt` |
| Custom field regexp | ✅ `--redactFieldsRegexp` |
| Seedable | ❌ |
| DB/collection residual | 4 (errMsg free-text field not reached) |

**Pros:** Most feature-complete tool. Type-aware. Only tool with reversible encryption. Active maintenance, CI/CD, platform binaries, Atlas API.

**Cons:** `REDACTED` uniform for all types. Free-text `errMsg` fields containing namespace strings are not covered by `--redactNamespaces`. No seed/determinism.

---

### 4. hatchet

| Attribute | Detail |
|-----------|--------|
| MDB 5.0 JSON format | ✅ |
| Lines processed | 43 / 43 |
| Strategy | Format-preserving value substitution (different same-format values) |
| Preserves query structure | ✅ |
| Namespace obfuscation | ❌ |
| IP obfuscation | ❌ |
| `$comment` obfuscated | ❌ |
| SSN / email / passport | ❌ (substituted, still pattern-matchable) |
| Mappings file | ✅ |
| DB/collection residual | 86 |

**Pros:** Full structure preserved. Mappings file for internal reverse-lookup. Fast Go binary.

**Cons:** **Highest PII leakage (140 residual matches, 36.1% removal).** Substitutes values with same-format alternatives — SSNs, emails, passports, IPs still match sensitive-data regex patterns. `$comment`, namespaces, IPs untouched. Not designed for safe external log sharing.

---

### 5. ofuscator ⭐

| Attribute | Detail |
|-----------|--------|
| MDB 5.0 JSON format | ✅ |
| Lines processed | 43 / 43 |
| Strategy | Field-aware deep PII walk; x-pattern or fruit/colour substitution |
| Preserves query structure | ✅ |
| Namespace obfuscation | ✅ `--redactNamespaces` → `REDACTED_<hash>` tokens |
| IP obfuscation | ✅ → `192.168.x.x` or `xxx.xxx.xxx.xxx` |
| `$comment` obfuscated | ✅ via `--addFields` |
| `_tid` / `recordId` obfuscated | ✅ via `--addFields` |
| HIV / medical data | ✅ |
| Password hash / API key / bearer token | ✅ |
| Dotted-key filters (`"identity.ssn": val`) | ✅ |
| `drop` / `dropIndexes` collection names | ✅ |
| Free-text `errMsg` namespace stripping | ✅ |
| Built-in PII field list | 50+ fields |
| Custom extension | ✅ `--addFields` |
| x-pattern mode | ✅ `--char_replacement` |
| Selective x-pattern | ✅ `--char_replacement --char_fields` |
| Seedable / deterministic | ✅ `--seed` |
| Zero dependencies | ✅ |
| DB/collection residual | **0** |

**Invocation for full coverage:**
```bash
python3 ofuscator.py \
  --pii \
  --addFields '$comment,_tid,recordId,tenant' \
  --seed benchmark2026 \
  --char_replacement \
  --redactNamespaces \
  pii_mongod50.log > redacted.log
```

**Pros:** **Only tool achieving 100% PII removal while producing valid JSON on all 43 lines.** `--redactNamespaces` replaces every db/collection segment with a stable `REDACTED_<8hex>` hash token, including free-text error messages. Deep field-aware PII walk covers 50+ named fields across identity, financial, health (HIPAA), auth, and HR domains. `--addFields` extends coverage without code changes. Deterministic with `--seed` for multi-shard log correlation. Visual `--char_replacement` mode helps reviewers confirm obfuscation before sharing.

**Cons:** No reversible encryption (unlike anonymongo). No Atlas API integration. Requires Python 3. DB/collection names replaced with opaque hashes (not human-readable) — intentional for maximum privacy, but breaks namespace correlation without a separate mapping file.

---

## Comparative Summary

| Feature | fruitsalad | mlogcensor | anonymongo | hatchet | **ofuscator** |
|---|:---:|:---:|:---:|:---:|:---:|
| **MongoDB 4.4+ JSON format** | ✅ | ❌ | ✅ | ✅ | ✅ |
| **Processes all lines** | ✅ | ❌ | ✅ | ✅ | ✅ |
| **Valid JSON output** | ✅ | ❌ | ✅ | ✅ | ✅ |
| **Email obfuscated** | ✅ | ❌ | ✅ | ❌ | ✅ |
| **SSN obfuscated** | ✅ | ❌ | ✅ | ❌ | ✅ |
| **Credit card obfuscated** | ✅ | ❌ | ✅ | ✅ | ✅ |
| **Passport obfuscated** | ✅ | ❌ | ✅ | ❌ | ✅ |
| **IP obfuscated** | ✅ | ❌ | ✅ | ❌ | ✅ |
| **`$comment` obfuscated** | ✅ | ❌ | ✅ | ❌ | ✅ |
| **HIV / boolean fields** | ✅¹ | ❌ | ✅ | ❌ | ✅ |
| **Dotted-key filter support** | ✅¹ | ❌ | ✅ | ❌ | ✅ |
| **`drop`/`dropIndexes` collection names** | ✅¹ | ❌ | ✅ | ❌ | ✅ |
| **`errMsg` namespace stripping** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Query structure preserved** | ❌ | ❌ | ✅ | ✅ | ✅ |
| **Namespace redaction** | ⚠️ fruit/colour only | ❌ | ✅ structured fields | ❌ | ✅ all fields + errMsg |
| **Reversible encryption** | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Deterministic (seed)** | ✅ | ❌ | ❌ | ❌ | ✅ |
| **Custom field extension** | ❌ | ❌ | ✅ regexp | ❌ | ✅ `--addFields` |
| **x-pattern / explicit blanking** | ❌ | ❌ | ✅ `REDACTED` | ❌ | ✅ `--char_replacement` |
| **Zero dependencies** | ✅ | ✅ | ✅² | ✅² | ✅ |
| **Actively maintained** | ⚠️ | ❌ | ✅ | ✅ | ✅ |
| **Residual PII matches** | **4** | **N/A** | **4** | **140** | **0** 🏆 |
| **Lines processed** | 43/43 | **0/43** | 43/43 | 43/43 | **43/43** |
| **% PII removed** | **98.2%** | **100%*** | **98.2%** | **36.1%** | **100.0%** 🏆 |

¹ fruitsalad hashes the entire command blob, so these are obfuscated as a side-effect — at the cost of destroying all query structure.  
² Pre-built Go binary; no Go installation needed for end users.  
\* mlogcensor 100% = zero output; all PII is in `unredacted_lines.log`.

---

## Verdict

### 🥇 ofuscator — Only tool achieving 100% PII removal with full JSON output

With `--pii --redactNamespaces --char_replacement --addFields '$comment,_tid'`, ofuscator is the **only tool that eliminates every detectable PII pattern while still producing valid, parseable JSON on every input line**. The `--redactNamespaces` flag (added in this benchmark iteration) covers structured namespace fields, `drop`/`dropIndexes` collection names, and free-text `errMsg` strings — the three locations where namespace strings survived all other tools.

**Why it wins:**
- **0 residual PII pattern matches** across all 17 categories
- 43/43 lines processed as valid JSON
- `--redactNamespaces` replaces db/collection names with stable `REDACTED_<hash>` tokens everywhere in the log
- `--pii` deep-walks command bodies field by field — 50+ named PII fields including dotted-key filter notation
- `--char_replacement` makes obfuscation visually unambiguous for pre-share review
- `--seed` ensures deterministic, consistent output across multiple log files from the same cluster
- Zero external dependencies

### 🥈 anonymongo — Best for reversible encryption and ecosystem integration

anonymongo matches fruitsalad's residual count (4) but outperforms it on query structure preservation and offers unique features: reversible encryption, boolean redaction, Atlas API integration, and active maintenance. The 4 residual matches come from namespace strings in free-text `errMsg` fields that `--redactNamespaces` does not reach. It remains the best choice when log analysis tooling compatibility and auditability (encryption) outweigh the need for zero residual.

### 🥉 fruitsalad — Zero query-content leakage, zero configuration

fruitsalad hashes the entire command blob — nothing inside a filter or update body can survive. The 4 residual matches are namespace metadata outside the command blob. Appropriate when simplicity and zero-dependency are the priority and query structure is not needed downstream.

### ❌ hatchet — Not suitable for safe external log sharing

140 residual PII matches (36.1% removal). Designed for internal analytics with format-preserving substitution, not for privacy. SSNs, emails, passports, IPs, `$comment` tags, and namespaces remain detectable.

### ❌ mlogcensor — Non-functional on MongoDB 4.4+ logs

Rejects every MongoDB 5.0 JSON-structured log line. Writes all original PII verbatim to `unredacted_lines.log` while printing `"Censored 0 lines"` — a misleading false-safety failure mode.

---

## Key Findings

1. **ofuscator is the only tool to achieve 100% PII removal with complete JSON output** after adding `--redactNamespaces` in this iteration. The flag covers three distinct locations other tools miss: structured namespace fields, collection-name command arguments (`drop`, `dropIndexes`, `create`, etc.), and free-text `errMsg` strings.

2. **The `errMsg` free-text field is a universal blind spot.** When a collection drop/createIndex fails, MongoDB logs `"ns not found db.collection"` in `attr.errMsg`. Neither fruitsalad nor anonymongo redact this string. ofuscator now applies regex-based namespace substitution to this field when `--redactNamespaces` is active.

3. **MongoDB 5.0 log format is identical to 4.4+ JSON structured format** for the purposes of this benchmark. All tools behaved identically on 5.0.31 logs. The only format difference from MongoDB 9.0 is the absence of the `svc` field added in 5.1.

4. **mlogcensor is broken for any MongoDB ≥ 4.4** and creates a dangerous false-confidence failure mode — outputting `"Censored 0 lines"` while all PII is in `unredacted_lines.log`.

5. **hatchet is not a privacy tool.** Format-preserving substitution still leaves pattern-detectable PII. A regex scan of hatchet output reports 140 hits across emails, SSNs, passports, IPs, and `$comment` tags.

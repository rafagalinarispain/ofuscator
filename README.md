# ofuscator.py — Enhanced MongoDB Log and FTDC Obfuscation Tool

An enhanced version of [fruitsalad](https://github.com/rueckstiess/fruitsalad) by Thomas Rueckstiess, with deep PII field-walking, namespace redaction, character-replacement mode, deterministic seeding, and FTDC diagnostic data redaction.

---

## Overview

`ofuscator.py` operates in two distinct modes selected by a required top-level flag:

| Mode | Flag | Purpose |
|------|------|---------|
| Log redaction | `--log_redact <logfile>` | Obfuscate a MongoDB log file (JSON structured or legacy text) |
| FTDC redaction | `--ftdc_redact` | Redact `hostInfo` from FTDC `diagnostic.data/metrics.*` files |

---

## Requirements

| Mode | Python | Extra packages |
|------|--------|----------------|
| `--log_redact` | 3.6+ | None (standard library only) |
| `--ftdc_redact` | 3.6+ | `pymongo` (`pip install pymongo`) |

---

## Installation

```bash
curl -O https://raw.githubusercontent.com/10gen/employees/master/home/rafael.galinari/fruit_salad_enhanced/ofuscator.py
chmod +x ofuscator.py

# Only needed for --ftdc_redact:
pip install pymongo
```

---

## Mode 1 — Log redaction (`--log_redact`)

Reads a MongoDB log file (JSON structured logs from MongoDB 4.4+, or legacy text logs) and outputs a fully redacted version safe to share with support teams.

```
python3 ofuscator.py --log_redact <logfile> [options]
```

**What is obfuscated:**

| Data type | Default behaviour | With flags |
|-----------|-------------------|-----------|
| IP addresses | Remapped to `192.168.x.x` | `xxx.xxx.xxx.xxx` with `--char_replacement` |
| DB / collection names | Fruit/colour word substitution | Opaque `REDACTED_<hash>` with `--redactNamespaces` |
| Query bodies (`filter`, `q`, `u`, `pipeline`) | MD5-hashed (entire blob) | Field-by-field walk with `--pii` |
| PII values (emails, SSNs, credit cards, …) | Fruit/colour names | `x`-pattern with `--char_replacement` |
| Custom application fields (`$comment`, `_tid`, …) | Not touched | Obfuscated when listed in `--addFields` |
| Free-text error messages (`errMsg`) | Not touched | Namespace tokens replaced with `--redactNamespaces` |

### Log redaction options

| Flag | Description |
|------|-------------|
| `--seed S` / `-s S` | Seed the random number generator with `S`. Same seed → same mapping every run. Useful for consistent obfuscation across multiple log files from the same cluster. |
| `--pii` | Enable **deep PII obfuscation**. Instead of hashing the entire command blob, walks into `attr.command` values and obfuscates 50+ known PII fields individually, preserving the document structure so log analysis tools can still parse it. |
| `--loadSchemaFile FILE` | JSON file with the extra fields you want obfuscated (bare names, dotted paths, or a nested schema). Rule: **default rules + the schema**, and together with `--addFields` the **union of all three**. Replacement style is the usual one (fruit words, or x-pattern with `--char_replacement`). See [Custom field schema](#custom-field-schema---loadschemafile). |
| `--addFields FIELDS` | Comma-separated list of **extra field names** to obfuscate on top of the built-in PII list. Redacted in **every scope**: `attr.command`, oplog applier entries (`attr.CRUD.o`/`o2`), `originatingCommand`, error messages, JSON embedded in strings, operator values (`{"f": {"$in": [...]}}`), aggregation comparisons (`{"$eq": ["$f", "x"]}`), dotted/positional keys (`a.0.f`) and legacy text logs (`f: value`). Matching is case-insensitive and the leading `$` is optional. Example: `'$comment,_tid,appId'` |
| `--strict` | Implies `--pii`. Redacts **every literal** inside filter / update / pipeline / document subtrees, not just values of known PII field names. Field names and `$operators` are preserved. Use this when unlisted application fields may hold personal data. |
| `--server_redaction` (alias `--redactClientLogData`) | Implies `--pii`. Emulates the server's `security.redactClientLogData=true` on client-data attributes: BSON redaction level **all** (every scalar of any type becomes `"###"`, keys / structure / arrays kept, an EJSON wrapper such as `$oid`, `$date`, `$binary` counts as one scalar) and Status / exception text becomes `CodeName: ###` (`what()` -> `###`). The mask is always `###` (ignores `--char_replacement` for those values). Everything else (namespaces, hosts, users, apps, IPs, free text) is still redacted by the normal rules, because the server leaves those visible. See [Server-side redaction policy](#server-side-redaction-policy). |
| `--single_pass` | Skip the name-learning pre-pass (~2x faster). By default the file is read twice: pass 1 learns every db / collection / host / user / app name, pass 2 redacts, so a name is scrubbed from free text even if it is first revealed *after* the line that mentions it. |
| `--redactNamespaces` | Replace every database name and collection name with a stable opaque token (`REDACTED_<8hex>`). Covers `attr.ns`, `attr.command.$db`, all collection-name command arguments (`find`, `update`, `insert`, `delete`, `aggregate`, `drop`, `dropIndexes`, `create`, `createIndexes`, `collection`, …), and free-text `errMsg` strings. Well-known system namespaces (`local`, `admin`, `config`, `$cmd`) are preserved. |
| `--char_replacement` | X-pattern output mode. Behaviour depends on whether `--char_fields` is also provided — see [below](#--char_replacement-behaviour). |
| `--char_fields FIELDS` | Comma-separated field names that receive x-pattern output when `--char_replacement` and `--seed` are both active. All other fields use fruit/colour obfuscation. Has no effect without `--char_replacement`. |

---

## How coverage works (universal sweep)

Earlier versions redacted a fixed list of paths (`attr.command.filter`, `attr.ns`, ...). Every key of every entry is now visited at any depth, following the [logv2 schema](https://github.com/mongodb/mongo/blob/master/docs/logging.md) (`t`, `s`, `c`, `ctx`, `id`, `msg`, `attr`, `tags`, `truncated`, `size`, plus unknown extras):

| Context | Treatment |
|---------|-----------|
| `command` / `commandSpec` / `originatingCommand` | Default-deny: only known structural keys (`limit`, `batchSize`, `ordered`, `writeConcern`, ...) are kept; every other key (`documents`, `updates`, `deletes`, `pipeline`, `comment`, unknown future keys) is data |
| Payload documents (`documents`, `o`, `o2`, `errInfo`, `keyValue`, `min`/`max`, `resumeToken`, `firstBatch`, ...) | With `--pii` every leaf is redacted, keys preserved |
| Filters / updates / pipelines | PII field names (case- and separator-insensitive, dotted paths); operator operands (`$in`, `$eq`, `$regex`, `$gt`, ...) are walked, not skipped; `$expr` comparisons against a PII field reference are redacted |
| Namespaces (`ns`, `namespace`, `$db`, `db`, `$lookup.from`, `$out`, ...) | db/collection aliasing (or `REDACTED_<hash>`); `config.*`, `local.*`, `admin.system.*` kept |
| Hosts / IPs (`host`, `remote`, `client`, `syncSource`, connection strings, `members[].host`, topology descriptions) | Hostnames, IPv4, IPv6, `host:port` |
| Users / apps / replica-set & shard names / certificate subjects | Aliased; learned and replaced in later free text |
| Startup options, `config`, `security`, `ldap`, `net`, `setParameter` | All string leaves redacted |
| Error / status text (`error`, `errmsg`, `errMsg`, `reason`, topology descriptions) | Quoted literals, `{ field: value }` documents (dup-key values) and `db.coll` names masked |
| **Every string, everywhere** (incl. `msg`, `ctx`, keys) | Content scan: emails, credit cards (Luhn), SSNs, IBANs, phones, JWTs, bearer/basic tokens, AWS keys, MACs, IPv4/IPv6, FQDNs, URI credentials, filesystem paths, JSON serialised inside strings |

**Both replacement styles use exactly the same rules.** Detection is independent of style; only `_replacement()` decides between fruit/colour words and x-pattern. `test_ofuscator.py` enforces this: it runs both styles and asserts that a token is changed in one style if and only if it is changed in the other.

**Robustness (fail closed).** Blank first lines, syslog-prefixed JSON, truncated/garbled lines and non-object JSON are redacted with the text pipeline instead of aborting; raw input is never written to stderr. Output lines always equal input lines.

**Hashes are salted.** Blob hashes, numeric replacements and `REDACTED_<hash>` tokens use HMAC-SHA256 keyed with `--seed` (or a random per-run key when no seed is given). Earlier versions used unsalted MD5, which can be brute-forced for low-entropy values (SSNs, phone numbers, common collection names). Consequence: tokens are stable across files only when the **same `--seed`** is used.

---

## Custom field schema (`--loadSchemaFile`)

`--loadSchemaFile FILE` lets you keep the list of application-specific fields to obfuscate in a JSON file instead of
on the command line. The rule for combining options is a plain **union on top of the built-in rules**:

| Options | What is redacted |
|---------|------------------|
| none | the **default** rules only |
| `--loadSchemaFile f.json` | default + the schema in `f.json` |
| `--addFields a,b` | default + the fields `a`, `b` |
| `--loadSchemaFile f.json --addFields a,b` | default + the schema + the fields |

The replacement style does not depend on the schema: fruit / colour words by default, x-pattern with `--char_replacement`
(and `--char_fields`, `--seed`, `--redactNamespaces`, `--strict`, `--server_redaction` combine as usual).

**File format** (every key optional; a top-level JSON array is shorthand for `"fields"`):

```json
{
  "fields": ["tenantRef", "$comment"],
  "paths":  ["customer.vipCode"],
  "schema": { "loyalty": { "tier": true } }
}
```

| Key | Meaning |
|-----|---------|
| `fields` | bare field names, matched at **any depth and in any scope** exactly like `--addFields`: filters, updates, documents, oplog `o`/`o2`, `originatingCommand`, error text, JSON serialised in strings, aggregation comparisons (`{"$eq": ["$tenantRef", "x"]}`), legacy text logs. Case-insensitive, leading `$` optional, dotted / positional keys (`a.0.tenantRef`, `a.$[e].tenantRef`) handled. |
| `paths` | dotted paths. The value of a key is redacted when its ancestor chain **ends with** the path: `customer.vipCode` matches `{"customer": {"vipCode": ..}}`, `{"customer.vipCode": ..}` (dot notation), `{"customer": {"$elemMatch": {"vipCode": ..}}}`, `customer: [{vipCode: ..}]`, `$set: {"customer.vipCode": ..}`, `{"$eq": ["$customer.vipCode", <value>]}` and free text `customer.vipCode: <value>`, but **not** `vendor.vipCode`. `$operators`, array indexes and positional `$[x]` are transparent. The path is contiguous: `customer.items.$[e].vipCode` is a different path. |
| `schema` | nested object; every leaf whose value is `true` (or `{}` / `null`) becomes a path (`false` is ignored). A file with no known key is read as this nested form. |
| `version`, `description`, `comment` | ignored |

Use a bare name in `fields` when the field may appear under any parent; use `paths` / `schema` when the same field name
must be redacted under one parent only.

Example (`--pii --seed s`, same input line, fields `tenantRef`, `customer.vipCode`, `loyalty.tier` in the file and `--addFields grId`):

| Options | `filter` of the slow query |
|---------|----------------------------|
| none | `{"email": "ugli.fruit@aliceblue.com", "grId": "G-1001", "tenantRef": "T-77", "customer.vipCode": "VIP-9", "vendor.vipCode": "V-5", "loyalty": {"tier": "gold"}}` |
| `--loadSchemaFile` | `{"email": "coconut@palegreen.com", "grId": "G-1001", "tenantRef": "melon", "customer.vipCode": "apple", "vendor.vipCode": "V-5", "loyalty": {"tier": "ugli.fruit"}}` |
| `--addFields grId` | `{"email": "ugli.fruit@aliceblue.com", "grId": "coconut", "tenantRef": "T-77", ...}` |
| both | `{"email": "coconut@palegreen.com", "grId": "melon", "tenantRef": "physalis", "customer.vipCode": "apple", "vendor.vipCode": "V-5", "loyalty": {"tier": "ugli.fruit"}}` |
| both + `--char_replacement` | `{"email": "xxxxx@xxxx.xxx", "grId": "x-xxxx", "tenantRef": "x-xx", "customer.vipCode": "xxx-x", "vendor.vipCode": "V-5", "loyalty": {"tier": "xxxx"}}` |

A missing file, invalid JSON or a wrong type (`"fields": "grId"`, `"paths": [5]`, `"schema": {"a": 5}` ...) stops the run with a one-line
`error: --loadSchemaFile: ...` and exit code 2 (no traceback, the file content is never echoed). The option is rejected with `--ftdc_redact`.
Empty schemas (`{}`, `[]`, `{"fields": []}`) are accepted and change nothing.

## Server-side redaction policy

The policies of the MongoDB server's own log redaction (`logv2/redaction.cpp`, `logv2/log_util.cpp`,
enterprise `log_redact_options.cpp`, `repl/bgsync.cpp`, and the nested `BSONObj::redact`) were compared with
this tool; the gaps are closed as follows (measured against real servers in [TEST_RESULTS.md](./TEST_RESULTS.md#3b-server-side-redaction-policy-what-the-mongodb-server-itself-does)):

| Server policy | In this tool |
|---------------|--------------|
| BinData subtype **6 (Encrypt)** and **8 (Sensitive)** become `"###"` at any depth, even with `redactClientLogData` off (`redactEncryptedFields` defaults to true; subtype 8 always) | **Always on** in every mode and every context (filters, documents, generic attrs, JSON embedded in strings, legacy `$binary/$type` form). Needed because 4.4 and 5.0 servers still write the base64 of those payloads. Subtypes 0 / 4 are untouched. |
| `redactClientLogData=true`: every scalar of any type -> `"###"` | `--server_redaction`. Independently of that flag, `--pii` now also erases booleans, null and `0/1/-1` in **payload documents** (`insert.documents`, oplog `o`/`o2`, `errInfo`, shard-key bounds ...) and booleans under PII keys (`hivStatus: true`). |
| `redact(Status)` -> `CodeName: ###`, `redact(DBException)` -> `CodeName ###`, `redact(what())` -> `###` | `--server_redaction` |
| Logs already redacted by the server must survive a second pass | Idempotent on `###`, `CodeName: ###`, `CodeName ###`, `OK` in every mode |

Deliberate deviations from the server: the keys of `sort` / `hint` / `projection` / `fields` (index and field
names, which the server leaves visible) are always obfuscated, and booleans / `-1,0,1` stay as-is under
`$project`, `$sort`, `$group` and update options (`multi`, `upsert` ...) in non-payload queries, because masking
them changes what the query means. The server itself redacts only the call sites wrapped in `redact()`: with
`redactClientLogData=true` it still prints `not authorized on acmeshopdb to execute command {...}`, host names
and several `error` reasons; this tool masks those as well.

## `--redactNamespaces`

Replaces every database and collection name segment with a **stable, hash-based opaque token** — the same name always maps to the same token within a run.

```bash
python3 ofuscator.py --log_redact mongod.log --pii --redactNamespaces > redacted.log
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

The token format `REDACTED_<8hex>` is a salted HMAC. With the same `--seed` the same name always produces the same token, so entries can be correlated across multiple redacted files; without `--seed` a random key is used per run.

---

## `--char_replacement` behaviour

This flag has two distinct modes depending on how it is combined with other options.

### Used alone — replaces everything with x-pattern

```bash
python3 ofuscator.py --log_redact mongod.log --pii --char_replacement > redacted.log
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
python3 ofuscator.py --log_redact mongod.log \
  --pii --seed myseed \
  --char_replacement --char_fields 'emails,externalShares,$comment' \
  > redacted.log
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

## Log redaction examples

### Basic obfuscation (namespaces + IPs only)

```bash
python3 ofuscator.py --log_redact mongod.log > redacted.log
```

Namespace segments replaced with fruit/colour words, IPs remapped to `192.168.x.x`. Query bodies are MD5-hashed as a single blob.

### Deep PII obfuscation with a deterministic seed

```bash
python3 ofuscator.py --log_redact mongod.log --pii --seed mysecretkey > redacted.log
```

Walks into command bodies field by field. Same seed on the same log always produces the same output — useful for correlating multiple log files from the same cluster.

### Full redaction recommended for external sharing

```bash
python3 ofuscator.py --log_redact mongod.log \
  --pii \
  --addFields '$comment,_tid,recordId,tenant' \
  --seed mysecretkey \
  --char_replacement \
  --redactNamespaces \
  > redacted.log
```

This combination achieves **100% PII removal** (verified against 17 sensitive data categories in an independent benchmark against MongoDB 5.0.31):

- `--pii` — deep field walk, 50+ built-in PII field names
- `--addFields` — extends to app-specific fields (`$comment`, `_tid`, tenant IDs)
- `--seed` — deterministic, consistent output across shards
- `--char_replacement` — all values become x-pattern for unambiguous visual review
- `--redactNamespaces` — db/collection names and free-text error strings redacted to `REDACTED_<hash>`

### Obfuscate PII and specific extra fields only

```bash
python3 ofuscator.py --log_redact mongod.log --pii --addFields '$comment,_tid' --seed test123 > redacted.log
```

### Full x-pattern (no seed, blanket replacement)

```bash
python3 ofuscator.py --log_redact mongod.log --pii --addFields '$comment,_tid' --char_replacement > redacted.log
```

### Selective x-pattern — specific fields blanked, rest fruit/colour

```bash
python3 ofuscator.py --log_redact mongod.log \
  --pii --seed test123 \
  --char_replacement --char_fields 'emails,externalShares,$comment,_tid' \
  > redacted.log
```

---

## Mode 2 — FTDC redaction (`--ftdc_redact`)

Redacts `hostInfo` fields from MongoDB FTDC `diagnostic.data/metrics.*` files so the files can be shared externally without exposing server hardware details, OS version, or hostname.

```
python3 ofuscator.py --ftdc_redact --input_dir <dir> --output_dir <dir>
```

### How it works

FTDC files are a stream of raw BSON documents. Each file contains:
- **type-0 (metadata) chunks** — full MongoDB server state snapshot including `buildInfo`, `getCmdLineOpts`, and `hostInfo`.
- **type-1 (metric) chunks** — compressed numeric delta data; no text fields.

The tool processes only type-0 chunks. For each one it:
1. Replaces every scalar value inside `hostInfo` with `"#"`.
2. Preserves datetime fields (`start`, `end`, `currentTime`) and the `ok` field.
3. Replaces `hostInfo.system.hostname` with `redacted_hostname_<member_id>:redacted_port_number`, where `<member_id>` is the RS member `_id` read from `replSetGetStatus.members[self=true]._id` inside the first type-1 metric chunk (falls back to `unknown` if not found).
4. Re-encodes the document as BSON and writes it to `--output_dir` under the same filename.

Type-1 metric chunks are written byte-for-byte unchanged, so the redacted files remain valid FTDC files that can be analysed with standard tools (`ftdc-utils`, `mongodump` viewers, etc.).

### FTDC redaction options

| Flag | Description |
|------|-------------|
| `--input_dir DIR` | Directory containing `metrics.*` files (typically `diagnostic.data/`). Required. |
| `--output_dir DIR` | Directory to write redacted files into. Created if it does not exist. Required. |

### Example

```bash
python3 ofuscator.py --ftdc_redact \
  --input_dir /data/db/diagnostic.data \
  --output_dir /tmp/redacted_ftdc
```

**Before** (`hostInfo.system` in a type-0 chunk):
```json
"system": {
  "currentTime": { "$date": "..." },
  "hostname": "prod-rs1.internal.example.com:27017",
  "cpuAddrSize": 64,
  "memSizeMB": 65536,
  "numCores": 32,
  "cpuArch": "x86_64"
}
```

**After**:
```json
"system": {
  "currentTime": { "$date": "..." },
  "hostname": "redacted_hostname_0:redacted_port_number",
  "cpuAddrSize": "#",
  "memSizeMB": "#",
  "numCores": "#",
  "cpuArch": "#"
}
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

`--redactNamespaces` tokens (`REDACTED_<hash>`) are HMAC-SHA256 keyed with the seed; use the same `--seed` on every file of a cluster to keep them correlatable.

---

## Testing

```bash
python3 test_ofuscator.py -v
```

`test_ofuscator.py` (63 tests) builds ~30 entries modelled on the mongod/mongos log schema (slow queries for find/insert/update/delete/findAndModify/aggregate/getMore, auth, TLS, client metadata, replication, sharding `moveChunk`, index builds, oplog applier, startup options, change streams, truncated entries, legacy text) carrying canary PII. For the whole flag matrix (default, `--pii`, `--strict`, `--redactNamespaces`, `--char_replacement`, `--char_fields`, `--seed`, `--addFields`) it asserts that **no canary appears anywhere in stdout or stderr**, that output stays valid JSON with the same line count, that fruit and x-pattern styles have identical coverage, and that no unsalted MD5 of a sensitive value is emitted.

### Integration test against real mongod / mongos logs

`test_integration_mongo.py` takes the MongoDB version as its argument, installs it with [`m`](https://github.com/aheckmann/m), starts a minimal **auth-enabled sharded cluster** with [mtools](https://github.com/rueckstiess/mtools) `mlaunch` (1 shard replica set + 1 config server + 1 mongos, `slowms=0`), runs a PII-heavy workload through the mongos, and pushes the three real logs through `ofuscator.py`:

```bash
pip install mtools pymongo                      # plus `m` on PATH
python3 test_integration_mongo.py 5.0           # newest 5.0.x installable on this platform
python3 test_integration_mongo.py 7.0.43 -v     # exact version
python3 test_integration_mongo.py 8.0 --shards 2   # 2 shards -> also exercises moveChunk
python3 test_integration_mongo.py 5.0 --keep    # keep cluster dir + logs
python3 test_integration_mongo.py 5.0 --use-logs DIR   # re-test saved logs, no cluster
OFUSCATOR_MONGO_VERSION=5.0 python3 -m unittest test_integration_mongo
```

- `X.Y` resolves to the newest `X.Y.Z` that `m` can actually install here (e.g. `5.0` -> 5.0.31: 5.0.32-5.0.34 have no macOS binaries). Your **active `m` version is restored** afterwards (symlinks are snapshotted and re-created); versions it had to download stay installed (`m rm <ver>` to remove).
- The workload covers CRUD, aggregation (`$lookup`/`$out`/`$unionWith`), dup-key / validation / bad-modifier errors, transactions, change streams + resume tokens, index builds, sharding (`shardCollection`, `split`, `moveChunk`), users, failed and successful logins, several `appName`s, and direct shard connections.
- Checks (per log x flag matrix): no canary PII in stdout/stderr, no source IP survives, machine hostname / OS user / work dir are removed, every line is schema-valid logv2 JSON with unchanged `t/s/c/id` and top-level `attr` keys, the message histogram and operational counters are preserved, fruit and x-pattern styles have identical coverage, independent PII-shape scans of the output, determinism / salting, idempotence, and fail-closed behaviour on a damaged copy of the real log.
- It also verifies the test is not vacuous: the canaries must really appear in the source logs produced by that server version.
- mtools 1.7.2 cannot parse 4.4+ JSON logs (it returns no datetime even for the original log), so for those versions the built-in logv2 validator is used; on legacy text logs `mloginfo` is used as a parse oracle.
- `--loadSchemaFile` x `--addFields`: 20 unit tests cover the 4 option combinations x fruit / x style x `--pii` / `--strict` / default mode on nine contexts (generic attr, filter with dotted keys, `$elemMatch`, arrays, `$set` on dotted and positional paths, `$expr` field references, oplog `o`, JSON in a string, free text), path precision (`vendor.vipCode` stays), file formats, validation errors and legacy text logs; the real-cluster suite repeats the four combinations against the mongos / shard / config logs (`test_56`, `test_57`).
- `--ground-truth` (enterprise build, e.g. `5.0.31-ent`, `7.0.17-ent`, `8.0.17-ent`) also runs a **second cluster whose server redacts its own logs** (`redactClientLogData=true`) and asserts that every distinct redacted command of the user operations is identical to `--server_redaction` applied to the unredacted cluster, that Status forms agree wherever the server masks, and that the tool is idempotent on the server-redacted logs.
- Run against 4.4, 5.0, 6.0, 7.0 and 8.0 while developing; it found real gaps the synthetic fixtures missed (shard-key `splitPoint`, internal `config.cache.chunks.<ns>` namespaces, index names in specs, `dropIndexes.index`, short host names in `event`/`server`, field-name collisions dropping fields).

## Known limits

- Without `--strict`, values of application field names that are neither in the built-in list nor in `--addFields` and that do not look like a known PII shape (e.g. `{"nickname2": "free text"}` inside a *filter*) are kept. Payload documents (`insert.documents`, oplog `o`/`o2`, ...) are always fully redacted with `--pii`; use `--strict` for filters/updates/pipelines.
- Bare numbers (e.g. a 9-digit SSN stored as a string) are only detected by key name or by an `$expr` comparison with a PII field, not by shape.
- Names are replaced in free text only when learned from a keyed field (`--single_pass` makes this order-dependent).
- `--ftdc_redact` only rewrites `hostInfo` in type-0 chunks. The compressed reference document of type-1 chunks (`replSetGetStatus` member hostnames, `serverStatus.host`, ...) is passed through unchanged.
- Always review the output manually before sharing externally.

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

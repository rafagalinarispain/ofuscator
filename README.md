# ofuscator.py — Enhanced MongoDB Log and FTDC Obfuscation Tool

An enhanced version of [fruitsalad](https://github.com/rueckstiess/fruitsalad) by Thomas Rueckstiess. **The default policy redacts client data the way the MongoDB server itself does with `security.redactClientLogData=true`** (every literal of every type inside commands, filters, documents and oplog entries becomes `###`, keys and structure are kept), and goes further: hosts, IPs, users, applications, namespaces, secrets and PII shapes are redacted in every string. Everything that is redacted becomes `###` by default; `--char_replacement [CHAR]` swaps that for a shape-preserving character pattern (`x` unless you choose another). Plus namespace redaction, deterministic `REDACTED_<hash>` tokens, a custom-field schema file, and FTDC diagnostic data redaction.

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

Reads a MongoDB log file (JSON structured logs from MongoDB 4.4+, or legacy text logs) and outputs a redacted version safe to share with support teams. A JSON log gives a JSON log (one valid logv2 object per line); a text log gives a text log.

```
python3 ofuscator.py --log_redact <logfile> [options]
```

### The default policy (no option needed)

Running with no options already applies **all** of the following; there are no `--pii` / `--strict` / `--server_redaction` switches to remember.

| What | Default behaviour |
|------|-------------------|
| **Client data**: `command` / `originatingCommand`, filters, updates, pipelines, documents, oplog entries (`o`, `o2`), `errInfo`, `keyValue`, shard-key bounds, resume tokens ... | Exactly the server's `redactClientLogData=true` output: **every scalar of every type** (strings, numbers, booleans, null, dates, ObjectIds, BinData) becomes the string `###`; field names, operators, nesting and arrays are kept. Collection names and `$db` inside a command are client data too. |
| BinData subtype 6 (Encrypt) / 8 (Sensitive) anywhere | `###` (the server does this only from 6.0 on; 4.4 / 5.0 logs still carry the ciphertext) |
| Status / exception text (`error`, `errMsg`, `reason`, `what()`) | `CodeName: ###`, `CodeName ###` or `###` (the code is kept, the reason dropped) |
| Namespaces outside commands (`ns`, `namespace`, ...) | `###.###`, or `REDACTED_<hash>` with `--redactNamespaces`; `config.*`, `local.*`, `admin.system.*`, `$cmd` kept |
| Hosts, IPs (v4 / v6), `host:port`, FQDNs, users, `appName`, replica set / shard names, certificate subjects, file paths | `###` (an IP keeps its port; loopback addresses are kept); learned and replaced in free text too |
| Startup options, credentials, tokens, JWTs, cards, SSNs, emails, MACs, IBANs, URI passwords in **any** string | Redacted by key name and by content scan |
| Extra fields you name (`--addFields`, `--loadSchemaFile`) | Redacted (`###`) wherever they appear outside client data |
| Operational data: `t`, `s`, `c`, `id`, `ctx`, `msg`, counters, durations, plan summaries, locks | Kept, so the log stays analysable |

Sample (input -> default output):

```json
{"c":"COMMAND","msg":"Slow query","attr":{"ns":"shop.customers","appName":"AcmeBilling","command":{"find":"customers","filter":{"email":"alice.smith@acme-corp.com","age":{"$gt":18},"vip":true,"notes":"called twice"},"sort":{"createdAt":-1},"limit":5,"$db":"shop"},"planSummary":"IXSCAN { email: 1 }","nreturned":1,"durationMillis":7,"remote":"10.20.30.40:51234"}}
```
```json
{"c":"COMMAND","msg":"Slow query","attr":{"ns":"###.###","appName":"###","command":{"find":"###","filter":{"email":"###","age":{"$gt":"###"},"vip":"###","notes":"###"},"sort":{"###":"###"},"limit":"###","$db":"###"},"planSummary":"IXSCAN { ###: 1 }","nreturned":1,"durationMillis":7,"remote":"###:51234"}}
```

With `--char_replacement` (default character `x`) the same line becomes `"ns":"xxxx.xxxxxxxxx"`, `"appName":"xxxxxxxxxxx"`, `"filter":{"email":"xxx", ...}`, `"sort":{"xxxxxxxxx":"xxx"}`, `"planSummary":"IXSCAN { xxxxx: 1 }"`, `"remote":"xxx.xxx.xxx.xxx:51234"`: see [`--char_replacement`](#--char_replacement-char). A log that the server already redacted passes through unchanged (the policy is idempotent on `###`, `CodeName: ###`, `CodeName ###`).

All names are replaced by the same `###`, so two different collections are no longer distinguishable. If you need to correlate names, use `--redactNamespaces` (stable `REDACTED_<hash>` tokens for databases and collections).

Because the policy mirrors the server, `limit`, `batchSize`, `writeConcern`, `ordered` ... inside a command are masked as well (the server masks them). Counters outside the command (`nreturned`, `keysExamined`, `durationMillis`, ...) stay.

### Log redaction options

| Flag | Description |
|------|-------------|
| `--seed S` / `-s S` | Fix the key of the `REDACTED_<hash>` tokens of `--redactNamespaces` (an HMAC of the name): with the same seed **the same name maps to the same token in every file, in any order**; without a seed a random key is used for each run. Without `--redactNamespaces` the output does not depend on the seed (every replacement is `###`). |
| `--loadSchemaFile FILE` | JSON file with extra fields to obfuscate (bare names, dotted paths, or a nested schema). Rule: **default + schema**, and together with `--addFields` the **union of all three**. See [Custom field schema](#custom-field-schema---loadschemafile). |
| `--addFields FIELDS` | Comma-separated **extra field names** to obfuscate on top of the default policy, at any depth and in any scope outside client data (generic attributes, JSON embedded in strings, aggregation comparisons such as `{"$eq": ["$f", "x"]}`, dotted / positional keys, free text, legacy text logs). Case-insensitive, leading `$` optional. Example: `'$comment,_tid,appId'` |
| `--redactNamespaces` | Replace every database and collection name with a stable opaque token (`REDACTED_<8hex>`) in namespace attributes, free text and error strings. Well-known system namespaces (`local`, `admin`, `config`, `$cmd`) are preserved. |
| `--char_replacement [CHAR]` | Use a character pattern instead of `###` **for everything that is redacted**. `CHAR` is optional (default `x`) and must be exactly one visible character (`'*'` must be quoted in a shell). Values that used to be replaced by a name keep their shape (`alice@acme.com` -> `xxxxx@xxxx.xxx`) and every `###` becomes `CHAR` x 3. See [below](#--char_replacement-char). |
| `--char_fields FIELDS` | With `--char_replacement`: comma-separated field names that alone receive the character pattern; everything else stays `###`. No effect without `--char_replacement`. |
| `--single_pass` | Skip the name-learning pre-pass (~2x faster). By default the file is read twice: pass 1 learns every db / collection / host / user / app name, pass 2 redacts, so a name is scrubbed from free text even if it is first revealed *after* the line that mentions it. |

**Deprecated, accepted and ignored:** `--pii`, `--strict`, `--server_redaction` and `--redactClientLogData` were options in earlier versions. They are the default policy now; passing them still works (hidden from `--help`) and prints one line to stderr: `note: ... ignored: deep PII, strict and server-style redaction are the default policy now.`

---

## How coverage works (universal sweep)

Every key of every entry is visited at any depth (there is no fixed list of paths), following the [logv2 schema](https://github.com/mongodb/mongo/blob/master/docs/logging.md) (`t`, `s`, `c`, `ctx`, `id`, `msg`, `attr`, `tags`, `truncated`, `size`, plus unknown extras):

| Context | Treatment |
|---------|-----------|
| `command` / `commandSpec` / `originatingCommand` / `request` / `cmdObj` | The whole BSON, like the server: every scalar `###` (collection name, `$db`, `limit`, `lsid`, `$clusterTime` ... included); keys kept, except the keys of `sort` / `hint` / `projection` / `fields` (index and field names), which are obfuscated |
| Payload documents (`documents`, `o`, `o2`, `errInfo`, `keyValue`, `min`/`max`, `splitPoint`, `resumeToken`, `firstBatch`, ...) | Every leaf `###`, keys preserved |
| Filters / updates / pipelines (`filter`, `q`, `u`, `updates`, `pipeline`, `$expr`, ...) | Every literal `###`; operators (`$in`, `$eq`, `$regex`, `$gt`, ...) and field names kept; a `{$regex, $options}` document is masked field by field |
| Namespaces (`ns`, `namespace`, `$db`, `db`, `$lookup.from`, `$out`, ...) | `###.###` (or `REDACTED_<hash>`); `config.*`, `local.*`, `admin.system.*` kept |
| Hosts / IPs (`host`, `remote`, `client`, `syncSource`, connection strings, `members[].host`, topology descriptions) | Hostnames, IPv4, IPv6, `host:port` (the port is kept) |
| Users / apps / replica-set & shard names / certificate subjects | `###`; learned and replaced in later free text |
| Startup options, `config`, `security`, `ldap`, `net`, `setParameter` | All string leaves redacted |
| Error / status text (`error`, `errmsg`, `errMsg`, `reason`, `what`) | `CodeName: ###` / `###` (server form). Other descriptive text (topology descriptions, `message`): quoted literals, `{ field: value }` documents and `db.coll` names masked |
| **Every string, everywhere** (incl. `msg`, `ctx`, keys) | Content scan: emails, credit cards (Luhn), SSNs, IBANs, phones, JWTs, bearer/basic tokens, AWS keys, MACs, IPv4/IPv6, FQDNs, URI credentials, filesystem paths, JSON serialised inside strings |

**Detection does not depend on the replacement.** With and without `--char_replacement` the same tokens are redacted; only the replacement text differs. `test_ofuscator.py` enforces this: it runs both and asserts that a token is changed in one if and only if it is changed in the other.

**Robustness (fail closed).** Blank first lines, syslog-prefixed JSON, truncated/garbled lines and non-object JSON are redacted with the text pipeline instead of aborting; raw input is never written to stderr. Output lines always equal input lines.

**Tokens are keyed.** `REDACTED_<hash>` tokens and the numeric replacements use HMAC-SHA256 keyed with `--seed` (or a random per-run key when no seed is given); unsalted MD5, which can be brute-forced for low-entropy values, is not used. Consequence: tokens are stable across files only when the **same `--seed`** is used.

---

## Custom field schema (`--loadSchemaFile`)

`--loadSchemaFile FILE` keeps the list of application-specific fields to obfuscate in a JSON file instead of on the command line. The rule for combining options is a plain **union on top of the default policy**:

| Options | What is redacted |
|---------|------------------|
| none | the **default** policy |
| `--loadSchemaFile f.json` | default + the schema in `f.json` |
| `--addFields a,b` | default + the fields `a`, `b` |
| `--loadSchemaFile f.json --addFields a,b` | default + the schema + the fields |

The replacement does not depend on the schema: `###` by default, or the character pattern with `--char_replacement` (`--char_fields` and `--redactNamespaces` combine as usual).

**Where it matters.** Inside client data (commands, filters, updates, documents, oplog entries) the default policy already masks *every* literal with `###`, so a field named in the schema is masked there with or without it. The schema extends the reach to everything else: generic attributes, containers the server does not treat as client data, JSON serialised in strings, free text, comparisons against field references, legacy text logs, and it makes those values `###` instead of leaving them readable.

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
| `fields` | bare field names, matched at **any depth** exactly like `--addFields`: nested objects, operator operands (`{"f": {"$in": [..]}}`), JSON serialised in strings, aggregation comparisons (`{"$eq": ["$tenantRef", "x"]}` and `{"$in": ["x", ["$tenantRef"]]}`), free text (`tenantRef: x`), legacy text logs. Case-insensitive, leading `$` optional, dotted / positional keys (`a.0.tenantRef`, `a.$[e].tenantRef`) handled. |
| `paths` | dotted paths. The value of a key is redacted when its ancestor chain **ends with** the path: `customer.vipCode` matches `{"customer": {"vipCode": ..}}`, `{"customer.vipCode": ..}` (dot notation), `{"customer": {"$elemMatch": {"vipCode": ..}}}`, `customer: [{vipCode: ..}]`, `$set: {"customer.vipCode": ..}`, `{"$eq": ["$customer.vipCode", <value>]}` and free text `customer.vipCode: <value>`, but **not** `vendor.vipCode`. `$operators`, array indexes and positional `$[x]` are transparent. The path is contiguous: `customer.items.$[e].vipCode` is a different path. |
| `schema` | nested object; every leaf whose value is `true` (or `{}` / `null`) becomes a path (`false` is ignored). A file with no known key is read as this nested form. |
| `version`, `description`, `comment` | ignored |

Use a bare name in `fields` when the field may appear under any parent; use `paths` / `schema` when the same field name must be redacted under one parent only.

Example (schema = `fields: [tenantRef]`, `paths: [customer.vipCode]`; one line whose attributes are not client data):

| Options | `attr` |
|---------|--------|
| none | `{"emails":["###","###"],"tenantRef":"T-77","customer":{"vipCode":"VIP-9"},"vendor":{"vipCode":"V-5"}}` |
| `--loadSchemaFile` | `{"emails":["###","###"],"tenantRef":"###","customer":{"vipCode":"###"},"vendor":{"vipCode":"V-5"}}` |
| `--loadSchemaFile --char_replacement '*'` | `{"emails":["*****@************.***","*****@************.***"],"tenantRef":"*-**","customer":{"vipCode":"***-*"},"vendor":{"vipCode":"V-5"}}` |

(`emails` is an identity key, so it is redacted by the default policy in every row; `vendor.vipCode` matches nothing and stays. With the character pattern a schema field keeps its shape, like any former name value.)

A missing file, invalid JSON or a wrong type (`"fields": "grId"`, `"paths": [5]`, `"schema": {"a": 5}` ...) stops the run with a one-line `error: --loadSchemaFile: ...` and exit code 2 (no traceback, the file content is never echoed). The option is rejected with `--ftdc_redact`. Empty schemas (`{}`, `[]`, `{"fields": []}`) are accepted and change nothing.

---

## Server-side redaction policy

The policies of the MongoDB server's own log redaction (`logv2/redaction.cpp`, `logv2/log_util.cpp`, enterprise `log_redact_options.cpp`, `repl/bgsync.cpp`, and the nested `BSONObj::redact`) were compared with this tool and are all part of the **default policy** (measured against real servers in [TEST_RESULTS.md](./TEST_RESULTS.md#3b-server-side-redaction-policy-what-the-mongodb-server-itself-does)):

| Server policy | In this tool (default) |
|---------------|------------------------|
| BinData subtype **6 (Encrypt)** and **8 (Sensitive)** become `"###"` at any depth, even with `redactClientLogData` off (`redactEncryptedFields` defaults to true; subtype 8 always) | Always masked, in every context, both EJSON forms. Needed because 4.4 and 5.0 servers still write the base64 of those payloads. Subtypes 0 / 4 are untouched. |
| `redactClientLogData=true`: BSON level `all`, every scalar of any type -> `"###"`, keys / structure / arrays kept, an EJSON wrapper (`$oid`, `$date`, `$binary` ...) counts as one scalar | Applied to all client data (commands, filters, documents, oplog entries, `errInfo`, ...). A `{$regex, $options}` document is masked field by field, as the server does. |
| `redact(Status)` -> `CodeName: ###`, `redact(DBException)` -> `CodeName ###`, `redact(what())` -> `###` | Same forms (`Code{ extra }: reason` is reduced to `Code: ###`); structured `{code, codeName, errmsg}` keeps the codes and masks `errmsg` |
| Logs already redacted by the server must survive a second pass | Idempotent on `###`, `CodeName: ###`, `CodeName ###`, `OK` |

Deliberate deviation from the server: the keys of `sort` / `hint` / `projection` / `fields` (index and field names, which the server leaves visible) are obfuscated.

This tool is **stricter** than the server where the server is not exhaustive: it redacts only the call sites wrapped in `redact()`, so even with `redactClientLogData=true` it still prints `not authorized on acmeshopdb to execute command {...}`, host names, namespaces, `appName`, users and several `error` reasons. The default policy masks all of those too; verified against enterprise 5.0 / 7.0 / 8.0 servers that redact their own logs.

---

## `--redactNamespaces`

Replaces every database and collection name segment with a **stable, hash-based opaque token** — the same name always maps to the same token within a run.

```bash
python3 ofuscator.py --log_redact mongod.log --redactNamespaces > redacted.log
```

**Input log fields:**
```
attr.ns                   → "pii_test_db.$cmd"
attr.namespace            → "pii_test_db.sensitive_records"
attr.command.$db          → "pii_test_db"        (client data: "###" in the default policy)
attr.command.find         → "sensitive_records"  (client data: "###" in the default policy)
attr.note                 → "ns not found pii_test_db.sensitive_records"
```

**Output:**
```
attr.ns                   → "REDACTED_edaac6f4.$cmd"
attr.namespace            → "REDACTED_edaac6f4.REDACTED_20170fcb"
attr.command.$db          → "###"
attr.command.find         → "###"
attr.note                 → "ns not found REDACTED_edaac6f4.REDACTED_20170fcb"
```

The token format `REDACTED_<8hex>` is a salted HMAC. With the same `--seed` the same name always produces the same token, so entries can be correlated across multiple redacted files; without `--seed` a random key is used per run. With `--char_replacement` the tokens are kept as they are.

---

## `--char_replacement [CHAR]`

By default every redacted value is `###`. `--char_replacement` replaces that with a character pattern:

```bash
python3 ofuscator.py --log_redact mongod.log --char_replacement > redacted.log        # x
python3 ofuscator.py --log_redact mongod.log --char_replacement '*' > redacted.log    # *
```

`CHAR` is optional (`x` when omitted) and must be exactly one visible character (not whitespace, not a control character); anything else stops the run with a usage error. The character covers **everything** that is redacted:

| Redacted value | Default | `--char_replacement` | `--char_replacement '*'` |
|----------------|---------|----------------------|--------------------------|
| client data literal (`"alice@acme.com"`, `18`, `true`) | `###` | `xxx` | `***` |
| status text (`UserNotFound: ...`) | `UserNotFound: ###` | `UserNotFound: xxx` | `UserNotFound: ***` |
| namespace `shop.customers` | `###.###` | `xxxx.xxxxxxxxx` | `****.*********` |
| `appName` `AcmeBilling` | `###` | `xxxxxxxxxxx` | `***********` |
| email outside client data | `###` | `xxxxx@xxxxxxxxxxxx.xxx` | `*****@************.***` |
| host / IP `10.20.30.40:51234` | `###:51234` | `xxx.xxx.xxx.xxx:51234` | `***.***.***.***:51234` |
| field name in `sort` | `###` | `xxxxxxxxx` | `*********` |

Client data (`###` in the default) always becomes exactly three characters, so its length or shape is not revealed; names, hosts and other non-client values keep their shape ([see below](#how-the-character-pattern-works)). Letters and digits of any alphabet are replaced (`Jürgen Müller` -> `****** ******`); separators (`@ . - / : _`) stay. Because the same flag turns every `###` into `CHAR` x 3, a log redacted with `--char_replacement` can no longer be told apart from the server's own `###` by a script, which is the intent: reviewers can search for real patterns (e.g. `@`) and see that nothing slipped through.

### `--char_fields`: selective pattern

```bash
python3 ofuscator.py --log_redact mongod.log \
  --char_replacement --char_fields 'emails,externalShares,$comment' \
  > redacted.log
```

Only the fields listed in `--char_fields` receive the character pattern; everything else stays `###`. Useful when most of the log should look like the server's own redaction but specific fields should be unmistakably blanked for review.

| Field | Output |
|-------|--------|
| `ns` (namespace) | `###.###` |
| `alternateLink` | `###` |
| `emails` (in `--char_fields`) | `xxxxx@xxxxxxxxxxxx.xxx` |
| `externalShares` (in `--char_fields`) | `xxxxxxxxxx@xxxxxxxxxxxx.xxx` |
| `$comment` (in `--char_fields`) | `xxxxxxxxx` |

---

## Log redaction examples

### Default run (nothing to choose)

```bash
python3 ofuscator.py --log_redact mongod.log > redacted.log
```

Client data (commands, filters, documents, oplog entries) is masked exactly like the server's `redactClientLogData=true` (`###`, keys and structure kept), Status text becomes `CodeName: ###`, BinData 6/8 is masked, and namespaces, hosts, IPs, users, apps, secrets and PII shapes are replaced by `###`.

### Correlatable names across all files of a cluster

```bash
python3 ofuscator.py --log_redact mongos.log --redactNamespaces --seed mysecretkey > mongos.red.log
python3 ofuscator.py --log_redact shard1.log --redactNamespaces --seed mysecretkey > shard1.red.log
```

With the same seed the same database / collection name becomes the same `REDACTED_<hash>` token in every file, so the redacted files of one cluster can still be correlated. (Everything else is `###`.)

### Full redaction recommended for external sharing

```bash
python3 ofuscator.py --log_redact mongod.log \
  --addFields '$comment,_tid,recordId,tenant' \
  --seed mysecretkey \
  --char_replacement '*' \
  --redactNamespaces \
  > redacted.log
```

- (default) — server-style redaction of every client literal, BinData 6/8, Status forms, hosts / IPs / users / apps / secrets
- `--addFields` — extends to app-specific fields outside client data (`$comment`, `_tid`, tenant IDs)
- `--seed` — the same namespace gets the same token in every file
- `--char_replacement '*'` — every redaction is visible as a character pattern for unambiguous visual review
- `--redactNamespaces` — db/collection names and free-text error strings redacted to `REDACTED_<hash>`

### Extra fields from a schema file

```bash
python3 ofuscator.py --log_redact mongod.log --loadSchemaFile fields.json --addFields '$comment' > redacted.log
```

Default + the schema in `fields.json` + `$comment` (see [Custom field schema](#custom-field-schema---loadschemafile)).

### Character pattern for everything

```bash
python3 ofuscator.py --log_redact mongod.log --addFields '$comment,_tid' --char_replacement > redacted.log
```

### Selective pattern: specific fields blanked, rest `###`

```bash
python3 ofuscator.py --log_redact mongod.log \
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

## Built-in PII field list

The following field names are recognised as PII: in client data every literal is already `###`, and in data subtrees outside client data (JSON in strings, query-shaped containers, comparisons against field references such as `{"$eq": ["$email", "x"]}`, free text) their values are replaced. In plain attributes only identity, host and secret-type keys (user, email, password, token, ...) are matched by name; everything else there is caught by its content shape or needs `--addFields`. Both exact keys and the last segment of dot-notation keys (e.g. `"identity.ssn"`) are matched, case- and separator-insensitively.

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

## How the character pattern works

With `--char_replacement` each letter and digit (any alphabet) of a name-like value is replaced individually, preserving structural separators so the shape remains readable (`x` shown; any single character works):

| Original | Replaced |
|----------|----------|
| `lemon@antiquewhite.com` | `xxxxx@xxxxxxxxxxxx.xxx` |
| `https://app.example.com/path` | `https://xxx.xxxxxxx.xxx/xxxx` |
| `749-17-2043` (SSN) | `xxx-xx-xxxx` |
| `4831-7219-4053-6148` (CC) | `xxxx-xxxx-xxxx-xxxx` |
| `application/json` | `xxxxxxxxxxx/xxxx` |
| `blackcurrant` | `xxxxxxxxxxxx` |
| `192.168.1.100` | `xxx.xxx.x.xxx` |
| client data literal `###` | `xxx` |

---

## Seed and determinism

Without `--redactNamespaces` the output is fully deterministic and independent of `--seed`: every replacement is `###` (or the character pattern). `--seed` keys only the `REDACTED_<hash>` tokens of `--redactNamespaces`, an HMAC of the name under that key:

- Same seed + same input -> same output, every run
- The same name maps to the same token in **every file** of a cluster, in any order, with any combination of the other options (tested: `test_seed_only_keys_the_redacted_namespace_tokens`)
- A different seed gives different tokens; the mapping cannot be reversed without the seed
- Without `--seed` a random key is generated for each run

---

## Testing

```bash
python3 test_ofuscator.py -v
```

`test_ofuscator.py` (75 tests) builds ~30 entries modelled on the mongod/mongos log schema (slow queries for find/insert/update/delete/findAndModify/aggregate/getMore, auth, TLS, client metadata, replication, sharding `moveChunk`, index builds, oplog applier, startup options, change streams, truncated entries, legacy text) carrying canary PII. For the option matrix (default, `--redactNamespaces`, `--char_replacement`, `--char_fields`, `--seed`, `--single_pass`, `--addFields`, `--loadSchemaFile`) it asserts that **no canary appears anywhere in stdout or stderr**, that output stays valid JSON with the same line count, that the default `###` and `--char_replacement` have identical coverage, that the character pattern leaves no readable letter or digit of any alphabet, and that no unsalted MD5 of a sensitive value is emitted.

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
- Checks (per log x flag matrix): no canary PII in stdout/stderr, no source IP survives, machine hostname / OS user / work dir are removed, every line is schema-valid logv2 JSON with unchanged `t/s/c/id` and top-level `attr` keys, the message histogram and operational counters are preserved, system namespaces and loopback addresses are kept, default and `--char_replacement` have identical coverage, independent PII-shape scans of the output, determinism / salting, idempotence, and fail-closed behaviour on a damaged copy of the real log.
- It also verifies the test is not vacuous: the canaries must really appear in the source logs produced by that server version.
- mtools 1.7.2 cannot parse 4.4+ JSON logs (it returns no datetime even for the original log), so for those versions the built-in logv2 validator is used; on legacy text logs `mloginfo` is used as the independent parse check.
- `--loadSchemaFile` x `--addFields`: 20 unit tests cover the 4 option combinations x `###` / character pattern on nine contexts outside client data (generic attr, query-shaped containers with dotted keys, `$elemMatch`, arrays, `$set` on dotted and positional paths, comparisons against field references, sub-documents, JSON in a string, free text), path precision (`vendor.vipCode` stays), file formats, validation errors and legacy text logs, and prove that client data is masked identically under every combination. The real-cluster suite repeats the four combinations on a real mongos log with an injected probe entry (`test_56`, `test_57`).
- `--ground-truth` (enterprise build, e.g. `5.0.31-ent`, `7.0.17-ent`, `8.0.17-ent`) also runs a **second cluster whose server redacts its own logs** (`redactClientLogData=true`) and asserts that every distinct redacted command of the user operations is identical to the **default output** for the unredacted cluster, that Status forms agree wherever the server masks, and that the tool is idempotent on the server-redacted logs.
- `--char_replacement [CHAR]`: 13 unit tests (default `x`, any visible character, rejection of invalid values, Unicode, `--char_fields` selective mode, idempotence, every `###` converted in JSON and text) plus real-log tests (`test_17`, `test_32`, `test_g4`) that also run it over the logs a server redacted itself.
- Run against 4.4, 5.0, 6.0, 7.0 and 8.0 while developing; it found real gaps the synthetic fixtures missed (shard-key `splitPoint`, internal `config.cache.chunks.<ns>` namespaces, index names in specs, `dropIndexes.index`, short host names in `event`/`server`, field-name collisions dropping fields).

## Known limits

- The default policy mirrors the server, so inside a command **everything** is masked, including `limit`, `batchSize`, `maxTimeMS`, `writeConcern`, `ordered`, the collection name and `$db`. Analysis of query shapes therefore relies on the plan summary, counters and durations outside the command, and on field names and operators, which are kept.
- Outside client data, a value is redacted when its key is an identity / host / secret-type name, an `--addFields` / schema field, or when its content looks like PII (email, card, SSN, IP, host, token, path ...). A value that is neither (for example `{"nickname2": "free text"}` in a custom attribute `attr.myStuff`) stays: name the field with `--addFields` / `--loadSchemaFile`.
- Bare numbers (e.g. a 9-digit SSN stored as a string) outside client data are only detected by key name or by a comparison with a PII field reference, not by shape.
- `###` replaces every name, so distinct names are indistinguishable; use `--redactNamespaces` (with `--seed`) for correlatable database / collection tokens.
- Names are replaced in free text only when learned from a keyed field (`--single_pass` makes this order-dependent).
- `--ftdc_redact` only rewrites `hostInfo` in type-0 chunks. The compressed reference document of type-1 chunks (`replSetGetStatus` member hostnames, `serverStatus.host`, ...) is passed through unchanged.
- Schema `paths` are contiguous suffixes (`customer.vipCode` does not match `customer.items.$[e].vipCode`); use a bare name in `fields` for any depth.
- Always review the output manually before sharing externally.

---

## Benchmark results

> Historical: measured with an earlier version, run as `--pii --addFields '$comment,_tid,recordId,tenant' --seed ... --char_replacement --redactNamespaces`. Those behaviours are the default policy now (and stricter); replacements are `###` instead of names unless `--char_replacement` is given.

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

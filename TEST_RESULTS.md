# ofuscator.py - Test Results

Results of the PII-leak review of `ofuscator.py` against the mongod / mongos
structured log schema
([`docs/logging.md`](https://github.com/mongodb/mongo/blob/master/docs/logging.md):
`t`, `s`, `c`, `ctx`, `id`, `msg`, `attr`, `tags`, `truncated`, `size`).

| Suite | File | Tests | Result |
|-------|------|------:|--------|
| Unit / synthetic corpus | `test_ofuscator.py` | 63 | **63 / 63 pass** |
| Real cluster (`m` + `mtools`), MongoDB 4.4.29 | `test_integration_mongo.py` | 32 (+4 ground-truth skipped) | **32 / 32 pass** |
| Real cluster, MongoDB 5.0.31 | `test_integration_mongo.py` | 32 (+4 skipped) | **32 / 32 pass** |
| Real cluster, MongoDB 6.0.29 | `test_integration_mongo.py` | 32 (+4 skipped) | **32 / 32 pass** |
| Real cluster, MongoDB 7.0.43 | `test_integration_mongo.py` | 32 (+4 skipped) | **32 / 32 pass** |
| Real cluster, MongoDB 8.0.32 | `test_integration_mongo.py` | 32 (+4 skipped) | **32 / 32 pass** |
| Real cluster + **ground truth** vs an enterprise server redacting its own logs, 5.0.31-ent | `test_integration_mongo.py --ground-truth` | 36 | **36 / 36 pass** |
| Real cluster + ground truth, 7.0.17-ent | `test_integration_mongo.py --ground-truth` | 36 | **36 / 36 pass** |
| Real cluster + ground truth, 8.0.17-ent | `test_integration_mongo.py --ground-truth` | 36 | **36 / 36 pass** |

Run date: 2026-10-07. Environment: macOS 26.7.1 arm64 (pre-6.0 servers run
under Rosetta), Python 3.9.6, pymongo 4.11.1, mtools 1.7.2, `m` 1.9.0.

```bash
python3 test_ofuscator.py -v                     # unit suite, ~3 s
python3 test_integration_mongo.py 5.0            # real cluster, ~2 min
python3 test_integration_mongo.py 5.0.31-ent --ground-truth   # + enterprise server as oracle, ~3 min
```

---

## 1. Before / after the fixes

The same 30-entry synthetic corpus (61 canary values of fake PII) was run
against the original script and the final script. A canary "leaks" when it
appears anywhere in the output.

| Flags | Leaked before | Leaked after |
|-------|--------------:|-------------:|
| default | 45 / 61 | 0 |
| `--pii` | 50 / 61 | 0 (`*`) |
| `--pii --redactNamespaces --char_replacement --seed` | 41 / 61 | 0 (`*`) |

`*` The only canaries that remain under plain `--pii` are the ones placed in
field names that are neither built-in PII keys nor listed in `--addFields`
(documented behaviour; `--strict` removes them, see tests 16/20).

### Breaches found and fixed

| # | Breach | Found by |
|---|--------|----------|
| 1 | Only ~20 hard-coded `attr` paths were redacted: hosts, users, `appName`, `insert.documents`, `deletes`, `errInfo`, shard-key values, startup options, TLS subjects, `msg` were untouched | synthetic corpus |
| 2 | Operator operands (`$in`, `$eq`, `$regex`, `$gt`, `$date`) were copied unredacted | synthetic corpus |
| 3 | PII key matching was case-broken (`FIRSTNAME`, `Phone` never matched) | synthetic corpus |
| 4 | IPv4 regex consumed delimiters (adjacent IPs missed), no IPv6, ran on raw JSON | synthetic corpus |
| 5 | Unsalted MD5 for hashes / namespace tokens (brute-forceable for SSNs, phones, db names) | synthetic corpus |
| 6 | Blank first line downgraded a JSON log to text mode; a malformed line aborted the run and echoed the raw line to stderr | synthetic corpus |
| 7 | No content scanning of free text (emails, cards, JWTs, hostnames, MACs in error text / `msg`) | synthetic corpus |
| 8 | Legacy text logs: unquoted values (`ssn: 123456789`) and `principal <user>` leaked | synthetic corpus |
| 9 | A JSON source could produce non-JSON output lines (fallback / syslog prefix) | review |
| 10 | Shard-key value in sharding logs leaked in **every** mode: `attr.splitPoint` | real logs |
| 11 | Internal namespace `config.cache.chunks.<db>.<coll>` embedded the user namespace | real logs |
| 12 | Index names leaked via `dropIndexes.index`, `firstIndex.name`, `indexes` | real logs |
| 13 | Short hostnames (`<laptop-hostname>:27701` in `event` / `server`) and the OS user were not treated as names | real logs |
| 14 | Learned-name replacement rewrote the static `msg` ("...replication collections" -> "...collection rock.melon") | real logs |
| 15 | Renamed field names could collide (few fruit words, `ab` and `cd` both -> `xx`) and silently **drop fields**, differently per style | real logs (8.0) |
| 16 | Public `www.mongodb.com` documentation links inside static `msg` were rewritten as hostnames | real logs (8.0) |
| 17 | `$project: {email: 1}` / `$group: {_id: 1}` structural `-1/0/1` values were masked in `--pii` | before/after review |
| 18 | Test teardown left a `mongos` running (quiesce period) | real cluster run |
| 19 | Version resolver skipped already-installed versions (`m ls` marks them `* 5.0.31`) | real cluster run |
| 20 | **Server policy S1**: BinData subtype 6 (Encrypt) / 8 (Sensitive) payloads were printed as base64 in filters and any other attr (the 4.4 and 5.0 servers write them in clear; 6.0+ mask them) | server-source review + real logs |
| 21 | **Server policy S2**: booleans, null and `0/1/-1` in payload documents, and booleans under PII keys (`hivStatus: true`), were never erased | server-source review |
| 22 | Not idempotent on already server-redacted input: `find: "###"` became `"loquat"`, hashes of `###` blobs | server-source review |
| 23 | No way to apply the server's own `redactClientLogData` form (BSON level `all`, `CodeName: ###`) | server-source review |
| 24 | `attr.db` as a *document* (`{"_id": "<db name>", "primary": ...}`, "Registering new database") leaked the db name once commands no longer taught it | ground-truth run |
| 25 | Modelling error: `{"$regex", "$options"}` was collapsed to one `"###"`; the server masks each field of that query-operator document | ground truth (real server) |
| 26 | Status with extra info (`ShutdownInProgress{ remainingQuiesceTimeMillis: 0 }: ...`) lost its code name (server keeps `ShutdownInProgress: ###`) | ground truth (real server) |
| 27 | Test harness: ground-truth comparisons were sensitive to shutdown races and server-generated change-stream pipelines | ground-truth runs on 7.0 / 8.0 |
| 28 | `--loadSchemaFile` **path** specs were not applied to aggregation comparisons: `{"$eq": ["$customer.vipCode", "<value>"]}` left the value in clear | new schema unit matrix |
| 29 | Path specs were not applied to free text (`customer.vipCode: <value>`): the error-text pipeline read the dotted name as `db.collection` before the field matcher ran | new schema unit matrix |
| 30 | Field references inside an operand array were not detected, for schema paths **and for built-in PII keys**: `{"$in": ["<value>", ["$customer.vipCode"]]}`, `{"$in": ["<value>", ["$email"]]}` | new schema unit matrix |
| 31 | Test fixture used `payload` as a key, which is a built-in force-redacted payload key (false over-redaction signal); and a precision expectation ignored that a path is contiguous | new schema unit matrix (test bugs) |

---

## 2. Unit suite - `test_ofuscator.py` (63 tests, all pass)

Corpus: 30 logv2 entries modelled on mongod/mongos (slow queries for
find / insert / update / delete / findAndModify / aggregate / getMore, auth,
TLS, client metadata, replication, sharding, index builds, oplog applier,
startup options, change streams, truncated entries), each carrying canary PII.

| # | Test | What it proves | Result |
|--:|------|----------------|:------:|
| 1 | `test_default` | no canary survives with default flags | pass |
| 2 | `test_pii` | ... with `--pii` | pass |
| 3 | `test_pii_seed` | ... with `--pii --seed` | pass |
| 4 | `test_pii_redact_namespaces` | ... with `--pii --redactNamespaces` | pass |
| 5 | `test_default_redact_namespaces` | ... with `--redactNamespaces` only | pass |
| 6 | `test_pii_char_replacement` | ... with `--pii --char_replacement` | pass |
| 7 | `test_everything` | ... with pii + seed + x + redactNamespaces + addFields | pass |
| 8 | `test_strict` | `--strict` also removes values of unlisted fields | pass |
| 9 | `test_strict_full` | `--strict` + seed + x + redactNamespaces | pass |
| 10 | `test_structure_preserved` | `t/s/c/ctx/id/msg/attr`, counters and ids unchanged | pass |
| 11 | `test_deterministic_with_seed` | same seed -> identical output | pass |
| 12 | `test_leading_blank_line_still_json` | blank first line does not downgrade to text mode | pass |
| 13 | `test_malformed_line_is_redacted_not_echoed` | truncated / syslog-prefixed lines: output stays JSON, nothing echoed to stderr | pass |
| 14 | `test_non_dict_json_line` | list / string JSON lines are handled | pass |
| 15 | `test_no_unsalted_md5_of_low_entropy_values` | MD5 of SSN / card / db names never appears | pass |
| 16 | `test_redact_namespaces_tokens_salted` | `REDACTED_<hash>` tokens are HMAC, not MD5 | pass |
| 17 | `test_system_namespaces_preserved` | `local.oplog.rs` kept | pass |
| 18 | `test_parity_default` | x-pattern and fruit styles change exactly the same tokens | pass |
| 19 | `test_parity_pii` | ... with `--pii` | pass |
| 20 | `test_parity_strict` | ... with `--strict` | pass |
| 21 | `test_parity_pii_redact_namespaces` | ... with `--pii --redactNamespaces` | pass |
| 22 | `test_char_fields_selective_keeps_coverage` | `--char_fields` keeps full coverage | pass |
| 23 | `test_legacy_text_log_both_styles` | pre-4.4 text log: no leaks, structure kept | pass |
| 24 | `test_benign_fields_not_corrupted` | `mechanism`, `msg`, oplog `op` are not rewritten by learned names | pass |
| 25 | `test_renamed_keys_never_collide_or_drop_fields` | field count preserved in both styles (fails without the fix) | pass |
| 26 | `test_addfields_still_works` | `--addFields grId` removes a custom field | pass |
| 27 | `ServerPolicyTests.test_s1_bindata_6_and_8_masked_in_every_context` | BinData 6/8 masked in a generic attr, a filter, a CRUD `o`, nested arrays and JSON embedded in a string, in 5 flag sets | pass |
| 28 | `..test_s1_mask_is_the_server_mask_and_replaces_the_whole_element` | the whole `{"$binary": ..}` becomes the string `"###"` (both styles) | pass |
| 29 | `..test_s1_other_subtypes_and_sibling_values_untouched` | like the server's `RedactSensitiveStringTest`: subtypes 0 / 4 and sibling strings stay | pass |
| 30 | `..test_s1_legacy_extended_json_form` | `{"$binary": "..", "$type": "08"}` | pass |
| 31 | `..test_s2_payload_documents_erase_bool_null_and_flag_ints` | bool / null / 0 / 1 / -1 / float / string in `documents` all erased | pass |
| 32 | `..test_s2_query_structure_is_not_erased_but_pii_bool_is` | `$project` flags, `$sort` directions, `$group._id: null` kept; `hivStatus: true` erased | pass |
| 33 | `..test_s2_update_options_are_kept` | `multi` / `upsert` stay booleans under `--strict` | pass |
| 34 | `..test_idempotent_on_server_redacted_logs_every_mode` | a server-redacted entry (`###`, `Unauthorized: ###`, `InternalError ###`) is unchanged in 7 flag sets | pass |
| 35 | `..test_server_redaction_matches_server_unit_tests` | the cases of the server's own `redaction_test.cpp` (`{a:1}`, `{"":1}`, `{a:"a"}`, ...) plus `$regex` operator document | pass |
| 36 | `..test_server_redaction_matches_reference_model` | 6 realistic commands == independent model of `BSONObj::redact(all)` | pass |
| 37 | `..test_server_redaction_schema_keys_are_still_obfuscated` | documented deviation: `sort` / `hint` / `projection` keys are aliased, values `###` | pass |
| 38 | `..test_server_redaction_other_data_attrs_and_oplog_entry` | oplog entry (`bgsync.cpp` `lastOplogEntry`), `keyValue`, `errInfo` | pass |
| 39 | `..test_server_redaction_status_exception_and_what_forms` | `CodeName: ###`, `Code{extra}: ..` -> `Code: ###`, `OK`, plain `what()` -> `###` | pass |
| 40 | `..test_server_redaction_structured_status_keeps_code_drops_reason` | `{code, codeName, errmsg}` -> `errmsg: "###"` | pass |
| 41 | `..test_server_redaction_mask_ignores_char_replacement_and_keeps_other_rules` | `###` in both styles; ns / appName / IP / email still redacted | pass |
| 42 | `..test_server_redaction_canary_corpus_both_styles` | full synthetic corpus: 0 leaks with `--server_redaction` (+ `--redactClientLogData` alias) | pass |
| 43 | `..test_server_redaction_rejected_for_ftdc` | log-only flag rejected in `--ftdc_redact` | pass |
| 44 | `ServerPolicyTests.test_s2_builtin_pii_ref_inside_operand_array` | `{"$in": [<value>, ["$email"]]}` redacts the literal | pass |
| 45 | `SchemaFileTests.test_rule_matrix` | **the rule**: none / schema / addFields / schema+addFields x fruit / x x `--pii` / `--strict` / default mode: requested fields are gone, un-requested ones stay, built-in PII always gone | pass |
| 46 | `..test_path_precision_vendor_not_redacted_by_customer_path` | path `customer.vipCode` redacts customer only, `vendor.vipCode` stays in 6 contexts | pass |
| 47 | `..test_path_is_contiguous_bare_name_matches_any_depth` | `customer.items.$[e].vipCode` is another path; a bare `vipCode` matches at any depth | pass |
| 48 | `..test_path_in_aggregation_field_reference_and_free_text` | `$eq` / `$in` against `$customer.vipCode`, and `customer.vipCode: <v>` in an error message | pass |
| 49 | `..test_flat_schema_field_matches_like_add_fields_everywhere` | `$in` operand, `$set`, `$expr` ref, oplog `o`, JSON string, free text | pass |
| 50 | `..test_style_fruit_vs_x_for_schema_values` | fruit words vs `x-xxxx` pattern | pass |
| 51 | `..test_union_equals_add_fields_with_the_same_names` | schema fields + `--addFields` == one `--addFields` with both lists (byte-identical with a seed) | pass |
| 52 | `..test_deterministic_with_seed` | same seed -> same output | pass |
| 53 | `..test_works_with_server_redaction_and_redact_namespaces` | combines with `--server_redaction --redactNamespaces` | pass |
| 54 | `..test_file_formats` | array shorthand, bare nested, fields-only, paths-only, one-segment path, `false` leaf, meta keys | pass |
| 55 | `..test_case_insensitive_dollar_optional_and_dotted_match` | `$TENANTREF`, `GrId`, `Customer.VIPCODE` | pass |
| 56 | `..test_empty_schema_is_a_noop` | `{}`, `[]`, `{"fields": []}`, `{"paths": []}` change nothing | pass |
| 57 | `..test_legacy_text_log` | the four combinations on a pre-4.4 text log | pass |
| 58 | `..test_rejects_missing_file` | exit 2, one-line error | pass |
| 59 | `..test_rejects_invalid_json` | exit 2, no traceback | pass |
| 60 | `..test_rejects_wrong_types` | nine malformed shapes rejected | pass |
| 61 | `..test_rejects_binary_garbage` | non-UTF-8 file rejected cleanly | pass |
| 62 | `..test_rejected_for_ftdc` | log-only option rejected with `--ftdc_redact` | pass |
| 63 | `..test_schema_file_content_never_echoed_on_error` | a field name in a broken file never appears in stderr | pass |

The parity test was checked with a deliberate mutation (x-mode skipping host
redaction): three tests failed, so it detects coverage drift. The server-policy
tests S1 / S2 / idempotence were run against the implementation *before* the
change: all six failed there and pass now.

---

## 3. Integration suite - real cluster (`m` + `mtools`)

`test_integration_mongo.py <version>`:

1. `m` resolves `X.Y` to the newest patch installable on this platform and
   installs it; the active `m` version is restored (symlinks re-created and
   verified identical afterwards).
2. `mlaunch` starts a minimal **auth-enabled sharded cluster**: 1 shard
   (single-node replica set) + 1 config server + 1 mongos, `slowms=0`.
3. A PII-heavy workload runs through the mongos: CRUD, aggregation
   (`$lookup`, `$out`, `$unionWith`), bad-modifier and validation errors,
   transactions, change streams + resume, index builds, `shardCollection` /
   `split` (`moveChunk` with `--shards 2`), users, failed and successful
   logins, several `appName`s, direct shard connections.
4. The three real logs (mongos, shard mongod, config mongod) are redacted under
   a flag matrix and checked. The cluster is stopped and processes verified gone.
5. With `--ground-truth` and an enterprise build (`5.0.31-ent`), a **second,
   identical cluster** runs the same workload with the server redacting its own
   logs (`redactClientLogData=true`); its output is the oracle for
   `--server_redaction` (section 3c).

### Results per version (community builds)

| Version | Resolved from | Log lines (config / mongos / shard) | Canaries in source logs | BinData 6/8 base64 in the *source* log | Server errors in workload (expected) | Tests | Time |
|---------|---------------|-------------------------------------|:------:|:------:|:--:|:------:|-----:|
| 4.4.29 | `4.4` (4.4.30/.31 have no macOS build) | 493 / 304 / 543 | 62 / 63 | **yes** | 8 | 32 / 32 (+4 skipped) | 74 s |
| 5.0.31 | `5.0` (5.0.32-.34 have no macOS build) | 543 / 558 / 834 | 62 / 63 | **yes** | 7 | 32 / 32 (+4 skipped) | 134 s |
| 6.0.29 | `6.0` | 605 / 554 / 923 | 62 / 63 | no (server masks) | 7 | 32 / 32 (+4 skipped) | 120 s |
| 7.0.43 | `7.0` | 775 / 694 / 1109 | 62 / 63 | no (server masks) | 7 | 32 / 32 (+4 skipped) | 119 s |
| 8.0.32 | `8.0` | 917 / 621 / 1394 | 62 / 63 | no (server masks) | 7 | 32 / 32 (+4 skipped) | 140 s |

The one canary never logged by any version is the admin password
(`Secr3tPassw0rd`): the server does not write it, which is the correct outcome.
After every run: 0 stray server processes, `m` symlinks identical to the
snapshot taken before any install.

### The 32 tests (identical result on all five versions)

| # | Test | What it proves | 4.4 | 5.0 | 6.0 | 7.0 | 8.0 |
|--:|------|----------------|:--:|:--:|:--:|:--:|:--:|
| 1 | `test_00_cluster_and_source_logs` | cluster started, logs are logv2 JSON | pass | pass | pass | pass | pass |
| 2 | `test_01_canaries_actually_reach_the_logs` | the fake PII really reached the logs (test is not vacuous) | pass | pass | pass | pass | pass |
| 3 | `test_10_matrix_default` | no canary / source IP / hostname / OS user; valid logv2; `t,s,c,id` and top-level attr keys unchanged | pass | pass | pass | pass | pass |
| 4 | `test_11_matrix_pii` | same, `--pii` | pass | pass | pass | pass | pass |
| 5 | `test_12_matrix_pii_seed` | same, `--pii --seed` | pass | pass | pass | pass | pass |
| 6 | `test_13_matrix_pii_redactns` | same, `--pii --redactNamespaces` | pass | pass | pass | pass | pass |
| 7 | `test_14_matrix_pii_x` | same, `--pii --char_replacement` | pass | pass | pass | pass | pass |
| 8 | `test_15_matrix_everything` | same, every option combined incl. `--addFields` | pass | pass | pass | pass | pass |
| 9 | `test_16_matrix_strict` | same, `--strict` (also unlisted fields) | pass | pass | pass | pass | pass |
| 10 | `test_17_matrix_strict_x_redactns` | same, `--strict --char_replacement --redactNamespaces` | pass | pass | pass | pass | pass |
| 11 | `test_18_matrix_single_pass` | `--single_pass` (names exempt by design, PII values not) | pass | pass | pass | pass | pass |
| 12 | `test_18b_matrix_server_redaction` | same leak matrix with `--server_redaction` | pass | pass | pass | pass | pass |
| 13 | `test_18c_matrix_server_redaction_x` | `--server_redaction --char_replacement --redactNamespaces --seed` | pass | pass | pass | pass | pass |
| 14 | `test_19_addfields_removes_custom_field_in_filters` | `--addFields grId` removes a custom field | pass | pass | pass | pass | pass |
| 15 | `test_20_strict_removes_unlisted_values` | `--strict` removes unlisted filter values; plain `--pii` keeps them (documented) | pass | pass | pass | pass | pass |
| 16 | `test_30_shape_oracle_x_mode` | independent scan of every string: no email / SSN / Luhn card / JWT / raw IP shape in x mode | pass | pass | pass | pass | pass |
| 17 | `test_31_shape_oracle_word_mode` | word mode: only `fruit@colour.com` emails, no SSN / JWT | pass | pass | pass | pass | pass |
| 18 | `test_40_parity_default` | fruit vs x style change exactly the same tokens (real logs) | pass | pass | pass | pass | pass |
| 19 | `test_41_parity_pii` | ... with `--pii` | pass | pass | pass | pass | pass |
| 20 | `test_42_parity_strict_redactns` | ... with `--strict --redactNamespaces` | pass | pass | pass | pass | pass |
| 21 | `test_50_redacted_logs_remain_parseable` | every line validates against logv2 (mtools 1.7.2 cannot parse 4.4+ JSON logs, so the built-in validator is used) | pass | pass | pass | pass | pass |
| 22 | `test_51_operational_metrics_preserved` | durations / counters kept; `(c, id, msg)` histogram identical | pass | pass | pass | pass | pass |
| 23 | `test_52_system_namespaces_and_loopback_kept` | `config.*`, `admin.$cmd`, 127.0.0.1 kept; `config.cache.chunks.<user ns>` redacted | pass | pass | pass | pass | pass |
| 24 | `test_53_bindata_6_and_8_masked_by_default_in_every_mode` | BinData 6/8 base64 (which the 4.4 / 5.0 servers print) absent in 5 flag sets | pass | pass | pass | pass | pass |
| 25 | `test_54_server_redaction_equals_reference_model_on_real_logs` | every real `command` / `originatingCommand` == the model of `BSONObj::redact(all)` | pass | pass | pass | pass | pass |
| 26 | `test_55_server_redaction_status_forms_and_fixpoint` | every status attr is `CodeName: ###` / `###` / `{errmsg:###}`; second pass is a fixpoint on client data | pass | pass | pass | pass | pass |
| 27 | `test_56_schema_file_and_add_fields_combinations` | the four option combinations x fruit / x x `--pii` (+ `--redactNamespaces --seed`) on the real mongos / shard / config logs: requested canaries gone, un-requested stay, built-in PII gone | pass | pass | pass | pass | pass |
| 28 | `test_57_schema_file_with_strict_and_server_redaction_is_additive` | schema + `--addFields` on top of `--strict` / `--server_redaction` | pass | pass | pass | pass | pass |
| 29 | `test_60_seed_determinism_and_salting` | same seed -> same output; unseeded tokens differ per run | pass | pass | pass | pass | pass |
| 30 | `test_61_no_unsalted_md5_of_sensitive_values` | no MD5 of any canary / name appears | pass | pass | pass | pass | pass |
| 31 | `test_62_idempotent_and_still_json_on_second_pass` | redacting the redacted log works and stays JSON | pass | pass | pass | pass | pass |
| 32 | `test_63_damaged_real_log_fails_closed_and_stays_json` | blank first line, truncated and syslog-prefixed lines: still JSON, no leak | pass | pass | pass | pass | pass |

---

## 3b. Server-side redaction policy (what the MongoDB server itself does)

Read from the server source: `logv2/redaction.cpp`, `logv2/log_util.cpp`,
enterprise `encryptdb/log_redact_options.cpp`, `db/repl/bgsync.cpp`, and the nested
calls `logv2/redaction.h`, `logv2/logv2_options.{idl,cpp}`, `bson/bsonobj.cpp`
(`BSONObj::redact`), `bson/bsonelement.cpp`, `bson/bsontypes.h` and the server's own
`logv2/redaction_test.cpp`.

| # | Server policy | Source | Covered before | Now |
|---|---------------|--------|----------------|-----|
| S0 | Mask is the constant `"###"`; field names and structure are kept | `redaction.cpp` `kRedactionDefaultMask` | different mask (fruit / x) | `###` in `--server_redaction`; names / x-pattern elsewhere |
| S1 | BinData subtype **6 (Encrypt)** and **8 (Sensitive)** -> `"###"` at any depth, even with `redactClientLogData` off (`redactBinDataEncrypt` defaults to **true**; subtype 8 unconditionally) | `log_util.cpp`, `bsonobj.cpp` `encryptedAndSensitive` / `sensitiveOnly` | **No** (base64 leaked in filters / generic attrs) | **Always on**, every mode, every context, both EJSON forms |
| S2 | `redactClientLogData=true` -> BSON level `all`: every scalar of ANY type (string, number, bool, null, date, oid, bindata) -> `"###"`; arrays walked | `redaction.cpp`, `log_redact_options.cpp`, `bsonobj.cpp` `RedactLevel::all` | partly (bool / null / `0,1,-1` survived in payloads and under PII keys) | type erasure always on for payload documents and PII-key booleans; **`--server_redaction`** = exact level `all` |
| S3 | `redact(Status)` -> `CodeName: ###` (`OK` stays), `redact(DBException)` -> `CodeName ###`, `redact(e.what())` -> `###` | `redaction.cpp`, `bgsync.cpp` lines 232 / 237 / 541 / 592 / 686 / 922 | reason text kept (heuristic masking) | `--server_redaction` reproduces the forms |
| S4 | Scope: only call sites wrapped in `redact()` (errors, exception text, BSON docs such as `lastOplogEntry`); hosts, namespaces, `syncSource` and five other `error` attrs in the same file are not | `bgsync.cpp` | we were already stricter | unchanged: every other rule of this tool still applies on top |
| S5 | Logs already redacted by the server must survive a second pass | - | **No** (`find: "###"` -> `"loquat"`) | idempotent on `###`, `CodeName: ###`, `CodeName ###`, `OK` |

Deliberate deviations (documented in the README): the keys of `sort` / `hint` /
`projection` / `fields` (index and field names, which the server leaves visible)
are always obfuscated; `-1 / 0 / 1` and booleans are kept under `$project` / `$sort` /
`$group` / update options in non-payload queries.

Examples (`--pii`, word style unless noted; real outputs of the final script):

| Policy | Input | Output |
|--------|-------|--------|
| S1 | `{"a": {"$binary": {"base64": "Y2lwaGVy...", "subType": "06"}}, "b": {... "subType": "08"}, "c": {... "subType": "00"}}` | `{"a": "###", "b": "###", "c": {"$binary": {... "subType": "00"}}}` (subtype 0 kept) |
| S2 | payload `{"optedOut": false, "hivStatus": true, "n": null}` | `{"optedOut": "###", "hivStatus": "###", "n": "###"}` |
| S2 | `$project: {"email": 1, "phone": true}`, `$sort: {"createdAt": -1}` | unchanged (structure) |
| S2 `--server_redaction` | `{"find":"c","filter":{"email":"a@b.com","age":{"$gt":18},"tags":["a","b"],"_id":{"$oid":"6ac6..."}},"$db":"acmeshopdb"}` | `{"find":"###","filter":{"email":"###","age":{"$gt":"###"},"tags":["###","###"],"_id":"###"},"$db":"###"}` |
| S3 `--server_redaction` | `Unauthorized: not authorized on acmeshopdb to execute command { find: "c" }` | `Unauthorized: ###` |
| S3 `--server_redaction` | `ShutdownInProgress{ remainingQuiesceTimeMillis: 0 }: Replication is being shut down; ...` | `ShutdownInProgress: ###` |
| S3 `--server_redaction` | `{"code":13,"codeName":"Unauthorized","errmsg":"not authorized on ..."}` | `{"code":13,"codeName":"Unauthorized","errmsg":"###"}` |
| S5 | `{"command":{"find":"###","filter":{"a":"###"}},"error":"Unauthorized: ###"}` | identical, in all 7 flag sets tested |

**The server masks BinData 6/8 only from 6.0 on.** Measured on the real servers of
this suite (`test_53`): the base64 of both payloads is present in the 4.4.29 and
5.0.31 logs and absent from 6.0.29, 7.0.43 and 8.0.32. Logs from older servers
therefore still carry ciphertext unless the tool masks it; it now does, for every
source version.

## 3c. Ground truth: an enterprise server redacting its own logs

`--ground-truth` runs a second, identical cluster on an **enterprise** build with
`setParameter redactClientLogData=true` on the mongos, the shard and the config
server, and compares the server's own redacted logs with `--server_redaction` applied
to the unredacted logs of the first cluster.

| Test | What it proves |
|------|----------------|
| `test_g0_server_really_redacts_and_what_it_leaves_visible` | the oracle works (>200 `"###"`, no email / SSN / card / IBAN / token) and shows what the SERVER leaves visible: `acmeshopdb`, `customer_profiles`, `AcmeBillingService`, `acme_root_user`, `mary.watson`, `jsmith_admin`, hostnames |
| `test_g1_our_command_masks_equal_the_servers_masks` | **every** distinct redacted command of the user ops (same `appName`) is identical in the server's log and in ours |
| `test_g2_status_forms_match_where_the_server_masks_and_we_are_never_weaker` | where the server masks a Status we produce the same form; everywhere else we mask too |
| `test_g3_idempotent_on_server_redacted_logs_and_stricter_elsewhere` | ofuscator on the server-redacted log keeps every `"###"`, removes the names the server left visible, and equals the reference model applied to the server's line |

| Enterprise build | Tests | Distinct server-redacted commands identical to ours (config / mongos / shard) | Status attrs compared | server masked and we match | server left the reason **in clear** (we mask) |
|------------------|:-----:|-----------------------------------------------|:--:|:--:|:--:|
| 5.0.31-ent | 36 / 36 | 26 / 67 / 77 (44 / 98 / 88 log lines) | 38 | 11 | 27 |
| 7.0.17-ent | 36 / 36 | 18 / 67 / 78 (34 / 98 / 89 log lines) | 40 | 11 | 29 |
| 8.0.17-ent | 36 / 36 | 18 / 67 / 81 (39 / 98 / 95 log lines) | 42 | 12 | 30 |

What the real servers showed (and the tests now encode):

- `redactClientLogData=true` masks **every** scalar of `attr.command`, including the
  collection name (`insert: "###"`), `$db`, `writeConcern.w`, `lsid`, `$clusterTime`
  (an EJSON wrapper is one scalar) and arrays (`shardVersion: ["###","###"]`).
- The server does **not** redact statuses globally: `Checking authorization failed`
  still prints `not authorized on acmeshopdb to execute command {`, and other attrs print
  `Error connecting to localhost:27701 (127.0.0.1:27701)`, `Connection reset by peer`,
  `Collection config.system.sessions is not sharded`. Only wrapped call sites give
  `UserNotFound: ###` / `errMsg: "###"`.
- 7.0 / 8.0 enterprise log an internal `createIndexes` command (collection and index
  keys) **in clear** even with redaction on; we mask it.
- The commands that ran before `redactClientLogData` was switched on (`profile`,
  `setParameter`) are logged in clear by the server; the tests skip that window.
- `redactEncryptedFields` does not exist as a parameter on 5.0 (BinData default
  masking arrived later) - consistent with the BinData measurement above.
- Model errors the real server exposed and fixed: `{"$regex": .., "$options": ..}` is a
  query-operator document (masked field by field, not one scalar); `Code{ extra }: reason`
  is reduced to `Code: ###`; `attr.db` can be a document whose `_id` is the db name.

---

## 3d. `--loadSchemaFile` x `--addFields`

Rule under test: **none -> default; `--loadSchemaFile` -> default + schema; `--addFields` -> default + fields;
both -> default + schema + fields.** Fixture (`SCHEMA_DOC`): `fields: [tenantRef]`, `paths: [customer.vipCode]`,
`schema: {loyalty: {tier: true}}`; `--addFields grId`. Five canaries: built-in PII (`email`), `grId` (only
`--addFields`), `tenantRef` / `customer.vipCode` / `loyalty.tier` (only the schema file), plus two that must
**stay visible**: `vendor.vipCode` (a different path) and `customer.items.$[e].vipCode` (not contiguous).

| Options | email (default) | grId | tenantRef | customer.vipCode | loyalty.tier | vendor.vipCode |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|
| none | gone | **visible** | **visible** | **visible** | **visible** | visible |
| `--loadSchemaFile` | gone | **visible** | gone | gone | gone | visible |
| `--addFields grId` | gone | gone | **visible** | **visible** | **visible** | visible |
| both | gone | gone | gone | gone | gone | visible |

The table is asserted (not only documented) for fruit and x style, in `--pii` and `--strict` mode on a nine-context
corpus (generic attr, filter with dotted keys, `$in` operand, `$elemMatch`, array of sub-documents, `$set` on dotted /
positional paths, `$expr` field references, oplog `o`, JSON serialised in a string, free text), and again on the
real mongos / shard / config logs of every version (`test_56`: 4 combinations x 2 styles x 2 modes; `test_57`: on top
of `--strict` and `--server_redaction`). Result: **all pass** on 4.4, 5.0, 6.0, 7.0, 8.0 and on the three enterprise builds.

Breaches found while writing the tests (all fixed, see section 1, #28-#31): dotted schema paths were not applied to
`$eq` / `$in` comparisons against `"$customer.vipCode"` nor to free text, and field references inside an operand
array were missed, for schema paths and also for the built-in PII keys (`{"$in": [<value>, ["$email"]]}`).

Examples (same input line, `--pii --seed s`):

| Options | `filter` |
|---------|----------|
| none | `{"email": "ugli.fruit@aliceblue.com", "grId": "G-1001", "tenantRef": "T-77", "customer.vipCode": "VIP-9", "vendor.vipCode": "V-5", "loyalty": {"tier": "gold"}}` |
| `--loadSchemaFile` | `{"email": "coconut@palegreen.com", "grId": "G-1001", "tenantRef": "melon", "customer.vipCode": "apple", "vendor.vipCode": "V-5", "loyalty": {"tier": "ugli.fruit"}}` |
| `--addFields grId` | `{"email": "ugli.fruit@aliceblue.com", "grId": "coconut", "tenantRef": "T-77", "customer.vipCode": "VIP-9", "vendor.vipCode": "V-5", "loyalty": {"tier": "gold"}}` |
| both | `{"email": "coconut@palegreen.com", "grId": "melon", "tenantRef": "physalis", "customer.vipCode": "apple", "vendor.vipCode": "V-5", "loyalty": {"tier": "ugli.fruit"}}` |
| both, `--char_replacement` | `{"email": "xxxxx@xxxx.xxx", "grId": "x-xxxx", "tenantRef": "x-xx", "customer.vipCode": "xxx-x", "vendor.vipCode": "V-5", "loyalty": {"tier": "xxxx"}}` |

Validation (exit code 2, one line, no traceback, content never echoed): missing file, invalid JSON, `"fields": "grId"`,
empty names, `"paths": ["a.b", 5]`, `"paths": ["..."]`, `"schema": {"a": 5}`, `"schema": ["a"]`, a JSON string / number
at top level, binary garbage; rejected together with `--ftdc_redact`.

---

## 4. One real line per test, before and after (MongoDB 5.0.31, x replacement)

Each row is a real log line redacted with `--char_replacement` plus the flags of
that test. Only relevant fields are shown; `...` marks shortened values.

| Test | Flags (+ `--char_replacement`) | Before | After |
|------|-------------------------------|--------|-------|
| 00 | default | `keyFile: "/tmp/ofuscator_it_XXXX/cluster/keyfile"`, `configDB: "configRepl/localhost:27702"` | `"/xxx/xxxxxxx/x_/xxxxxxxx.../xxxxxxx"`, `"xxxxxxxxxx/xxxxxxxxx:xxxxx"` |
| 01 | default | `ns: "acmeshopdb.customer_profiles"`, `appName: "AcmeBillingService"`, `filter: {"email":"alice.smith@acme-corp.com"}` | `"xxxxxxxxxx.xxxxxxxx_xxxxxxxx"`, `"xxxxxxxxxxxxxxxxxx"`, `"{\"xxxxx\": \"xxxxx.xxxxx@xxxx-xxxx.xxx\"}"` |
| 10 | default | same line | filter replaced as one blob (as 01) |
| 11 | `--pii` | `filter: {"email":"alice.smith@acme-corp.com"}` | `{"email": "xxxxx.xxxxx@xxxx-xxxx.xxx"}` (structure kept) |
| 12 | `--pii --seed it-seed` | `documents:[{"_id":"C-dup-canary-0001","name":"Alice Smith","phone":"+1-555-010-9999","identity":{"ssn":"123-45-6789"...` | `{"_id":"x-xxx-xxxxxx-xxxx","name":"xxxxx xxxxx","phone":"+x-xxx-xxx-xxxx","identity":{"ssn":"xxx-xx-xxxx"...` |
| 13 | `--pii --redactNamespaces` | `ns: "acmeshopdb.customer_profiles"`, `find: "customer_profiles"`, `$db: "acmeshopdb"` | `"REDACTED_9fb2ea45.REDACTED_15c3e987"`, `"REDACTED_15c3e987"`, `"REDACTED_9fb2ea45"` |
| 14 | `--pii` | `principalName: "mary.watson"`, `error: "UserNotFound: User \"mary.watson@admin\" not found"` | `"xxxx.xxxxxx"`, `"UserNotFound: User \"xxxx.xxxxxx@xxxxx\" not found"`; `authenticationDatabase: "admin"` and `remote: 127.0.0.1` kept |
| 15 | `--pii --seed --redactNamespaces --addFields` | `errmsg: "not authorized on acmeshopdb to execute command { insert: \"customer_profiles\", ... UUID(\"bdfedbbb-...\")..."` | `"xxx xxxxxxxxxx xx xxxxxxxxxx xx xxxxxxx xxxxxxx { xxxxxx: \"xxxxxxxx_xxxxxxxx\", ... xx: xxxx(\"xxxxxxxx-xxxx-...\")..."` |
| 16 | `--strict` | `filter: {"unlistedField":"filter-unlisted-canary-9"}` | `{"unlistedField":"xxxxxx-xxxxxxxx-xxxxxx-x"}` |
| 17 | `--strict --redactNamespaces --seed k` | `splitPoint:{"customerId":"chunk-split-canary-5000"}`, `namespace:"acmeshopdb.customer_profiles"`, `shardId:"shard1"` | `{"customerId":"xxxxx-xxxxx-xxxxxx-xxxx"}`, `"REDACTED_0bf62d8a.REDACTED_a400b7a1"`, `"xxxxxx"`; `MinKey`/`MaxKey` kept |
| 18 | `--pii --single_pass` | `application.name:"AcmeBillingService"`, `driver:"PyMongo\|c"`, `os:"Darwin"` | name -> `"xxxxxxxxxxxxxxxxxx"`; driver and OS kept |
| 19 | `--pii --addFields grId` | documents with `email`, `address`, `ssn`, `creditCard "4111 1111 1111 1111"`, `grId` | all values x'd, e.g. `"xxxx xxxx xxxx xxxx"` |
| 20 | `--strict` | `unlistedField: "filter-unlisted-canary-9"` | `"xxxxxx-xxxxxxxx-xxxxxx-x"` |
| 30 | `--strict` | documents with email, SSN, card, IBAN, MAC | `"xxx-xxx-xxxxxx@xxxx-xxxx.xxx"`, `"xxx-xx-xxxx"`, `"xxxx xxxx xxxx xxxx"`, ... |
| 31 | `--strict` | `filter:{"email":"alice.smith@acme-corp.com"}` | `{"email":"xxxxx.xxxxx@xxxx-xxxx.xxx"}` |
| 40 | default | `pipeline:[{"$match":{"identity.ssn":"123-45-6789"}},{"$group":{"_id":1,"n":{"$sum":1}}}]` | one blob string `"[{\"$xxxxx\": {\"xxxxxxxx.xxx\": \"xxx-xx-xxxx\"}}, ...]"`; `lsid.id.$uuid` x'd |
| 41 | `--pii` | same pipeline | `[{"$match":{"identity.ssn":"xxx-xx-xxxx"}},{"$group":{"_id":1,"n":{"$sum":1}}}]` |
| 42 | `--strict --redactNamespaces` | same pipeline | ns -> `REDACTED_...`, SSN -> `"xxx-xx-xxxx"`, `"_id":1` and `"$sum":1` kept |
| 50 | `--pii` | full "Authentication succeeded" line, `principalName:"acme_root_user"` | `"xxxx_xxxx_xxxx"`; `t/s/c/ctx/id/msg/attr` and `mechanism` untouched |
| 51 | `--pii` | `durationMillis 0, nreturned 0, keysExamined 0, docsExamined 0, planSummary "COLLSCAN"` | identical (operational data preserved) |
| 52 | `--pii --redactNamespaces` | `ns:"config.databases"`, `appName:"AcmeBillingService"`, `remote:"127.0.0.1:56795"`, `query:{"_id":"acmeshopdb"}` | `ns` kept, `appName:"xxxxxxxxxxxxxxxxxx"`, `remote` kept, `{"_id":"xxxxxxxxxx"}` |
| 60 | `--pii --seed abc` | `principalName:"acme_root_user"` | `"xxxx_xxxx_xxxx"` |
| 61 | `--pii` | `$match:{"tenant":"tenant-canary-acme-42"}`, `$project:{"email":1,"phone":1}`, `$out:"customer_profiles_archive"` | `"xxxxxx-xxxxxx-xxxx-xx"`, `$project` flags kept as `1`, `$out:"xxxxxxxx_xxxxxxxx_xxxxxxx"` |
| 62 | `--pii` | `u:{"$set":{"phone":"555-010-9999"}}`, `q:{"orderNo":"txn-canary-order-7781"}` | `"xxx-xxx-xxxx"`; **`orderNo` unchanged** (unlisted field in a filter, see limits) |
| 63 | `--pii` | a truncated JSON line; `Oct 7 host mongos[1]: {...}` | `{"s":"W","c":"REDACTOR","ctx":"ofuscator","id":0,"msg":"Unparseable log line redacted","attr":{"lineNumber":2,"line":"{\"x\":{\"$xxxx\":..."}}`; the syslog-prefixed line becomes a normal JSON entry |

---

## 5. Observations and known limits

- **Unlisted field names in filters.** Plain `--pii` keeps values of field
  names that are neither built-in PII keys nor in `--addFields` when they sit
  in a *filter / update / pipeline* (test 62: `orderNo`). Payload documents
  (`insert.documents`, oplog `o` / `o2`, `errInfo`, shard-key bounds, ...) are
  always fully redacted with `--pii`. Use `--strict` to redact every literal.
- **Bare system collection names.** `ns: "config.databases"` is kept, but the
  same name as a lone command argument (`findAndModify: "databases"`) is
  redacted with `--redactNamespaces`, because a single name has no database
  context. Harmless but inconsistent (test 52).
- **Server redaction is a subset of this tool.** With `--server_redaction` the client-data attributes equal the server's output, but names, hosts, users, apps, IPs and infrastructure text (which the server leaves visible) are still redacted by the rest of the tool. The deliberate deviations are listed in section 3b.
- **Schema paths are contiguous.** `customer.vipCode` does not match `customer.items.$[e].vipCode`; use the bare name `vipCode` in `fields` to match at any depth. Paths are matched on keys (and `$ref` / `path: value` text); a value that merely *contains* the field name in prose is not detected.
- **Hash salt.** Hashes and `REDACTED_<hash>` tokens are keyed with `--seed`
  (random per-run key without a seed). Tokens correlate across files only with
  the same seed.
- **mtools 1.7.2** cannot parse 4.4+ JSON logs (no datetime even for the original
  log), so it is used only to start the cluster; a built-in logv2 validator does
  the parse check. On legacy text logs `mloginfo` is used as the oracle.
- **Duplicate-key error text** is not written by 4.4-8.0 to the log (write
  errors are returned to the client); the command itself is logged and is
  covered. The error-text masker is covered by the "not authorized on ..." line
  (test 15) and the unit corpus.
- **FTDC**: `--ftdc_redact` only rewrites `hostInfo` of type-0 chunks; the
  compressed reference document of type-1 chunks (e.g. `replSetGetStatus` member
  hostnames) is passed through unchanged. Not covered by these tests.
- **Disk side effect**: versions downloaded by `m` for the integration run stay
  installed (`m rm <version>` to remove).

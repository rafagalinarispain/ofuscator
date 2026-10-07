# ofuscator.py - Test Results

Results of the PII-leak review of `ofuscator.py` against the mongod / mongos
structured log schema
([`docs/logging.md`](https://github.com/mongodb/mongo/blob/master/docs/logging.md):
`t`, `s`, `c`, `ctx`, `id`, `msg`, `attr`, `tags`, `truncated`, `size`).

**Policy under test.** With no options the tool applies the server-style policy to client data
(every literal `###`, keys and structure kept, BinData 6/8 masked, Status `CodeName: ###`) plus
redaction of hosts, IPs, users, apps, namespaces, secrets and PII shapes in every string.
`--pii`, `--strict` and `--server_redaction` are not options any more: they are the default.

| Suite | File | Tests | Result |
|-------|------|------:|--------|
| Unit / synthetic corpus | `test_ofuscator.py` | 62 | **62 / 62 pass** |
| Real cluster (`m` + `mtools`), MongoDB 4.4.29 | `test_integration_mongo.py` | 28 (+4 ground-truth skipped) | **28 / 28 pass** |
| Real cluster, MongoDB 5.0.31 | `test_integration_mongo.py` | 28 (+4 skipped) | **28 / 28 pass** |
| Real cluster, MongoDB 6.0.29 | `test_integration_mongo.py` | 28 (+4 skipped) | **28 / 28 pass** |
| Real cluster, MongoDB 7.0.43 | `test_integration_mongo.py` | 28 (+4 skipped) | **28 / 28 pass** |
| Real cluster, MongoDB 8.0.32 | `test_integration_mongo.py` | 28 (+4 skipped) | **28 / 28 pass** |
| Real cluster + **ground truth** vs an enterprise server redacting its own logs, 5.0.31-ent | `test_integration_mongo.py --ground-truth` | 32 | **32 / 32 pass** |
| Real cluster + ground truth, 7.0.17-ent | `test_integration_mongo.py --ground-truth` | 32 | **32 / 32 pass** |
| Real cluster + ground truth, 8.0.17-ent | `test_integration_mongo.py --ground-truth` | 32 | **32 / 32 pass** |

Run date: 2026-10-07. Environment: macOS 26.7.1 arm64 (pre-6.0 servers run
under Rosetta), Python 3.9.6, pymongo 4.11.1, mtools 1.7.2, `m` 1.9.0.

```bash
python3 test_ofuscator.py -v                     # unit suite, ~10 s
python3 test_integration_mongo.py 5.0            # real cluster, ~2 min
python3 test_integration_mongo.py 5.0.31-ent --ground-truth   # + enterprise server as the reference, ~3 min
```

---

## 1. Before / after the fixes

The same 30-entry synthetic corpus (61 canary values of fake PII) was run against the
original script and the final script. A canary "leaks" when it appears anywhere in the output.
(The "before" runs used the options of that time; today's default is stricter than all of them.)

| Run | Leaked before | Leaked after |
|-----|--------------:|-------------:|
| original script, default | 45 / 61 | 0 |
| original script `--pii` | 50 / 61 | 0 |
| original script `--pii --redactNamespaces --char_replacement --seed` | 41 / 61 | 0 |
| final script, default (includes the values of unlisted fields) | - | 0 / 61 |

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
| 32 | **Policy change**: deep PII walk, every-literal redaction and the server's own `redactClientLogData` rules were options (`--pii`, `--strict`, `--server_redaction`); they are now the DEFAULT, the flags are hidden no-ops | requirement |
| 33 | Fruit / colour words came from a **shared random stream**: with the same `--seed` a name could map to different words in different files, and adding any option shifted later words (README promised consistency across files) | real-log test (`test_57`) |
| 34 | Comparisons against an `--addFields` field or a built-in PII key outside client data (`{"$eq": ["$grId", <v>]}`, `{"$eq": ["$email", <v>]}`) left the literal in clear | new unit matrix |
| 35 | Test assumptions encoded the old default (system namespaces expected inside command bodies, "unlisted values survive plain `--pii`") | full regression |

---

## 2. Unit suite - `test_ofuscator.py` (62 tests, all pass)

Corpus: 30 logv2 entries modelled on mongod/mongos (slow queries for find / insert / update / delete /
findAndModify / aggregate / getMore, auth, TLS, client metadata, replication, sharding, index builds, oplog applier,
startup options, change streams, truncated entries), each carrying canary PII; plus server-policy and
schema-file corpora.

| # | Test | What it proves | Result |
|--:|------|----------------|:------:|
| 1 | `LeakTests.test_default` | DEFAULT policy: none of the 61 canaries survives, **including values of unlisted field names** (used to need `--strict`) | pass |
| 2 | `LeakTests.test_seed` | ... with `--seed` | pass |
| 3 | `LeakTests.test_redact_namespaces` | ... with `--redactNamespaces` | pass |
| 4 | `LeakTests.test_char_replacement` | ... with `--char_replacement` | pass |
| 5 | `LeakTests.test_single_pass` | ... with `--single_pass` | pass |
| 6 | `LeakTests.test_everything` | ... with seed + x-pattern + redactNamespaces + addFields | pass |
| 7 | `LeakTests.test_deprecated_flags_are_accepted_and_ignored` | `--pii`, `--strict`, `--server_redaction`, `--redactClientLogData` (and all three together): same output as the default, hidden from `--help`, exactly one stderr note | pass |
| 8 | `LeakTests.test_structure_preserved` | `t/s/c/ctx/id/msg/attr` and counters unchanged; `command.limit` is `###` (server masks it); operators kept | pass |
| 9 | `LeakTests.test_deterministic_with_seed` | same seed -> identical output | pass |
| 10 | `LeakTests.test_leading_blank_line_still_json` | blank first line does not downgrade to text mode | pass |
| 11 | `LeakTests.test_malformed_line_is_redacted_not_echoed` | truncated / syslog-prefixed lines: output stays JSON, nothing echoed to stderr | pass |
| 12 | `LeakTests.test_non_dict_json_line` | list / string JSON lines are handled | pass |
| 13 | `LeakTests.test_no_unsalted_md5_of_low_entropy_values` | MD5 of SSN / card / db names never appears | pass |
| 14 | `LeakTests.test_redact_namespaces_tokens_salted` | `REDACTED_<hash>` tokens are HMAC, not MD5 | pass |
| 15 | `LeakTests.test_system_namespaces_preserved` | `local.oplog.rs` kept | pass |
| 16 | `LeakTests.test_parity_default` | x-pattern and fruit styles change exactly the same tokens | pass |
| 17 | `LeakTests.test_parity_redact_namespaces` | ... with `--redactNamespaces` | pass |
| 18 | `LeakTests.test_char_fields_selective_keeps_coverage` | `--char_fields` keeps full coverage | pass |
| 19 | `LeakTests.test_legacy_text_log_both_styles` | pre-4.4 text log: no leaks, structure kept | pass |
| 20 | `LeakTests.test_benign_fields_not_corrupted` | `mechanism`, `msg` are not rewritten by learned names; oplog entry keys kept, `op` masked like the server | pass |
| 21 | `LeakTests.test_renamed_keys_never_collide_or_drop_fields` | field count preserved in both styles (fails without the fix) | pass |
| 22 | `LeakTests.test_addfields_still_works` | `--addFields grId` removes a custom field | pass |
| 23 | `LeakTests.test_seed_gives_the_same_words_across_files_order_and_options` | same seed -> same word for the same name in another file, another order, other options; another seed -> other word | pass |
| 24 | `ServerPolicyTests.test_s1_bindata_6_and_8_masked_in_every_context` | BinData 6/8 masked in a generic attr, a filter, a CRUD `o`, nested arrays and JSON embedded in a string | pass |
| 25 | `ServerPolicyTests.test_s1_mask_is_the_server_mask_and_replaces_the_whole_element` | the whole `{"$binary": ..}` becomes the string `"###"` (both styles) | pass |
| 26 | `ServerPolicyTests.test_s1_other_subtypes_and_sibling_values_untouched` | like the server's `RedactSensitiveStringTest`: subtypes 0 / 4 and sibling strings stay | pass |
| 27 | `ServerPolicyTests.test_s1_legacy_extended_json_form` | `{"$binary": "..", "$type": "08"}` | pass |
| 28 | `ServerPolicyTests.test_s2_payload_documents_erase_bool_null_and_flag_ints` | bool / null / 0 / 1 / -1 / float / string in `documents` all erased | pass |
| 29 | `ServerPolicyTests.test_default_keeps_keys_and_operators_but_masks_every_literal` | `$project` / `$sort` / `$group` keep stage names, operators and keys; every literal incl. flags and null is `###` | pass |
| 30 | `ServerPolicyTests.test_default_masks_update_options_like_the_server` | `multi` / `upsert` / `ordered` are `###` like the server | pass |
| 31 | `ServerPolicyTests.test_default_builtin_pii_ref_inside_operand_array` | `{"$in": [<value>, ["$email"]]}` redacts the literal | pass |
| 32 | `ServerPolicyTests.test_idempotent_on_server_redacted_logs_every_mode` | a server-redacted entry (`###`, `Unauthorized: ###`, `InternalError ###`) is unchanged in 4 option sets | pass |
| 33 | `ServerPolicyTests.test_server_redaction_matches_server_unit_tests` | the cases of the server's own `redaction_test.cpp` plus the `{$regex, $options}` operator document | pass |
| 34 | `ServerPolicyTests.test_server_redaction_matches_reference_model` | 6 realistic commands == independent model of `BSONObj::redact(all)` | pass |
| 35 | `ServerPolicyTests.test_server_redaction_schema_keys_are_still_obfuscated` | documented deviation: `sort` / `hint` / `projection` keys are aliased, values `###` | pass |
| 36 | `ServerPolicyTests.test_server_redaction_other_data_attrs_and_oplog_entry` | oplog entry (`bgsync.cpp` `lastOplogEntry`), `keyValue`, `errInfo` | pass |
| 37 | `ServerPolicyTests.test_server_redaction_status_exception_and_what_forms` | `CodeName: ###`, `Code{extra}: ..` -> `Code: ###`, `OK`, plain `what()` -> `###` | pass |
| 38 | `ServerPolicyTests.test_server_redaction_structured_status_keeps_code_drops_reason` | `{code, codeName, errmsg}` -> `errmsg: "###"` | pass |
| 39 | `ServerPolicyTests.test_server_redaction_mask_ignores_char_replacement_and_keeps_other_rules` | `###` in both styles; ns / appName / IP / email still redacted | pass |
| 40 | `ServerPolicyTests.test_server_redaction_canary_corpus_both_styles` | full synthetic corpus: 0 leaks in both styles | pass |
| 41 | `ServerPolicyTests.test_log_only_options_rejected_for_ftdc` | log-only options rejected in `--ftdc_redact` | pass |
| 42 | `SchemaFileTests.test_rule_matrix` | **the rule**: none / schema / addFields / schema+addFields x fruit / x: requested fields are gone, un-requested stay, built-in PII always gone | pass |
| 43 | `SchemaFileTests.test_client_data_is_always_masked_whatever_the_options` | inside a command every literal is `###` and the result is identical under all 4 combinations x 2 styles | pass |
| 44 | `SchemaFileTests.test_path_precision_vendor_not_redacted_by_customer_path` | path `customer.vipCode` redacts customer only, `vendor.vipCode` stays in 6 contexts | pass |
| 45 | `SchemaFileTests.test_path_is_contiguous_bare_name_matches_any_depth` | `customer.items.$[e].vipCode` is another path; a bare `vipCode` matches at any depth | pass |
| 46 | `SchemaFileTests.test_path_in_aggregation_field_reference_and_free_text` | `$eq` / `$in` against `$customer.vipCode`, and `customer.vipCode: <v>` in free text | pass |
| 47 | `SchemaFileTests.test_flat_names_and_builtin_pii_in_comparisons_outside_client_data` | `{"$eq": ["$grId", <v>]}` / `{"$in": [<v>, ["$grId"]]}` / `$email` in a non-data container | pass |
| 48 | `SchemaFileTests.test_flat_schema_field_matches_like_add_fields_everywhere` | `$in` operand, `$set`, comparison refs, sub-document, JSON string, free text | pass |
| 49 | `SchemaFileTests.test_style_fruit_vs_x_for_schema_values` | fruit words vs `x-xxxx` pattern | pass |
| 50 | `SchemaFileTests.test_union_equals_add_fields_with_the_same_names` | schema fields + `--addFields` == one `--addFields` with both lists (byte-identical with a seed) | pass |
| 51 | `SchemaFileTests.test_deterministic_with_seed` | same seed -> same output | pass |
| 52 | `SchemaFileTests.test_works_with_redact_namespaces_and_seed` | combines with `--redactNamespaces --seed` | pass |
| 53 | `SchemaFileTests.test_file_formats` | array shorthand, bare nested, fields-only, paths-only, one-segment path, `false` leaf, meta keys | pass |
| 54 | `SchemaFileTests.test_case_insensitive_dollar_optional_and_dotted_match` | `$TENANTREF`, `GrId`, `Customer.VIPCODE` | pass |
| 55 | `SchemaFileTests.test_empty_schema_is_a_noop` | `{}`, `[]`, `{"fields": []}`, `{"paths": []}` change nothing | pass |
| 56 | `SchemaFileTests.test_legacy_text_log` | the four combinations on a pre-4.4 text log | pass |
| 57 | `SchemaFileTests.test_rejects_missing_file` | exit 2, one-line error | pass |
| 58 | `SchemaFileTests.test_rejects_invalid_json` | exit 2, no traceback | pass |
| 59 | `SchemaFileTests.test_rejects_wrong_types` | nine malformed shapes rejected | pass |
| 60 | `SchemaFileTests.test_rejects_binary_garbage` | non-UTF-8 file rejected cleanly | pass |
| 61 | `SchemaFileTests.test_rejected_for_ftdc` | log-only option rejected with `--ftdc_redact` | pass |
| 62 | `SchemaFileTests.test_schema_file_content_never_echoed_on_error` | a field name in a broken file never appears in stderr | pass |

Mutation checks: the parity test detects a style that skips host redaction (3 tests failed); the server-policy
tests failed against the implementation *before* the change and pass now.

---

## 3. Integration suite - real cluster (`m` + `mtools`)

`test_integration_mongo.py <version>`:

1. `m` resolves `X.Y` to the newest patch installable on this platform and installs it; the active `m` version is
   restored (symlinks re-created and verified identical afterwards).
2. `mlaunch` starts a minimal **auth-enabled sharded cluster**: 1 shard (single-node replica set) + 1 config server +
   1 mongos, `slowms=0`.
3. A PII-heavy workload runs through the mongos: CRUD, aggregation (`$lookup`, `$out`, `$unionWith`), bad-modifier and
   validation errors, transactions, change streams + resume, index builds, `shardCollection` / `split` (`moveChunk`
   with `--shards 2`), users, failed and successful logins, BinData 6/8 payloads, schema-targeted fields, several
   `appName`s, direct shard connections.
4. The three real logs (mongos, shard mongod, config mongod) are redacted under an option matrix and checked. The
   cluster is stopped and processes verified gone.
5. With `--ground-truth` and an enterprise build (`5.0.31-ent`), a **second, identical cluster** runs the same
   workload with the server redacting its own logs (`redactClientLogData=true`); its output is the reference for the
   default policy (section 3c).

### Results per version (community builds)

| Version | Resolved from | Log lines (config / mongos / shard) | Canaries in source logs | BinData 6/8 base64 in the *source* log | System ns attrs / loopback remotes kept | Tests | Time |
|---------|---------------|-------------------------------------|:------:|:------:|:------:|:------:|-----:|
| 4.4.29 | `4.4` (4.4.30/.31 have no macOS build) | 490 / 300 / 541 | 62 / 63 | **yes** | 294 / 314 | 28 / 28 (+4 skipped) | 67 s |
| 5.0.31 | `5.0` (5.0.32-.34 have no macOS build) | 539 / 560 / 835 | 62 / 63 | **yes** | 499 / 740 | 28 / 28 (+4 skipped) | 124 s |
| 6.0.29 | `6.0` | 594 / 560 / 928 | 62 / 63 | no (server masks) | 583 / 771 | 28 / 28 (+4 skipped) | 111 s |
| 7.0.43 | `7.0` | 794 / 705 / 1110 | 62 / 63 | no (server masks) | 630 / 743 | 28 / 28 (+4 skipped) | 112 s |
| 8.0.32 | `8.0` | 919 / 621 / 1395 | 62 / 63 | no (server masks) | 862 / 852 | 28 / 28 (+4 skipped) | 127 s |

The one canary never logged by any version is the admin password (`Secr3tPassw0rd`): the server does not write it,
which is the correct outcome. After every run: 0 stray server processes, `m` symlinks identical to the snapshot taken
before any install.

### The 28 tests (identical result on all five versions)

| # | Test | What it proves | 4.4 | 5.0 | 6.0 | 7.0 | 8.0 |
|--:|------|----------------|:--:|:--:|:--:|:--:|:--:|
| 1 | `test_00_cluster_and_source_logs` | cluster started, logs are logv2 JSON | pass | pass | pass | pass | pass |
| 2 | `test_01_canaries_actually_reach_the_logs` | the fake PII really reached the logs (the suite is not vacuous) | pass | pass | pass | pass | pass |
| 3 | `test_10_matrix_default` | no canary / source IP / hostname / OS user / unlisted-field value; valid logv2; `t,s,c,id` and top-level attr keys unchanged | pass | pass | pass | pass | pass |
| 4 | `test_11_matrix_seed` | same, `--seed` | pass | pass | pass | pass | pass |
| 5 | `test_12_matrix_redactns` | same, `--redactNamespaces` | pass | pass | pass | pass | pass |
| 6 | `test_13_matrix_x` | same, `--char_replacement` | pass | pass | pass | pass | pass |
| 7 | `test_14_matrix_everything` | same, seed + x + redactNamespaces + `--addFields` | pass | pass | pass | pass | pass |
| 8 | `test_15_matrix_x_redactns_seed` | same, x + redactNamespaces + seed | pass | pass | pass | pass | pass |
| 9 | `test_16_matrix_single_pass` | `--single_pass` (names exempt by design, PII values not) | pass | pass | pass | pass | pass |
| 10 | `test_19_addfields_removes_custom_field` | `--addFields grId` removes the custom field everywhere | pass | pass | pass | pass | pass |
| 11 | `test_20_default_removes_values_of_unlisted_fields` | values of field names the tool has never heard of are removed by the DEFAULT policy | pass | pass | pass | pass | pass |
| 12 | `test_21_deprecated_flags_are_accepted_and_ignored` | `--pii` / `--strict` / `--server_redaction` / `--redactClientLogData`: identical output, one stderr note | pass | pass | pass | pass | pass |
| 13 | `test_30_shape_scan_x_mode` | independent scan of every string: no email / SSN / Luhn card / JWT / raw IP shape in x mode | pass | pass | pass | pass | pass |
| 14 | `test_31_shape_scan_word_mode` | word mode: only `fruit@colour.com` emails, no SSN / JWT | pass | pass | pass | pass | pass |
| 15 | `test_40_parity_default` | fruit vs x style change exactly the same tokens (real logs) | pass | pass | pass | pass | pass |
| 16 | `test_41_parity_redactns` | ... with `--redactNamespaces` | pass | pass | pass | pass | pass |
| 17 | `test_50_redacted_logs_remain_parseable` | every line validates against logv2 (mtools 1.7.2 cannot parse 4.4+ JSON logs, so the built-in validator is used) | pass | pass | pass | pass | pass |
| 18 | `test_51_operational_metrics_preserved` | durations / counters kept; `(c, id, msg)` histogram identical | pass | pass | pass | pass | pass |
| 19 | `test_52_system_namespaces_and_loopback_kept` | `ns` / `namespace` attributes of `config.*`, `local.*`, `admin.*` kept line by line (hundreds), 127.0.0.1 kept; `config.cache.chunks.<user ns>` redacted | pass | pass | pass | pass | pass |
| 20 | `test_53_bindata_6_and_8_masked_by_default_in_every_mode` | BinData 6/8 base64 (which the 4.4 / 5.0 servers print) absent in 4 option sets | pass | pass | pass | pass | pass |
| 21 | `test_54_default_equals_server_reference_model_on_real_logs` | every real `command` / `originatingCommand` == the model of `BSONObj::redact(all)` | pass | pass | pass | pass | pass |
| 22 | `test_55_default_status_forms_and_fixpoint` | every status attr is `CodeName: ###` / `###` / `{errmsg:###}`; a second pass is a fixpoint on client data | pass | pass | pass | pass | pass |
| 23 | `test_56_schema_file_and_add_fields_combinations` | the 4 combinations x 2 styles x 2 option sets on a real log + an injected non-client-data probe: requested fields gone, un-requested stay; real client data masked in every combination | pass | pass | pass | pass | pass |
| 24 | `test_57_schema_file_with_addfields_is_additive_and_deterministic` | same seed -> same output; real lines unchanged, only the probe gains redactions | pass | pass | pass | pass | pass |
| 25 | `test_60_seed_determinism_and_salting` | same seed -> same output; unseeded tokens differ per run | pass | pass | pass | pass | pass |
| 26 | `test_61_no_unsalted_md5_of_sensitive_values` | no MD5 of any canary / name appears | pass | pass | pass | pass | pass |
| 27 | `test_62_idempotent_and_still_json_on_second_pass` | redacting the redacted log works and stays JSON | pass | pass | pass | pass | pass |
| 28 | `test_63_damaged_real_log_fails_closed_and_stays_json` | blank first line, truncated and syslog-prefixed lines: still JSON, no leak | pass | pass | pass | pass | pass |

---

## 3b. Server-side redaction policy (what the MongoDB server itself does)

Read from the server source: `logv2/redaction.cpp`, `logv2/log_util.cpp`,
enterprise `encryptdb/log_redact_options.cpp`, `db/repl/bgsync.cpp`, and the nested
calls `logv2/redaction.h`, `logv2/logv2_options.{idl,cpp}`, `bson/bsonobj.cpp`
(`BSONObj::redact`), `bson/bsonelement.cpp`, `bson/bsontypes.h` and the server's own
`logv2/redaction_test.cpp`.

| # | Server policy | Source | Covered before | Now |
|---|---------------|--------|----------------|-----|
| S0 | Mask is the constant `"###"`; field names and structure are kept | `redaction.cpp` `kRedactionDefaultMask` | different mask (fruit / x) | `###` for all client data; fruit / x-pattern for names, hosts, users, apps |
| S1 | BinData subtype **6 (Encrypt)** and **8 (Sensitive)** -> `"###"` at any depth, even with `redactClientLogData` off (`redactBinDataEncrypt` defaults to **true**; subtype 8 unconditionally) | `log_util.cpp`, `bsonobj.cpp` `encryptedAndSensitive` / `sensitiveOnly` | **No** (base64 leaked in filters / generic attrs) | **Default**, every context, both EJSON forms |
| S2 | `redactClientLogData=true` -> BSON level `all`: every scalar of ANY type (string, number, bool, null, date, oid, bindata) -> `"###"`; arrays walked | `redaction.cpp`, `log_redact_options.cpp`, `bsonobj.cpp` `RedactLevel::all` | partly (bool / null / `0,1,-1` survived in payloads and under PII keys) | **default**: exact level `all` for all client data |
| S3 | `redact(Status)` -> `CodeName: ###` (`OK` stays), `redact(DBException)` -> `CodeName ###`, `redact(e.what())` -> `###` | `redaction.cpp`, `bgsync.cpp` lines 232 / 237 / 541 / 592 / 686 / 922 | reason text kept (heuristic masking) | **default** reproduces the forms |
| S4 | Scope: only call sites wrapped in `redact()` (errors, exception text, BSON docs such as `lastOplogEntry`); hosts, namespaces, `syncSource` and five other `error` attrs in the same file are not | `bgsync.cpp` | we were already stricter | unchanged: every other rule of this tool still applies on top |
| S5 | Logs already redacted by the server must survive a second pass | - | **No** (`find: "###"` -> `"loquat"`) | **default**: idempotent on `###`, `CodeName: ###`, `CodeName ###`, `OK` |

Deliberate deviation (documented in the README): the keys of `sort` / `hint` / `projection` /
`fields` (index and field names, which the server leaves visible) are always obfuscated.

Since these policies became the **default**, `--pii`, `--strict`, `--server_redaction` and
`--redactClientLogData` are accepted and ignored (hidden from `--help`, one stderr note).

Examples (default policy, word style unless noted; real outputs of the final script):

| Policy | Input | Output |
|--------|-------|--------|
| S1 | `{"a": {"$binary": {"base64": "Y2lwaGVy...", "subType": "06"}}, "b": {... "subType": "08"}, "c": {... "subType": "00"}}` | `{"a": "###", "b": "###", "c": {"$binary": {... "subType": "00"}}}` (subtype 0 kept) |
| S2 | payload `{"optedOut": false, "hivStatus": true, "n": null}` | `{"optedOut": "###", "hivStatus": "###", "n": "###"}` |
| S2 | `$project: {"email": 1, "phone": true}`, `$sort: {"createdAt": -1}` | `{"email": "###", "phone": "###"}`, `{"createdAt": "###"}` (operators and keys kept) |
| S2 | `{"find":"c","filter":{"email":"a@b.com","age":{"$gt":18},"tags":["a","b"],"_id":{"$oid":"6ac6..."}},"$db":"acmeshopdb"}` | `{"find":"###","filter":{"email":"###","age":{"$gt":"###"},"tags":["###","###"],"_id":"###"},"$db":"###"}` |
| S3 | `Unauthorized: not authorized on acmeshopdb to execute command { find: "c" }` | `Unauthorized: ###` |
| S3 | `ShutdownInProgress{ remainingQuiesceTimeMillis: 0 }: Replication is being shut down; ...` | `ShutdownInProgress: ###` |
| S3 | `{"code":13,"codeName":"Unauthorized","errmsg":"not authorized on ..."}` | `{"code":13,"codeName":"Unauthorized","errmsg":"###"}` |
| S5 | `{"command":{"find":"###","filter":{"a":"###"}},"error":"Unauthorized: ###"}` | identical |

**The server masks BinData 6/8 only from 6.0 on.** Measured on the real servers of
this suite (`test_53`): the base64 of both payloads is present in the 4.4.29 and
5.0.31 logs and absent from 6.0.29, 7.0.43 and 8.0.32. Logs from older servers
therefore still carry ciphertext unless the tool masks it; it now does, for every
source version.

## 3c. Ground truth: an enterprise server redacting its own logs

`--ground-truth` runs a second, identical cluster on an **enterprise** build with
`setParameter redactClientLogData=true` on the mongos, the shard and the config
server, and compares the server's own redacted logs with the **default output** of the
tool for the unredacted logs of the first cluster (no flags).

| Test | What it proves |
|------|----------------|
| `test_g0_server_really_redacts_and_what_it_leaves_visible` | the reference cluster works (>200 `"###"`, no email / SSN / card / IBAN / token) and shows what the SERVER leaves visible: `acmeshopdb`, `customer_profiles`, `AcmeBillingService`, `acme_root_user`, `mary.watson`, `jsmith_admin`, hostnames |
| `test_g1_our_command_masks_equal_the_servers_masks` | **every** distinct redacted command of the user ops (same `appName`) is identical in the server's log and in ours |
| `test_g2_status_forms_match_where_the_server_masks_and_we_are_never_weaker` | where the server masks a Status we produce the same form; everywhere else we mask too |
| `test_g3_idempotent_on_server_redacted_logs_and_stricter_elsewhere` | ofuscator on the server-redacted log keeps every `"###"`, removes the names the server left visible, and equals the reference model applied to the server's line |

| Enterprise build | Tests | Distinct server-redacted commands identical to ours (config / mongos / shard) | Status attrs compared | server masked and we match | server left the reason **in clear** (we mask) |
|------------------|:-----:|-----------------------------------------------|:--:|:--:|:--:|
| 5.0.31-ent | 32 / 32 | 26 / 67 / 77 (43 / 98 / 89 log lines) | 39 | 11 | 28 |
| 7.0.17-ent | 32 / 32 | 18 / 67 / 78 (33 / 98 / 89 log lines) | 40 | 11 | 29 |
| 8.0.17-ent | 32 / 32 | 18 / 67 / 81 (38 / 98 / 95 log lines) | 42 | 12 | 30 |

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
`schema: {loyalty: {tier: true}}`; `--addFields grId`. Inside client data (commands, filters, documents, oplog
entries) the default policy already masks every literal with `###`, so the combinations are observed in containers that
are **not** client data. Seven canaries: built-in PII (`email`), `grId` (only `--addFields`), `tenantRef` /
`customer.vipCode` / `loyalty.tier` (only the schema file), plus two that must **stay visible**: `vendor.vipCode`
(a different path) and `customer.items.$[e].vipCode` (not contiguous).

| Options | email (default) | grId | tenantRef | customer.vipCode | loyalty.tier | vendor.vipCode |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|
| none | gone | **visible** | **visible** | **visible** | **visible** | visible |
| `--loadSchemaFile` | gone | **visible** | gone | gone | gone | visible |
| `--addFields grId` | gone | gone | **visible** | **visible** | **visible** | visible |
| both | gone | gone | gone | gone | gone | visible |

The table is asserted for fruit and x style on a nine-context corpus (generic attr, query-shaped container with dotted
keys and `$in` operands, `$elemMatch`, arrays of sub-documents, `$set` on dotted / positional paths, comparisons
against field references, sub-document, JSON serialised in a string, free text). The same four combinations applied to
a **command** give one identical result (every literal `###`), asserted by
`test_client_data_is_always_masked_whatever_the_options`. On the real servers (`test_56`, `test_57`) a real log plus one
injected non-client-data entry gives the same table, and the real client data of all three logs is masked in every
combination. Result: **all pass** on 4.4, 5.0, 6.0, 7.0, 8.0 and on the three enterprise builds.

Examples (`--seed s`; one line whose attributes are not client data; schema = `fields: [tenantRef]`,
`paths: [customer.vipCode]`):

| Options | `attr` |
|---------|--------|
| none | `{"emails":["damson","date"],"tenantRef":"T-77","customer":{"vipCode":"VIP-9"},"vendor":{"vipCode":"V-5"}}` |
| `--loadSchemaFile` | `{"emails":["damson","date"],"tenantRef":"olive","customer":{"vipCode":"tamarillo"},"vendor":{"vipCode":"V-5"}}` |
| `--loadSchemaFile --char_replacement` | `{"emails":["xxxxx@xxxxxxxxxxxx.xxx","xxxxx@xxxxxxxxxxxx.xxx"],"tenantRef":"x-xx","customer":{"vipCode":"xxx-x"},"vendor":{"vipCode":"V-5"}}` |

Breaches found while writing these tests (all fixed, section 1): dotted schema paths were not applied to `$eq` / `$in`
comparisons against `"$customer.vipCode"` nor to free text; field references inside an operand array were missed;
and comparisons against an `--addFields` field or a built-in PII key (`{"$eq": ["$grId", "x"]}`,
`{"$eq": ["$email", "x"]}`) in a non-client-data container left the literal in clear.

Validation (exit code 2, one line, no traceback, content never echoed): missing file, invalid JSON, `"fields": "grId"`,
empty names, `"paths": ["a.b", 5]`, `"paths": ["..."]`, `"schema": {"a": 5}`, `"schema": ["a"]`, a JSON string / number
at top level, binary garbage; rejected together with `--ftdc_redact`.

---

## 4. One real line per test, before and after (MongoDB 5.0.31, x replacement)

Real lines from the 5.0.31 cluster, redacted with `--char_replacement` plus the options of that test (the
default policy is always on). Only relevant fields are shown; `...` marks shortened values.

| Test | Options | Before | After |
|------|---------|--------|-------|
| `test_00_cluster_and_source_logs` | `(none)` | `{"options":{"net":{"port":27700},"processManagement":{"fork":true},"security":{"keyFile":"/tmp/ofuscator_it_XXXX/cluster/keyfile"},"sharding":{"configDB":"configRepl/localhost:27702"},"systemL...` | `{"options":{"net":{"port":27700},"processManagement":{"fork":true},"security":{"keyFile":"/xxx/xxxxxxx/x_/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/x/xxxxxxxxx_xx_xxxxxxxx/xxxxxxx/xxxxxxx"},"sharding":{"configDB":"xxxxxxxxxx/xxxxxxxxx:xxxxx"},"systemL...` |
| `test_01_canaries_actually_reach_the_logs` | `(none)` | `{"ns":"acmeshopdb.customer_profiles","appName":"AcmeBillingService","command.filter":{"email":"alice.smith@acme-corp.com"}}` | `{"ns":"xxxxxxxxxx.xxxxxxxx_xxxxxxxx","appName":"xxxxxxxxxxxxxxxxxx","command.filter":{"email":"###"}}` |
| `test_10_matrix_default` | `(none)` | `{"ns":"acmeshopdb.customer_profiles","appName":"AcmeBillingService","command.filter":{"email":"alice.smith@acme-corp.com"},"remote":"127.0.0.1:51771"}` | `{"ns":"xxxxxxxxxx.xxxxxxxx_xxxxxxxx","appName":"xxxxxxxxxxxxxxxxxx","command.filter":{"email":"###"},"remote":"127.0.0.1:51771"}` |
| `test_11_matrix_seed` | `--seed it-seed` | `{"ns":"acmeshopdb.customer_profiles","command.insert":"customer_profiles","command.documents":[{"_id":"C-dup-canary-0001","customerId":"C-99887766","name":"Alice Smith","email":"dup-key-canary@acme-corp.com","alternateEmails":["carol.white@...` | `{"ns":"xxxxxxxxxx.xxxxxxxx_xxxxxxxx","command.insert":"###","command.documents":[{"_id":"###","customerId":"###","name":"###","email":"###","alternateEmails":["###"],"phone":"###","address":"###","identity":{"ssn":"###","passportNumber":"##...` |
| `test_12_matrix_redactns` | `--redactNamespaces` | `{"namespace":"acmeshopdb.customer_profiles","shardId":"shard1"}` | `{"namespace":"REDACTED_24fc4a94.REDACTED_526d7bb9","shardId":"xxxxxx"}` |
| `test_13_matrix_x` | `(none)` | `{"principalName":"mary.watson","authenticationDatabase":"admin","remote":"127.0.0.1:51799","error":"UserNotFound: User \"mary.watson@admin\" not found"}` | `{"principalName":"xxxx.xxxxxx","authenticationDatabase":"admin","remote":"127.0.0.1:51799","error":"UserNotFound: ###"}` |
| `test_14_matrix_everything` | `--seed it --redactNamespaces --addFields $comment,_tid,grId` | `{"error":{"code":13,"codeName":"Unauthorized","errmsg":"not authorized on acmeshopdb to execute command { insert: \"customer_profiles\", ordered: true, lsid: { id: UUID(\"ba611968-27c4-4c7d-9758-87c90167b8ff\") }, txnNumber: 1, $clusterTime...` | `{"error":{"code":13,"codeName":"Unauthorized","errmsg":"###"}}` |
| `test_15_matrix_x_redactns_seed` | `--redactNamespaces --seed k` | `{"chunkRange":"[{ customerId: MinKey }, { customerId: MaxKey })","splitPoint":{"customerId":"chunk-split-canary-5000"},"namespace":"acmeshopdb.customer_profiles","shardId":"shard1"}` | `{"chunkRange":"[{ customerId: MinKey }, { customerId: MaxKey })","splitPoint":{"customerId":"###"},"namespace":"REDACTED_0bf62d8a.REDACTED_a400b7a1","shardId":"xxxxxx"}` |
| `test_16_matrix_single_pass` | `--single_pass` | `{"remote":"127.0.0.1:51770","doc.application":{"name":"AcmeBillingService"},"doc.driver.name":"PyMongo\|c","doc.os.type":"Darwin"}` | `{"remote":"127.0.0.1:51770","doc.application":{"name":"xxxxxxxxxxxxxxxxxx"},"doc.driver.name":"PyMongo\|c","doc.os.type":"Darwin"}` |
| `test_19_addfields_removes_custom_field` | `--addFields grId` | `{"grId":"grid-canary-xyz-001","tenantRef":"schema-canary-tenantref-77","customer":{"vipCode":"schema-canary-path-vip-1"},"vendor":{"vipCode":"keep-canary-vendor-vip-5"}}` | `{"grId":"xxxx-xxxxxx-xxx-xxx","tenantRef":"schema-canary-tenantref-77","customer":{"vipCode":"schema-canary-path-vip-1"},"vendor":{"vipCode":"keep-canary-vendor-vip-5"}}` |
| `test_20_default_removes_values_of_unlisted_fields` | `(none)` | `{"command.filter":{"unlistedField":"filter-unlisted-canary-9"}}` | `{"command.filter":{"unlistedField":"###"}}` |
| `test_30_shape_scan_x_mode` | `(none)` | `{"command.documents":[{"_id":"C-dup-canary-0001","customerId":"C-99887766","name":"Alice Smith","email":"dup-key-canary@acme-corp.com","alternateEmails":["carol.white@acme-corp.com"],"phone":"+1-555-010-9999","address":"Wonderland Street 42...` | `{"command.documents":[{"_id":"###","customerId":"###","name":"###","email":"###","alternateEmails":["###"],"phone":"###","address":"###","identity":{"ssn":"###","passportNumber":"###","email":"###"},"financial":{"creditCard":"###","iban":"#...` |
| `test_31_shape_scan_word_mode` | `(none)` | `{"command.filter":{"email":"alice.smith@acme-corp.com"}}` | `{"command.filter":{"email":"###"}}` |
| `test_40_parity_default` | `(none)` | `{"command.pipeline":[{"$match":{"identity.ssn":"123-45-6789"}},{"$group":{"_id":1,"n":{"$sum":1}}}]}` | `{"command.pipeline":[{"$match":{"identity.ssn":"###"}},{"$group":{"_id":"###","n":{"$sum":"###"}}}]}` |
| `test_41_parity_redactns` | `--redactNamespaces` | `{"ns":"acmeshopdb.customer_profiles","command.aggregate":"customer_profiles"}` | `{"ns":"REDACTED_24fc4a94.REDACTED_526d7bb9","command.aggregate":"###"}` |
| `test_50_redacted_logs_remain_parseable` | `(none)` | `{"mechanism":"SCRAM-SHA-256","speculative":true,"principalName":"acme_root_user","authenticationDatabase":"admin","remote":"127.0.0.1:51771","extraInfo":{}}` | `{"mechanism":"SCRAM-SHA-256","speculative":true,"principalName":"xxxx_xxxx_xxxx","authenticationDatabase":"admin","remote":"127.0.0.1:51771","extraInfo":{}}` |
| `test_51_operational_metrics_preserved` | `(none)` | `{"durationMillis":0,"nreturned":0,"keysExamined":0,"docsExamined":0,"planSummary":"COLLSCAN"}` | `{"durationMillis":0,"nreturned":0,"keysExamined":0,"docsExamined":0,"planSummary":"COLLSCAN"}` |
| `test_52_system_namespaces_and_loopback_kept` | `--redactNamespaces` | `{"ns":"config.databases","appName":"AcmeBillingService","remote":"127.0.0.1:51737","command.query":{"_id":"acmeshopdb"}}` | `{"ns":"config.databases","appName":"xxxxxxxxxxxxxxxxxx","remote":"127.0.0.1:51737","command.query":{"_id":"###"}}` |
| `test_53_bindata_6_and_8_masked_by_default_in_every_mode` | `(none)` | `{"command.filter":{"secretBlob":{"$binary":{"base64":"YmluZGF0YS1jaXBoZXItY2FuYXJ5LTY=","subType":"6"}},"sensitiveBlob":{"$binary":{"base64":"YmluZGF0YS1zZW5zaXRpdmUtY2FuYXJ5LTg=","subType":"8"}}}}` | `{"command.filter":{"secretBlob":"###","sensitiveBlob":"###"}}` |
| `test_54_default_equals_server_reference_model_on_real_logs` | `(none)` | `{"command":{"aggregate":"customer_profiles","pipeline":[{"$match":{"identity.ssn":"123-45-6789"}},{"$group":{"_id":1,"n":{"$sum":1}}}],"cursor":{},"lsid":{"id":{"$uuid":"4c2db123-8f6c-457e-adec-e6e669825bd4"}},"$clusterTime":{"clusterTime":...` | `{"command":{"aggregate":"###","pipeline":[{"$match":{"identity.ssn":"###"}},{"$group":{"_id":"###","n":{"$sum":"###"}}}],"cursor":{},"lsid":{"id":"###"},"$clusterTime":{"clusterTime":"###","signature":{"hash":"###","keyId":"###"}},"$db":"##...` |
| `test_55_default_status_forms_and_fixpoint` | `(none)` | `{"error":"UserNotFound: User \"mary.watson@admin\" not found"}` | `{"error":"UserNotFound: ###"}` |
| `test_56_schema_file_and_add_fields_combinations` | `--loadSchemaFile schema.json --addFields grId` | `{"grId":"grid-canary-xyz-001","tenantRef":"schema-canary-tenantref-77","customer":{"vipCode":"schema-canary-path-vip-1"},"loyalty":{"tier":"schema-canary-nested-tier-9"},"vendor":{"vipCode":"keep-canary-vendor-vip-5"}}` | `{"grId":"xxxx-xxxxxx-xxx-xxx","tenantRef":"xxxxxx-xxxxxx-xxxxxxxxx-xx","customer":{"vipCode":"xxxxxx-xxxxxx-xxxx-xxx-x"},"loyalty":{"tier":"xxxxxx-xxxxxx-xxxxxx-xxxx-x"},"vendor":{"vipCode":"keep-canary-vendor-vip-5"}}` |
| `test_57_schema_file_with_addfields_is_additive_and_deterministic` | `--loadSchemaFile schema.json --addFields grId --seed abc` | `{"grId":"grid-canary-xyz-001","tenantRef":"schema-canary-tenantref-77","customer":{"vipCode":"schema-canary-path-vip-1"},"loyalty":{"tier":"schema-canary-nested-tier-9"},"vendor":{"vipCode":"keep-canary-vendor-vip-5"}}` | `{"grId":"xxxx-xxxxxx-xxx-xxx","tenantRef":"xxxxxx-xxxxxx-xxxxxxxxx-xx","customer":{"vipCode":"xxxxxx-xxxxxx-xxxx-xxx-x"},"loyalty":{"tier":"xxxxxx-xxxxxx-xxxxxx-xxxx-x"},"vendor":{"vipCode":"keep-canary-vendor-vip-5"}}` |
| `test_60_seed_determinism_and_salting` | `--seed abc` | `{"principalName":"acme_root_user","authenticationDatabase":"admin","remote":"127.0.0.1:51771","mechanism":"SCRAM-SHA-256"}` | `{"principalName":"xxxx_xxxx_xxxx","authenticationDatabase":"admin","remote":"127.0.0.1:51771","mechanism":"SCRAM-SHA-256"}` |
| `test_61_no_unsalted_md5_of_sensitive_values` | `(none)` | `{"ns":"acmeshopdb.customer_profiles","command.pipeline":[{"$match":{"tenant":"tenant-canary-acme-42"}},{"$project":{"email":1,"phone":1}},{"$out":"customer_profiles_archive"}]}` | `{"ns":"xxxxxxxxxx.xxxxxxxx_xxxxxxxx","command.pipeline":[{"$match":{"tenant":"###"}},{"$project":{"email":"###","phone":"###"}},{"$out":"###"}]}` |
| `test_62_idempotent_and_still_json_on_second_pass` | `(none)` x2 | `{"command.filter":{"email":"###"},"command.find":"###"}` (output of pass 1) | `{"command.filter":{"email":"###"},"command.find":"###"}` (pass 2: unchanged masks) |
| `test_63_damaged_real_log_fails_closed_and_stays_json` | `(none)` | `"mith@acme-corp.com\"},\"lsid\":{\"id\":{\"$uuid\":\"4c2db123-8f6c-457e-adec-e6e669825bd4\"}},\"$clusterTime\":{\"clusterTi"` (truncated line); `Oct 7 host mongos[1]: {...}` | `{"s":"W","c":"REDACTOR","ctx":"ofuscator","id":0,"msg":"Unparseable log line redacted","attr":{"lineNumber":2,"line":"{\"x\":{\"$xxxx\":\"xxxx-xx-xxxxx:xx:xx.xxx+xx:xx\"},\"x\":\"x\",  \"x\":\"xxxxxxx...` ; `{"find":"###","filter":{"email":"###"},"lsid":{"id":"###"},"$clusterTime":{"clusterTime":"###","signature":{"hash":"###"...` |

Reading the table: client data (`command.*`) is `###` in both styles; names, hosts, users, apps, `remote` and
namespaces take the x-pattern; `127.0.0.1`, `admin`, counters and plan summaries are kept; `test_56`/`57` use the
injected non-client-data probe.

---

## 5. Observations and known limits

- **Client data loses its detail.** The default mirrors the server, so inside a command everything is `###`, including `limit`, `batchSize`, `maxTimeMS`, `writeConcern`, `ordered`, the collection name and `$db` (the real servers do the same, section 3c). Query-shape analysis relies on field names, operators, plan summaries, counters and durations, which are kept.
- **Unlisted field names.** Inside client data they no longer survive. Outside client data (a custom attribute such as `attr.myStuff`) a value is redacted only when its key is a built-in PII name or is named with `--addFields` / `--loadSchemaFile`, or when its content looks like PII (email, card, SSN, IP, host, token, path ...).
- **The tool is stricter than the server.** With `redactClientLogData=true` the real servers still print namespaces, `appName`, users, hosts and many `error` reasons (e.g. `not authorized on <db> to execute command {`, `Error connecting to localhost:27701`); the default policy masks all of them (section 3c).
- **Deliberate deviation from the server.** The keys of `sort` / `hint` / `projection` / `fields` (index and field names) are obfuscated, the server leaves them visible.
- **Schema paths are contiguous.** `customer.vipCode` does not match `customer.items.$[e].vipCode`; use the bare name `vipCode` in `fields` to match at any depth. Paths are matched on keys (and `$ref` / `path: value` text); a value that merely *contains* the field name in prose is not detected.
- **Words and tokens are keyed.** The fruit / colour word and the `REDACTED_<hash>` token of a value are an HMAC of the value under the `--seed` key (random per-run key without a seed): the same name gets the same word in every file with the same seed, in any order and with any options (`test_seed_gives_the_same_words_across_files_order_and_options`, `test_57`).
- **mtools 1.7.2** cannot parse 4.4+ JSON logs (no datetime even for the original log), so it is used only to start the cluster; a built-in logv2 validator does the parse check. On legacy text logs `mloginfo` is used as the independent parse check.
- **Duplicate-key error text** is not written by 4.4-8.0 to the log (write errors are returned to the client); the command itself is logged and is covered. The error-text masker is exercised by the "not authorized on ..." line and the unit corpus.
- **FTDC**: `--ftdc_redact` only rewrites `hostInfo` of type-0 chunks; the compressed reference document of type-1 chunks (e.g. `replSetGetStatus` member hostnames) is passed through unchanged. Not covered by these tests.
- **Disk side effect**: versions downloaded by `m` for the integration run stay installed (`m rm <version>` to remove).

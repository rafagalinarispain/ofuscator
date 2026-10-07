#!/usr/bin/env python3
"""
test_ofuscator.py - PII leak regression tests for ofuscator.py.

The corpus below follows the mongod/mongos structured log schema
(https://github.com/mongodb/mongo/blob/master/docs/logging.md):

    {"t": {"$date": ...}, "s": sev, "c": component, "ctx": thread,
     "id": int, "msg": str, "attr": {...}, "tags": [...], "truncated": {...},
     "size": int}

Every entry carries "canary" values (fake PII).  After running the tool with
each flag combination, NONE of the canaries may appear anywhere in the output
(keys, values, msg, ctx, nested JSON strings, ...).

Run:  python3 test_ofuscator.py -v
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'ofuscator.py')

# ── Canaries ────────────────────────────────────────────────────────────────
# Must disappear in EVERY mode (default, --pii, --redactNamespaces, ...).
ALWAYS = [
    'alice.smith@acme-corp.com', 'bob.jones@acme-corp.com', 'acme-corp.com',
    '123-45-6789', '987654321', '4111111111111111', '4111 1111 1111 1111',
    '4831-7219-4053-6148', '+1-555-010-9999', '555-010-9999',
    'db-prod-01.internal.acme.com', 'db-prod-02.internal.acme.com',
    'cfg-prod-01.internal.acme.com', 'ldap.acme.com', 'proxy7.acme.net',
    '10.20.30.40', '10.20.30.41', '10.20.30.42', '10.20.30.43',
    '10.20.30.44', '10.20.30.45', '172.16.99.7',
    '2001:db8::ff00:42:8329', 'fe80::1c2d:3e4f:5a6b:7c8d',
    'jsmith_admin', 'mary.watson', 'AcmeBillingService', 'AcmeReportsApp',
    'C-99887766', 'Secr3tPassw0rd', 'acmeRS', 'acmeConfigRS',
    '/etc/acme/keyfile', '/data/acme/db', 'mongod-acme.conf',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl',
    'cn=admin,dc=acme,dc=com', 'CN=jsmith,OU=Eng,O=Acme',
    'Alice Smith', 'Smith', 'Wonderland Street 42', 'GB82WEST12345698765432',
    '00:1A:2B:3C:4D:5E', 'acmeshopdb', 'customer_profiles', 'acme_orders',
    'acme_archive', 'ssn_lookup_idx', 'notes_secret_index',
    'tok_live_9f8e7d6c5b4a', 'resume-token-canary-0001',
    'dup-key-canary@acme-corp.com', 'validation-canary-ssn-555',
    'chunk-min-canary-1111', 'chunk-max-canary-2222',
    'bearer-canary-abcdef123456', 'hello-regex-canary',
    'comment-canary-tenant-42',
]
# Values of unlisted field names: only guaranteed removed with --strict.
STRICT_ONLY = [
    'unlisted-free-text-canary', 'another-unlisted-canary-77',
    'nickname-like-canary-zed',
]

T = {"$date": "2026-10-07T12:00:00.000+00:00"}


def L(c, ctx, id_, msg, attr=None, s="I", **extra):
    e = {"t": T, "s": s, "c": c, "ctx": ctx, "id": id_, "msg": msg}
    if attr is not None:
        e["attr"] = attr
    e.update(extra)
    return e


LSID = {"id": {"$uuid": "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"},
        "uid": {"$binary": {"base64": "dXNlcmhhc2g=", "subType": "0"}}}
CT = {"clusterTime": {"$timestamp": {"t": 1, "i": 1}},
      "signature": {"hash": {"$binary": {"base64": "c2ln", "subType": "0"}},
                    "keyId": 7}}


def build_entries():
    e = []
    # 1. Slow query: find with filter / projection / sort / hint / comment
    e.append(L("COMMAND", "conn42", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "appName": "AcmeBillingService",
        "command": {
            "find": "customer_profiles",
            "filter": {"identity.email": "alice.smith@acme-corp.com",
                       "identity": {"ssn": {"$in": ["123-45-6789"]}},
                       "card": {"$eq": "4111111111111111"},
                       "name": {"$regex": "hello-regex-canary"},
                       "unlistedField": "unlisted-free-text-canary",
                       "Phone": "+1-555-010-9999",
                       "FIRSTNAME": "Alice", "LastName": "Smith"},
            "projection": {"identity.email": 1},
            "sort": {"createdAt": -1},
            "hint": "ssn_lookup_idx",
            "comment": "comment-canary-tenant-42",
            "limit": 5, "lsid": LSID, "$clusterTime": CT,
            "$db": "acmeshopdb",
            "$readPreference": {"mode": "secondaryPreferred"}},
        "planSummary": "IXSCAN { identity.email: 1 }",
        "keysExamined": 1, "docsExamined": 1, "nreturned": 1,
        "queryHash": "A1B2C3D4", "planCacheKey": "E5F6A7B8",
        "numYields": 0, "ok": 1, "durationMillis": 7,
        "remote": "10.20.30.40:51234",
        "locks": {"ReplicationStateTransition": {"acquireCount": {"w": 1}}},
        "storage": {}, "protocol": "op_msg"}))
    # 2. insert with documents (never covered by old path list)
    e.append(L("COMMAND", "conn42", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"insert": "customer_profiles", "ordered": True,
                    "documents": [{"_id": "C-99887766",
                                   "email": "bob.jones@acme-corp.com",
                                   "ssn": "987654321",
                                   "iban": "GB82WEST12345698765432",
                                   "notes": "unlisted-free-text-canary",
                                   "address": "Wonderland Street 42"}],
                    "lsid": LSID, "$db": "acmeshopdb"},
        "ninserted": 1, "durationMillis": 3}))
    # 3. update with updates[] (q/u/arrayFilters) + upsert
    e.append(L("COMMAND", "conn42", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"update": "customer_profiles", "ordered": True,
                    "updates": [{"q": {"email": "alice.smith@acme-corp.com"},
                                 "u": {"$set": {"ssn": "123-45-6789",
                                                "extra.unlisted": "unlisted-free-text-canary"}},
                                 "multi": False, "upsert": True,
                                 "arrayFilters": [{"e.email": "bob.jones@acme-corp.com"}]}],
                    "$db": "acmeshopdb"},
        "nMatched": 1, "nModified": 1, "durationMillis": 4}))
    # 4. delete with deletes[]
    e.append(L("COMMAND", "conn42", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"delete": "customer_profiles",
                    "deletes": [{"q": {"creditCard": "4111 1111 1111 1111",
                                       "x": "unlisted-free-text-canary"},
                                 "limit": 1}], "$db": "acmeshopdb"},
        "ndeleted": 1}))
    # 5. findAndModify
    e.append(L("COMMAND", "conn43", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"findAndModify": "customer_profiles",
                    "query": {"email": "alice.smith@acme-corp.com"},
                    "update": {"$set": {"phone": "555-010-9999"}},
                    "fields": {"ssn": 1}, "new": True, "$db": "acmeshopdb"}}))
    # 6. aggregate with $match/$lookup/$expr comparison
    e.append(L("COMMAND", "conn43", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"aggregate": "customer_profiles", "pipeline": [
            {"$match": {"$expr": {"$eq": ["$email", "alice.smith@acme-corp.com"]}}},
            {"$match": {"$expr": {"$eq": ["$ssn", "987654321"]}}},
            {"$lookup": {"from": "acme_orders", "localField": "_id",
                         "foreignField": "custId", "as": "o"}},
            {"$match": {"tag": "unlisted-free-text-canary"}},
            {"$text": {"$search": "Alice Smith"}}],
            "cursor": {}, "$db": "acmeshopdb"}}))
    # 7. distinct / count / mapReduce style commands
    e.append(L("COMMAND", "conn44", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"distinct": "customer_profiles", "key": "email",
                    "query": {"email": "bob.jones@acme-corp.com"},
                    "$db": "acmeshopdb"}}))
    e.append(L("COMMAND", "conn44", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"count": "customer_profiles",
                    "query": {"ssn": "123-45-6789"}, "$db": "acmeshopdb"}}))
    # 8. getMore with originatingCommand
    e.append(L("COMMAND", "conn44", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"getMore": 123456789, "collection": "customer_profiles",
                    "batchSize": 10, "$db": "acmeshopdb"},
        "originatingCommand": {"find": "customer_profiles",
                               "filter": {"email": "alice.smith@acme-corp.com"},
                               "projection": {"ssn": "123-45-6789"},
                               "hint": {"notes_secret_index": 1},
                               "comment": "comment-canary-tenant-42",
                               "lsid": LSID, "$db": "acmeshopdb"},
        "cursorid": 123456789, "nreturned": 10}))
    # 9. connection accepted / ended (mongod + mongos)
    e.append(L("NETWORK", "listener", 22943, "Connection accepted", {
        "remote": "10.20.30.41:50222", "uuid": "11111111-2222-3333-4444-555555555555",
        "connectionId": 42, "connectionCount": 7}))
    e.append(L("NETWORK", "conn42", 22944, "Connection ended", {
        "remote": "10.20.30.41:50222 10.20.30.42:1", "connectionId": 42,
        "connectionCount": 6}))
    # two adjacent IPs separated by one char (regression: shared delimiter)
    e.append(L("NETWORK", "conn42", 9999, "Hops",
               {"path": "10.20.30.43,10.20.30.44 10.20.30.45",
                "v6": "[2001:db8::ff00:42:8329]:27017",
                "v6b": "fe80::1c2d:3e4f:5a6b:7c8d"}))
    # 10. client metadata
    e.append(L("NETWORK", "conn42", 51800, "client metadata", {
        "remote": "10.20.30.41:50222",
        "client": "conn42",
        "doc": {"application": {"name": "AcmeReportsApp"},
                "driver": {"name": "PyMongo", "version": "4.6.0"},
                "os": {"type": "Linux", "name": "Ubuntu", "architecture": "x86_64",
                       "version": "22.04"}, "platform": "CPython 3.11"}}))
    # 11. authentication success / failure
    e.append(L("ACCESS", "conn42", 5286306, "Successfully authenticated", {
        "client": "10.20.30.41:50222", "mechanism": "SCRAM-SHA-256",
        "user": "jsmith_admin", "db": "admin", "result": 0}))
    e.append(L("ACCESS", "conn42", 20249, "Authentication failed", {
        "mechanism": "SCRAM-SHA-256", "speculative": False,
        "principalName": "mary.watson", "authenticationDatabase": "acmeshopdb",
        "remote": "10.20.30.41:50222",
        "error": "UserNotFound: Could not find user \"mary.watson\" for db \"acmeshopdb\""},
        s="W"))
    e.append(L("ACCESS", "conn42", 20436, "Checking authorization failed", {
        "error": {"code": 13, "codeName": "Unauthorized",
                  "errmsg": "not authorized on acmeshopdb to execute command { find: \"customer_profiles\", filter: { email: \"alice.smith@acme-corp.com\" } }"}}))
    # 12. duplicate key errors
    e.append(L("COMMAND", "conn42", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"insert": "customer_profiles", "$db": "acmeshopdb"},
        "writeErrors": [{"index": 0, "code": 11000,
                         "errmsg": "E11000 duplicate key error collection: acmeshopdb.customer_profiles index: ssn_lookup_idx dup key: { email: \"dup-key-canary@acme-corp.com\" }",
                         "keyValue": {"email": "dup-key-canary@acme-corp.com"}}],
        "errMsg": "E11000 duplicate key error collection: acmeshopdb.customer_profiles index: ssn_lookup_idx dup key: { email: \"dup-key-canary@acme-corp.com\" }",
        "errName": "DuplicateKey"}))
    e.append(L("WRITE", "conn42", 4639700, "Document validation failed", {
        "namespace": "acmeshopdb.customer_profiles",
        "errInfo": {"failingDocumentId": "C-99887766",
                    "details": {"operatorName": "$jsonSchema",
                                "schemaRulesNotSatisfied": [
                                    {"propertyName": "ssn", "details": [
                                        {"consideredValue": "validation-canary-ssn-555"}]}]}},
        "document": {"ssn": "validation-canary-ssn-555"}}))
    # 13. replication / topology (hosts)
    e.append(L("REPL", "ReplCoord-0", 21215, "Member is in new state", {
        "hostAndPort": "db-prod-02.internal.acme.com:27017", "newState": "SECONDARY"}))
    e.append(L("REPL", "BackgroundSync", 21095, "Choosing new sync source", {
        "syncSource": "db-prod-01.internal.acme.com:27017",
        "replicaSet": "acmeRS"}))
    e.append(L("REPL", "ReplCoord-0", 21392, "New replica set config in use", {
        "config": {"_id": "acmeRS", "version": 3, "term": 1,
                   "members": [{"_id": 0, "host": "db-prod-01.internal.acme.com:27017",
                                "tags": {"dc": "acme-east"}, "priority": 1},
                               {"_id": 1, "host": "db-prod-02.internal.acme.com:27017"}],
                   "settings": {"replicaSetId": {"$oid": "5f2b1c0e9d3a4b5c6d7e8f90"}}}}))
    e.append(L("SHARDING", "ShardRegistry", 22727, "Updating shard registry", {
        "connString": "acmeRS/db-prod-01.internal.acme.com:27017,db-prod-02.internal.acme.com:27017",
        "configServer": "acmeConfigRS/cfg-prod-01.internal.acme.com:27019"}))
    e.append(L("NETWORK", "ReplicaSetMonitor-TaskExecutor", 4333213,
               "RSM Topology Change", {
                   "replicaSet": "acmeRS",
                   "newTopologyDescription": "{ id: \"x\", topologyType: \"ReplicaSetWithPrimary\", servers: { db-prod-01.internal.acme.com:27017: { type: \"RSPrimary\", minWireVersion: 0 } } }",
                   "previousTopologyDescription": "{ servers: { db-prod-02.internal.acme.com:27017: { type: \"Unknown\" } } }"}))
    # 14. sharding chunk ops with shard-key values
    e.append(L("SHARDING", "MoveChunk", 21993, "moveChunk", {
        "namespace": "acmeshopdb.customer_profiles",
        "min": {"customerId": "chunk-min-canary-1111"},
        "max": {"customerId": "chunk-max-canary-2222"},
        "fromShard": "acmeRS", "toShard": "acmeConfigRS",
        "shardKeyPattern": {"customerId": 1}}))
    # 15. index build (spec with partial filter)
    e.append(L("INDEX", "IndexBuildsCoordinator-0", 20384, "Index build: starting", {
        "buildUUID": "11111111-2222-3333-4444-555555555555",
        "namespace": "acmeshopdb.customer_profiles",
        "indexName": "ssn_lookup_idx",
        "spec": {"v": 2, "key": {"ssn": 1}, "name": "ssn_lookup_idx",
                 "partialFilterExpression": {"ssn": {"$gt": "987654321"},
                                             "email": "bob.jones@acme-corp.com"}}}))
    # 16. oplog applier CRUD
    e.append(L("REPL", "ReplWriterWorker-1", 21260, "applied op", {
        "CRUD": {"op": "u", "ns": "acmeshopdb.customer_profiles",
                 "o": {"$v": 1, "$set": {"email": "alice.smith@acme-corp.com"}},
                 "o2": {"_id": "C-99887766"}}}))
    # 17. startup options / process details / build info
    e.append(L("CONTROL", "initandlisten", 21951, "Options set by command line", {
        "options": {"config": "/etc/acme/mongod-acme.conf",
                    "net": {"bindIp": "10.20.30.40,127.0.0.1", "port": 27017},
                    "storage": {"dbPath": "/data/acme/db"},
                    "security": {"keyFile": "/etc/acme/keyfile",
                                 "ldap": {"servers": "ldap.acme.com",
                                          "bind": {"queryUser": "cn=admin,dc=acme,dc=com",
                                                   "queryPassword": "Secr3tPassw0rd"}}},
                    "replication": {"replSet": "acmeRS"},
                    "setParameter": {"authenticationMechanisms": "SCRAM-SHA-256"}}}))
    e.append(L("CONTROL", "initandlisten", 4615611, "MongoDB starting", {
        "pid": 1234, "port": 27017, "dbPath": "/data/acme/db",
        "architecture": "64-bit", "host": "db-prod-01.internal.acme.com"}))
    e.append(L("CONTROL", "initandlisten", 51765, "Operating System", {
        "os": {"name": "Ubuntu", "version": "22.04"}}))
    # 18. TLS
    e.append(L("NETWORK", "conn42", 23214, "Accepted connection with TLS", {
        "peerSubject": "CN=jsmith,OU=Eng,O=Acme",
        "subject": "CN=jsmith,OU=Eng,O=Acme",
        "remote": "10.20.30.41:50222"}))
    # 19. change streams / resume token / sessions
    e.append(L("QUERY", "conn45", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"aggregate": "customer_profiles", "pipeline": [
            {"$changeStream": {"resumeAfter": {"_data": "resume-token-canary-0001"},
                               "fullDocument": "updateLookup"}}],
                    "cursor": {}, "$db": "acmeshopdb"}}))
    e.append(L("ACCESS", "conn45", 20000, "Session", {
        "sessionId": "tok_live_9f8e7d6c5b4a", "lsid": LSID,
        "authorization": "Bearer bearer-canary-abcdef123456"}))
    # 20. free-text 'msg' containing PII (legacy / dynamic msg) + odd fields
    e.append(L("STORAGE", "conn42", 1, "User jsmith_admin from 172.16.99.7 mailed alice.smith@acme-corp.com with card 4111111111111111 and mac 00:1A:2B:3C:4D:5E jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"))
    # 21. entry without attr but extra top-level data
    e.append(L("STORAGE", "conn42", 2, "no attr", None,
               extra_data="alice.smith@acme-corp.com 10.20.30.40"))
    # 22. truncated
    e.append(L("COMMAND", "conn42", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"insert": "customer_profiles",
                    "documents": [{"email": "alice.smith@acme-corp.com"}],
                    "$db": "acmeshopdb"}},
        truncated={"attr": {"command": {"type": "object", "size": 99999}}},
        size={"attr": {"command": 99999}}))
    # 23. archive namespace by itself and oplog
    e.append(L("STORAGE", "TTLMonitor", 22543, "Deleted expired documents", {
        "namespace": "acme_archive.acme_orders", "numDeleted": 3}))
    e.append(L("REPL", "rsSync", 21,"oplog", {"ns": "local.oplog.rs"}))
    # 24. tags
    e.append(L("CONTROL", "initandlisten", 22120, "startup warning",
               {"a": 1}, tags=["startupWarnings"]))
    # 25. nested JSON serialised into a string
    e.append(L("COMMAND", "conn46", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": json.dumps({"find": "customer_profiles",
                               "filter": {"email": "alice.smith@acme-corp.com"},
                               "$db": "acmeshopdb"})}))
    # 26. nickname / unlisted values deep under PII containers
    e.append(L("COMMAND", "conn47", 51803, "Slow query", {
        "type": "command", "ns": "acmeshopdb.customer_profiles",
        "command": {"insert": "customer_profiles", "$db": "acmeshopdb",
                    "documents": [{"profile": {"nickname": "nickname-like-canary-zed",
                                               "misc": {"x": "another-unlisted-canary-77"}}}]}}))
    return e


class LeakTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.log = os.path.join(cls.tmp.name, 'mongod.log')
        cls.entries = build_entries()
        with open(cls.log, 'w') as fh:
            for ent in cls.entries:
                fh.write(json.dumps(ent) + '\n')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_tool(self, *flags, path=None):
        p = subprocess.run(
            [sys.executable, SCRIPT, '--log_redact', path or self.log, *flags],
            capture_output=True, text=True, timeout=300)
        return p

    def check(self, flags, canaries):
        p = self.run_tool(*flags)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        out = p.stdout
        lines = [ln for ln in out.splitlines() if ln.strip()]
        self.assertEqual(len(lines), len(self.entries), 'line count changed')
        for ln in lines:
            self.assertIsInstance(json.loads(ln), dict)   # JSON in -> JSON out
        # The original value must not occur raw, nor JSON-escaped.
        leaks = [c for c in canaries
                 if c in out or json.dumps(c)[1:-1] in out]
        self.assertEqual(leaks, [], 'LEAKED: %r' % leaks)
        # stderr must never echo raw input
        for c in ALWAYS:
            self.assertNotIn(c, p.stderr)
        return out

    # -- flag matrix ---------------------------------------------------------
    # The DEFAULT policy already is "deep PII + every literal + server-style": values of
    # unlisted field names (STRICT_ONLY) are removed without any option.
    def test_default(self):
        self.check([], ALWAYS + STRICT_ONLY)

    def test_seed(self):
        self.check(['--seed', 's1'], ALWAYS + STRICT_ONLY)

    def test_redact_namespaces(self):
        self.check(['--redactNamespaces'], ALWAYS + STRICT_ONLY)

    def test_char_replacement(self):
        self.check(['--char_replacement'], ALWAYS + STRICT_ONLY)

    def test_single_pass(self):
        self.check(['--single_pass'], ALWAYS + STRICT_ONLY)

    def test_everything(self):
        self.check(['--seed', 'k', '--char_replacement', '--redactNamespaces',
                    '--addFields', '$comment,_tid'], ALWAYS + STRICT_ONLY)

    def test_deprecated_flags_are_accepted_and_ignored(self):
        """--pii / --strict / --server_redaction / --redactClientLogData are the default
        policy now: hidden from --help, accepted, no effect on the output."""
        base = self.run_tool('--seed', 'z')
        self.assertEqual(base.returncode, 0)
        self.assertNotIn('ignored', base.stderr)
        for flags in (['--pii'], ['--strict'], ['--server_redaction'],
                      ['--redactClientLogData'], ['--pii', '--strict', '--server_redaction']):
            r = self.run_tool(*flags, '--seed', 'z')
            self.assertEqual(r.returncode, 0, (flags, r.stderr[-300:]))
            self.assertEqual(r.stdout, base.stdout, flags)          # identical output
            self.assertIn('ignored', r.stderr)                      # one-line note
            self.assertIn('default policy', r.stderr)
            self.assertEqual(len(r.stderr.strip().splitlines()), 1, r.stderr)
        h = subprocess.run([sys.executable, SCRIPT, '--help'], capture_output=True, text=True).stdout
        for flag in ('--pii', '--strict', '--server_redaction', '--redactClientLogData'):
            self.assertNotIn(flag + ' ', h.replace('\n', ' ') + ' ')

    # -- behaviour / robustness ---------------------------------------------
    def test_structure_preserved(self):
        out = self.check([], ALWAYS)
        first = json.loads(out.splitlines()[0])
        for k in ("t", "s", "c", "ctx", "id", "msg", "attr"):
            self.assertIn(k, first)
        self.assertEqual(first["attr"]["durationMillis"], 7)
        self.assertEqual(first["attr"]["keysExamined"], 1)         # counters are not client data
        self.assertEqual(first["attr"]["command"]["limit"], "###")   # server masks every literal
        self.assertEqual(set(first["attr"]["command"]["filter"]["identity"]["ssn"]), {"$in"})  # operators kept
        self.assertEqual(first["id"], 51803)
        self.assertEqual(first["msg"], "Slow query")

    def test_deterministic_with_seed(self):
        a = self.run_tool('--seed', 'abc').stdout
        b = self.run_tool('--seed', 'abc').stdout
        self.assertEqual(a, b)

    def test_seed_gives_the_same_words_across_files_order_and_options(self):
        """With --seed a value maps to the same fruit / colour in EVERY file, whatever the
        order, the other content and the other options (the words come from an HMAC of the
        value, not from a shared random stream)."""
        mk = lambda ns, app: L("COMMAND", "c", 1, "Slow query", {"ns": ns, "appName": app,
                                                                 "user": "jane.roe", "host": "h1.acme.net:27017"})
        fa = os.path.join(self.tmp.name, 'fa.log')
        fb = os.path.join(self.tmp.name, 'fb.log')
        with open(fa, 'w') as fh:
            for e in (mk("shop.customers", "AcmeApp"), mk("shop.orders", "AcmeApp")):
                fh.write(json.dumps(e) + '\n')
        with open(fb, 'w') as fh:                       # other content, other order
            for e in (mk("zzz.first", "Other"), mk("a.b", "Third"), mk("shop.customers", "AcmeApp")):
                fh.write(json.dumps(e) + '\n')
        def attr(path, line, *flags):
            return json.loads(self.run_tool(*flags, '--seed', 'k', path=path).stdout.splitlines()[line])['attr']
        a = attr(fa, 0)
        for flags in ([], ['--addFields', 'whatever'], ['--single_pass'], ['--char_fields', 'x']):
            b = attr(fb, 2, *flags)
            for key in ('ns', 'appName', 'user', 'host'):
                self.assertEqual(a[key], b[key], (key, flags))
        c = json.loads(self.run_tool('--seed', 'other', path=fa).stdout.splitlines()[0])['attr']
        self.assertNotEqual(a['ns'], c['ns'])           # a different seed gives different words

    def test_leading_blank_line_still_json(self):
        p = os.path.join(self.tmp.name, 'blank_first.log')
        with open(p, 'w') as fh:
            fh.write('\n')
            fh.write(json.dumps(self.entries[0]) + '\n')
        out = self.run_tool(path=p).stdout
        for c in ALWAYS:
            self.assertNotIn(c, out)
        self.assertIn('"attr"', out)

    def test_malformed_line_is_redacted_not_echoed(self):
        p = os.path.join(self.tmp.name, 'broken.log')
        good = json.dumps(self.entries[0])
        with open(p, 'w') as fh:
            fh.write(good + '\n')
            fh.write('{"t":{"$date":"x"},"msg":"cut off alice.smith@acme-corp.com 10.20.30.40 "attr":{\n')
            fh.write('Oct  7 host mongod[1]: ' + good + '\n')     # syslog prefix
            fh.write(good + '\n')
        p_ = self.run_tool(path=p)
        self.assertEqual(p_.returncode, 0, p_.stderr[-1500:])
        for c in ALWAYS:
            self.assertNotIn(c, p_.stdout)
            self.assertNotIn(c, p_.stderr)
        lines = [x for x in p_.stdout.splitlines() if x.strip()]
        self.assertEqual(len(lines), 4)
        for ln in lines:                       # JSON source -> JSON output
            self.assertIsInstance(json.loads(ln), dict)
        self.assertEqual(json.loads(lines[1])['msg'], 'Unparseable log line redacted')
        self.assertIn('attr', json.loads(lines[2]))      # syslog prefix dropped, JSON kept

    def test_non_dict_json_line(self):
        p = os.path.join(self.tmp.name, 'nondict.log')
        with open(p, 'w') as fh:
            fh.write(json.dumps(self.entries[0]) + '\n')
            fh.write('["alice.smith@acme-corp.com"]\n')
            fh.write('"10.20.30.40"\n')
        p_ = self.run_tool(path=p)
        self.assertEqual(p_.returncode, 0, p_.stderr[-1500:])
        self.assertNotIn('alice.smith', p_.stdout)
        self.assertNotIn('10.20.30.40', p_.stdout)
        for ln in p_.stdout.splitlines():
            json.loads(ln)                     # every line stays valid JSON

    def test_no_unsalted_md5_of_low_entropy_values(self):
        import hashlib
        out = self.run_tool().stdout
        for v in ('987654321', '123-45-6789', '4111111111111111'):
            self.assertNotIn(hashlib.md5(v.encode()).hexdigest(), out)
        out = self.run_tool().stdout        # default: hashed blobs
        for v in ('acmeshopdb', 'customer_profiles'):
            self.assertNotIn(hashlib.md5(v.encode()).hexdigest(), out)
            self.assertNotIn(hashlib.md5(v.encode()).hexdigest()[:8], out)

    def test_redact_namespaces_tokens_salted(self):
        import hashlib
        out = self.run_tool('--redactNamespaces', '--seed', 'x').stdout
        self.assertNotIn(hashlib.md5(b'acmeshopdb').hexdigest()[:8], out)
        self.assertIn('REDACTED_', out)

    def test_system_namespaces_preserved(self):
        out = self.run_tool('--redactNamespaces').stdout
        self.assertIn('local.oplog.rs', out)

    # -- x-pattern must follow exactly the same rules as fruit-salad ---------
    @staticmethod
    def _flatten(node, acc):
        """Ordered list of every key and scalar in a JSON tree."""
        if isinstance(node, dict):
            for k, v in node.items():
                acc.append(('k', k))
                LeakTests._flatten(v, acc)
        elif isinstance(node, list):
            for v in node:
                LeakTests._flatten(v, acc)
        else:
            acc.append(('v', node))
        return acc

    def _parity(self, *flags):
        word = self.run_tool(*flags).stdout.splitlines()
        xpat = self.run_tool(*flags, '--char_replacement').stdout.splitlines()
        self.assertEqual(len(word), len(xpat))
        mismatches = []
        for i, (ent, w, x) in enumerate(zip(self.entries, word, xpat)):
            fo = self._flatten(ent, [])
            fw = self._flatten(json.loads(w), [])
            fx = self._flatten(json.loads(x), [])
            if len(fw) != len(fx):
                mismatches.append((i, 'shape', len(fo), len(fw), len(fx)))
                continue
            if len(fo) != len(fw):
                # blob-hashed subtrees (non --pii): both styles collapsed the
                # same subtrees into one token, so shapes are identical; the
                # key/value kind sequence must also agree.
                if [k for k, _ in fw] != [k for k, _ in fx]:
                    mismatches.append((i, 'kinds'))
                continue
            for (ko, o), (_, a), (_, b) in zip(fo, fw, fx):
                if not isinstance(o, str) or not any(c.isalnum() for c in o):
                    continue          # nothing to redact in "---" or numbers-as-structure
                if (o != a) != (o != b):
                    mismatches.append((i, o[:60], a[:60] if isinstance(a, str) else a,
                                       b[:60] if isinstance(b, str) else b))
        self.assertEqual(mismatches, [], 'coverage differs between styles')

    def test_parity_default(self):
        self._parity()

    def test_parity_redact_namespaces(self):
        self._parity('--redactNamespaces')

    def test_char_fields_selective_keeps_coverage(self):
        out = self.check(['--seed', 's', '--char_replacement',
                          '--char_fields', 'emails,email,$comment,user'],
                         ALWAYS)
        self.assertIn('@', out)       # fruit@colour.com style still used elsewhere

    def test_legacy_text_log_both_styles(self):
        p = os.path.join(self.tmp.name, 'legacy.log')
        with open(p, 'w') as fh:
            fh.write('2019-03-01T10:00:00.123+0000 I COMMAND  [conn7] command '
                     'acmeshopdb.customer_profiles command: find { find: "customer_profiles", '
                     'filter: { email: "alice.smith@acme-corp.com", ssn: 123456789 } } '
                     'planSummary: IXSCAN { email: 1 } 10.20.30.40:5555 protocol:op_msg 12ms\n')
            fh.write('2019-03-01T10:00:02.000+0000 I ACCESS [conn8] Successfully authenticated '
                     'as principal jsmith_admin on admin from client db-prod-01.internal.acme.com:27017\n')
        for flags in ([], ['--char_replacement'], ['--redactNamespaces']):
            out = self.run_tool(*flags, path=p).stdout
            for c in ('alice.smith@acme-corp.com', '123456789', '10.20.30.40',
                      'jsmith_admin', 'db-prod-01.internal.acme.com',
                      'acmeshopdb', 'customer_profiles'):
                self.assertNotIn(c, out, (flags, c))
            self.assertIn('IXSCAN { email: 1 }', out)      # structure kept
            self.assertIn('protocol:op_msg 12ms', out)

    def test_benign_fields_not_corrupted(self):
        """Learned-name replacement must not damage unrelated attributes."""
        out = self.run_tool('--seed', 'k').stdout.splitlines()
        for ln in out:
            e = json.loads(ln)
            a = e.get('attr', {})
            if 'mechanism' in a:
                self.assertEqual(a['mechanism'], 'SCRAM-SHA-256')
            if a.get('type') == 'command':
                self.assertEqual(e['msg'], 'Slow query')
        crud = [json.loads(x)['attr']['CRUD'] for x in out
                if 'CRUD' in json.loads(x).get('attr', {})][0]
        self.assertEqual(set(crud), {'op', 'ns', 'o', 'o2'})     # keys kept, like the server
        self.assertEqual(crud['op'], '###')                      # the server masks the op too

    def test_renamed_keys_never_collide_or_drop_fields(self):
        """Different field names can obfuscate to the same word / x-pattern:
        the number of fields must be preserved in BOTH styles."""
        sort = {"ab": 1, "cd": -1, "ef": 1, "gh": 1, "ij": 1, "kl": 1}
        hint = {f"field{i}": 1 for i in range(120)}       # > number of fruit words
        ent = L("COMMAND", "conn1", 51803, "Slow query", {
            "type": "command", "ns": "db1.c1",
            "command": {"find": "c1", "filter": {"a": 1}, "sort": sort,
                        "hint": hint, "$db": "db1"}})
        p = os.path.join(self.tmp.name, 'collide.log')
        with open(p, 'w') as fh:
            fh.write(json.dumps(ent) + '\n')
        for flags in ([], ['--char_replacement'], [], ['--char_replacement']):
            cmd = json.loads(self.run_tool(*flags, path=p).stdout)['attr']['command']
            self.assertEqual(len(cmd['sort']), len(sort), flags)
            self.assertEqual(len(cmd['hint']), len(hint), flags)

    def test_addfields_still_works(self):
        ent = L("COMMAND", "conn1", 51803, "Slow query", {
            "type": "command", "ns": "a.b",
            "command": {"find": "b", "filter": {"grId": "zzz-grid-canary"},
                        "$db": "a"}})
        p = os.path.join(self.tmp.name, 'af.log')
        with open(p, 'w') as fh:
            fh.write(json.dumps(ent) + '\n')
        out = self.run_tool('--addFields', 'grId', path=p).stdout
        self.assertNotIn('zzz-grid-canary', out)


# ══════════════════════════════════════════════════════════════════════════════
# Server-side redaction policy (mongo: logv2/redaction.cpp, log_util.cpp,
# bson/bsonobj.cpp, enterprise log_redact_options.cpp, repl/bgsync.cpp)
# ══════════════════════════════════════════════════════════════════════════════

MASK = '###'
_EXT = {'$oid', '$date', '$numberLong', '$numberInt', '$numberDouble', '$numberDecimal',
        '$timestamp', '$binary', '$uuid', '$regularExpression', '$minKey',
        '$maxKey', '$undefined', '$symbol', '$code', '$dbPointer'}


def server_redact_all(v):
    """Independent reference model of BSONObj::redact(RedactLevel::all):
    keys and structure kept, arrays walked, every scalar -> "###"."""
    if isinstance(v, dict):
        ks = set(v)
        if (len(ks) == 1 and next(iter(ks)) in _EXT) or ks in (
                {'$binary', '$type'}, {'$code', '$scope'}):
            return MASK                      # an EJSON wrapper is ONE bson scalar
        return {k: server_redact_all(x) for k, x in v.items()}
    if isinstance(v, list):
        return [server_redact_all(x) for x in v]
    return MASK


def binary(b64, subtype):
    return {"$binary": {"base64": b64, "subType": "%02x" % subtype}}


B64_6 = 'Y2lwaGVydGV4dC1jYW5hcnktNg=='      # "ciphertext-canary-6"
B64_8 = 'c2Vuc2l0aXZlLWNhbmFyeS04'          # "sensitive-canary-8"
B64_0 = 'Z2VuZXJhbC1iaW5hcnktMA=='          # "general-binary-0" (NOT redacted by the server)


class ServerPolicyTests(unittest.TestCase):
    """Policies the MongoDB server applies when it writes its own logs."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_attr(self, attr, *flags, **top):
        ent = L("COMMAND", "conn1", 51803, "Slow query", attr, **top)
        p = os.path.join(self.tmp.name, 'one.log')
        with open(p, 'w') as fh:
            fh.write(json.dumps(ent) + '\n')
        r = subprocess.run([sys.executable, SCRIPT, '--log_redact', p, *flags],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        return json.loads(r.stdout.splitlines()[0])['attr']

    # ---- S1: BinData Encrypt (6) / Sensitive (8): masked by DEFAULT -------------------
    FLAGS = ([], ['--char_replacement'], ['--redactNamespaces'], ['--seed', 'k'])

    def test_s1_bindata_6_and_8_masked_in_every_context(self):
        b6, b8, b0 = binary(B64_6, 6), binary(B64_8, 8), binary(B64_0, 0)
        attr = {
            "generic": {"a": b6, "b": b8, "c": b0,
                        "arr": [b6, {"n": b8}, "string"]},            # nested obj + array
            "command": {"find": "c", "$db": "d",
                        "filter": {"x": b6, "y": b8}},
            "CRUD": {"op": "i", "ns": "d.c", "o": {"secret": b8, "ciph": b6}},
            "embedded": json.dumps({"deep": {"k": b6}}),             # JSON inside a string
        }
        for flags in self.FLAGS:
            out = json.dumps(self.run_attr(attr, *flags))
            for canary in (B64_6, B64_8):
                self.assertNotIn(canary, out, (flags, canary))

    def test_s1_mask_is_the_server_mask_and_replaces_the_whole_element(self):
        for flags in ([], [], ['--char_replacement']):
            a = self.run_attr({"generic": {"a": binary(B64_6, 6), "b": binary(B64_8, 8)}}, *flags)
            self.assertEqual(a["generic"], {"a": MASK, "b": MASK}, flags)

    def test_s1_other_subtypes_and_sibling_values_untouched(self):
        """Like the server's RedactSensitiveStringTest: with redactClientLogData off
        only BinData 6/8 change, siblings (`string: "string"`) stay."""
        a = self.run_attr({"generic": {"type6": binary(B64_6, 6), "string": "string",
                                       "general": binary(B64_0, 0),
                                       "uuid": {"$binary": {"base64": "AAAAAAAAAAAAAAAAAAAAAA==", "subType": "04"}}}})
        g = a["generic"]
        self.assertEqual(g["type6"], MASK)
        self.assertEqual(g["string"], "string")
        self.assertEqual(g["general"]["$binary"]["subType"], "00")   # subtype 0 kept
        self.assertEqual(g["uuid"]["$binary"]["subType"], "04")      # subtype 4 kept

    def test_s1_legacy_extended_json_form(self):
        a = self.run_attr({"generic": {"old": {"$binary": B64_8, "$type": "08"},
                                       "old0": {"$binary": B64_0, "$type": "00"}}})
        self.assertEqual(a["generic"]["old"], MASK)
        self.assertNotEqual(a["generic"]["old0"], MASK)

    # ---- S2: type erasure (server: redact(all) turns EVERY scalar type into "###") ----------
    def test_s2_payload_documents_erase_bool_null_and_flag_ints(self):
        doc = {"optedOut": False, "hivStatus": True, "n": None, "flag": 1, "zero": 0,
               "neg": -1, "age": 42, "ratio": 0.5, "name": "nm-canary", "nested": [True, None, 1]}
        for flags in ([], ['--char_replacement'], []):
            a = self.run_attr({"command": {"insert": "c", "documents": [doc], "$db": "d"}}, *flags)
            got = a["command"]["documents"][0]
            for k, orig in doc.items():
                self.assertNotEqual(got[k], orig, (flags, k, got[k]))
            self.assertEqual(got["nested"], [MASK, MASK, got["nested"][2]])
            self.assertNotEqual(got["nested"][2], 1)

    def test_default_keeps_keys_and_operators_but_masks_every_literal(self):
        """Same as the server with redactClientLogData=true (BSON level `all`): stage names,
        operators and field names stay, EVERY literal becomes ###, flags and nulls included."""
        for flags in ([], ['--char_replacement']):
            a = self.run_attr({"command": {
                "aggregate": "c", "cursor": {}, "$db": "d",
                "pipeline": [{"$project": {"email": 1, "phone": True, "_id": 0}},
                             {"$sort": {"createdAt": -1}},
                             {"$group": {"_id": None, "n": {"$sum": 1}}},
                             {"$match": {"hivStatus": True, "status": "x"}}]}}, *flags)
            pl = a["command"]["pipeline"]
            self.assertEqual(pl[0]["$project"], {"email": MASK, "phone": MASK, "_id": MASK})
            self.assertEqual(pl[1]["$sort"], {"createdAt": MASK})
            self.assertEqual(pl[2]["$group"], {"_id": MASK, "n": {"$sum": MASK}})
            self.assertEqual(pl[3]["$match"], {"hivStatus": MASK, "status": MASK})
            self.assertEqual([list(st)[0] for st in pl], ["$project", "$sort", "$group", "$match"])

    def test_default_builtin_pii_ref_inside_operand_array(self):
        a = self.run_attr({"check": {"$in": ["in-operand-canary-77", ["$email"]]}})
        self.assertNotIn("in-operand-canary-77", json.dumps(a))

    def test_default_masks_update_options_like_the_server(self):
        a = self.run_attr({"command": {"update": "c", "$db": "d", "ordered": True,
                                       "updates": [{"q": {"ssn": "123-45-6789"}, "u": {"$set": {"a": 1}},
                                                    "multi": False, "upsert": True}]}})
        u = a["command"]["updates"][0]
        self.assertEqual(u, {"q": {"ssn": MASK}, "u": {"$set": {"a": MASK}}, "multi": MASK, "upsert": MASK})
        self.assertEqual(a["command"]["ordered"], MASK)

    # ---- idempotence on logs the server already redacted ----------------------------------
    SERVER_REDACTED = {
        "command": {"find": MASK, "filter": {"a": MASK, "b": [MASK, MASK], "c": {"$gt": MASK}},
                    "lsid": {"id": MASK}, "$db": MASK},
        "error": "Unauthorized: " + MASK,
        "exception": "InternalError " + MASK,
        "errMsg": MASK,
        "lastOplogEntry": {"op": MASK, "ns": MASK, "o": {"x": MASK}},
    }

    def test_idempotent_on_server_redacted_logs_every_mode(self):
        for flags in ([], [], [], ['--char_replacement'],
                      ['--redactNamespaces'], [],
                      ['--char_replacement']):
            a = self.run_attr(self.SERVER_REDACTED, *flags)
            for key in ("command", "error", "exception", "errMsg"):
                self.assertEqual(a[key], self.SERVER_REDACTED[key], (flags, key))

    # ---- --server_redaction = security.redactClientLogData=true ----------------------------
    SERVER_TEST_CASES = [       # taken from the server's own redaction_test.cpp
        ({}, {}),
        ({"": 1}, {"": MASK}),
        ({"a": 1}, {"a": MASK}),
        ({"a": 1.0}, {"a": MASK}),
        ({"a": "a"}, {"a": MASK}),
        ({"a": 1, "b": "str"}, {"a": MASK, "b": MASK}),
        # verified on a real enterprise server: a query-operator document, NOT a regex scalar
        ({"name": {"$regex": "^a", "$options": "i"}},
         {"name": {"$regex": MASK, "$options": MASK}}),
        ({"r": {"$regularExpression": {"pattern": "^a", "options": "i"}}}, {"r": MASK}),
    ]

    def test_server_redaction_matches_server_unit_tests(self):
        for src, want in self.SERVER_TEST_CASES:
            for flags in ([], ['--char_replacement']):
                a = self.run_attr({"command": {"find": "c", "filter": src, "$db": "d"}}, *flags)
                self.assertEqual(a["command"]["filter"], want, (src, flags))

    def test_server_redaction_matches_reference_model(self):
        commands = [
            {"find": "customer_profiles", "filter": {"email": "a@b.com", "age": {"$gt": 18},
             "ok": True, "tags": ["a", "b"], "n": None, "_id": {"$oid": "6ac613bb0c8d1d7c44cf7be3"},
             "when": {"$date": "2026-10-07T09:41:16Z"}, "big": {"$numberLong": "123"}},
             "limit": 5, "$db": "acmeshopdb"},
            {"insert": "c", "ordered": True, "documents": [{"a": 1, "b": {"c": [1, 2, {"d": "x"}]}},
             {"bin": binary(B64_0, 0), "cipher": binary(B64_6, 6)}], "$db": "d"},
            {"update": "c", "updates": [{"q": {"a": {"$in": [1, 2, 3]}}, "u": {"$set": {"b": "z"}},
             "multi": False, "upsert": True, "arrayFilters": [{"e.x": "y"}]}], "$db": "d"},
            {"aggregate": "c", "pipeline": [{"$match": {"$expr": {"$eq": ["$ssn", "999"]}}},
             {"$lookup": {"from": "o", "localField": "a", "foreignField": "b", "as": "r"}},
             {"$group": {"_id": "$email", "n": {"$sum": 1}}}], "cursor": {}, "$db": "d"},
            {"findAndModify": "c", "query": {"x": {"$regex": "^a", "$options": "i"}},
             "update": {"$inc": {"n": 1}}, "new": True, "$db": "d"},
            {"getMore": 123456789, "collection": "c", "batchSize": 10, "$db": "d",
             "$clusterTime": {"clusterTime": {"$timestamp": {"t": 1, "i": 1}},
                              "signature": {"hash": binary("AAAA", 0), "keyId": 7}}},
        ]
        for cmd in commands:
            want = server_redact_all(cmd)
            for flags in ([], ['--char_replacement']):
                got = self.run_attr({"command": cmd}, *flags)["command"]
                self.assertEqual(got, want, (list(cmd)[0], flags))

    def test_server_redaction_schema_keys_are_still_obfuscated(self):
        """Deliberate deviation: the server keeps the keys of sort / hint / projection
        (index and field names); this tool never does."""
        cmd = {"find": "c", "filter": {"a": 1}, "sort": {"notes_secret_index": -1},
               "hint": {"ssn_lookup_idx": 1}, "projection": {"identity.ssn": 1}, "$db": "d"}
        for flags in ([], ['--char_replacement']):
            got = self.run_attr({"command": cmd}, *flags)["command"]
            blob = json.dumps(got)
            for name in ("notes_secret_index", "ssn_lookup_idx", "identity.ssn"):
                self.assertNotIn(name, blob, flags)
            self.assertEqual(set(got["sort"].values()), {MASK})       # values are masked
            self.assertEqual(got["filter"], {"a": MASK})

    def test_server_redaction_other_data_attrs_and_oplog_entry(self):
        """bgsync.cpp logs `lastOplogEntry = redact(oplogEntry)`."""
        entry = {"op": "u", "ns": "shop.customers", "ui": {"$uuid": "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"},
                 "o": {"$v": 2, "diff": {"u": {"email": "a@b.com"}}}, "o2": {"_id": "C-1"},
                 "ts": {"$timestamp": {"t": 1, "i": 1}}, "t": 1, "wall": {"$date": "2026-10-07T00:00:00Z"}}
        a = self.run_attr({"CRUD": entry, "keyValue": {"email": "a@b.com"},
                           "errInfo": {"failingDocumentId": "C-9", "details": {"x": "y"}}})
        self.assertEqual(a["CRUD"]["o"], server_redact_all(entry["o"]))
        self.assertEqual(a["CRUD"]["o2"], {"_id": MASK})
        self.assertEqual(a["keyValue"], {"email": MASK})
        self.assertEqual(a["errInfo"], server_redact_all({"failingDocumentId": "C-9", "details": {"x": "y"}}))

    def test_server_redaction_status_exception_and_what_forms(self):
        cases = {
            "Unauthorized: not authorized on acmeshopdb to execute command { find: \"c\" }":
                "Unauthorized: " + MASK,                       # redact(Status)
            "InternalError: Not initialized": "InternalError: " + MASK,
            # Status with extra info, seen in a real server log: the server keeps only the code name
            "ShutdownInProgress{ remainingQuiesceTimeMillis: 0 }: Replication is being shut down; "
            "Error details: { writeConcern: { w: \"majority\" } }": "ShutdownInProgress: " + MASK,
            "DuplicateKey: E11000 duplicate key error ... dup key: { email: \"a@b.com\" }":
                "DuplicateKey: " + MASK,
            "something unexpected happened for alice": MASK,   # redact(e.what())
            "OK": "OK",                                        # redact(Status::OK())
            "InternalError " + MASK: "InternalError " + MASK,  # redact(DBException), already masked
        }
        for text, want in cases.items():
            a = self.run_attr({"error": text})
            self.assertEqual(a["error"], want, text)

    def test_server_redaction_structured_status_keeps_code_drops_reason(self):
        a = self.run_attr({"error": {"code": 13, "codeName": "Unauthorized",
                                     "errmsg": "not authorized on acmeshopdb to execute command"}})
        self.assertEqual(a["error"], {"code": 13, "codeName": "Unauthorized", "errmsg": MASK})

    def test_server_redaction_mask_ignores_char_replacement_and_keeps_other_rules(self):
        attr = {"ns": "acmeshopdb.customers", "appName": "AcmeApp", "remote": "10.20.30.40:5555",
                "command": {"find": "customers", "filter": {"email": "a@b.com"}, "$db": "acmeshopdb"},
                "error": "Unauthorized: boom"}
        word = self.run_attr(attr)
        xpat = self.run_attr(attr, '--char_replacement')
        self.assertEqual(word["command"], xpat["command"])            # "###" in both styles
        self.assertEqual(word["error"], xpat["error"])
        for a in (word, xpat):                                        # extra rules still apply
            blob = json.dumps(a)
            for leak in ("acmeshopdb", "customers", "AcmeApp", "10.20.30.40", "a@b.com"):
                self.assertNotIn(leak, blob)

    def test_server_redaction_canary_corpus_both_styles(self):
        """The full synthetic corpus: no canary survives --server_redaction."""
        p = os.path.join(self.tmp.name, 'corpus.log')
        with open(p, 'w') as fh:
            for ent in build_entries():
                fh.write(json.dumps(ent) + '\n')
        for flags in ([], ['--char_replacement'],
                      ['--redactNamespaces', '--seed', 'k']):
            r = subprocess.run([sys.executable, SCRIPT, '--log_redact', p, *flags],
                               capture_output=True, text=True, timeout=300)
            self.assertEqual(r.returncode, 0, r.stderr[-400:])
            lines = [x for x in r.stdout.splitlines() if x.strip()]
            self.assertEqual(len(lines), len(build_entries()))
            for ln in lines:
                json.loads(ln)
            leaked = [c for c in ALWAYS + STRICT_ONLY if c in r.stdout]
            self.assertEqual(leaked, [], (flags, leaked))

    def test_log_only_options_rejected_for_ftdc(self):
        for opt in (['--seed', 'x'], ['--redactNamespaces'], ['--char_replacement'],
                    ['--addFields', 'a']):
            r = subprocess.run([sys.executable, SCRIPT, '--ftdc_redact', '--input_dir', self.tmp.name,
                                '--output_dir', self.tmp.name + '/o', *opt],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, opt)
            self.assertIn('only valid with --log_redact', r.stderr)


# ══════════════════════════════════════════════════════════════════════════════
# --loadSchemaFile  x  --addFields : "default (+ schema) (+ fields)"
# ══════════════════════════════════════════════════════════════════════════════

CAN_DEFAULT = 'alice.smith@acme-corp.com'           # built-in PII rule (field "email")
CAN_ADD = 'add-canary-grid-001'                      # only --addFields grId
CAN_SCHEMA = 'schema-canary-tenantref-77'            # schema "fields": tenantRef
CAN_PATH = 'schema-canary-path-vip-1'                # schema "paths": customer.vipCode
CAN_NESTED = 'schema-canary-nested-tier-9'           # schema "schema": {"loyalty": {"tier": true}}
CAN_KEEP = 'keep-canary-vendor-vip-5'                # vendor.vipCode: NOT in the schema path
CAN_DEEP = 'keep-canary-customer-items-vip-3'        # customer.items.$[e].vipCode: path is contiguous -> NOT matched

SCHEMA_DOC = {"fields": ["tenantRef"],
              "paths": ["customer.vipCode"],
              "schema": {"loyalty": {"tier": True}}}


def schema_corpus():
    """One entry per CONTEXT in which a field can show up OUTSIDE client data.
    (Client data - commands, filters, documents, oplog entries - is masked by the DEFAULT
    policy whatever the options are; the schema / --addFields rules extend the default to
    every other place, see test_client_data_is_always_masked_whatever_the_options.)"""
    E = []
    # 1 generic attrs
    E.append(L("COMMAND", "c1", 1, "generic attrs", {
        "email": CAN_DEFAULT, "grId": CAN_ADD, "tenantRef": CAN_SCHEMA,
        "customer": {"vipCode": CAN_PATH, "name_": "n"}, "vendor": {"vipCode": CAN_KEEP},
        "loyalty": {"tier": CAN_NESTED}}))
    # 2 query-shaped document in a container the server does not treat as client data
    E.append(L("COMMAND", "c2", 2, "query shaped", {"ctxFilter": {
        "email": CAN_DEFAULT, "grId": CAN_ADD, "tenantRef": {"$in": [CAN_SCHEMA]},
        "customer.vipCode": CAN_PATH, "loyalty": {"tier": CAN_NESTED},
        "vendor.vipCode": CAN_KEEP}}))
    E.append(L("COMMAND", "c3", 3, "elemMatch", {"ctxFilter": {
        "customer": {"$elemMatch": {"vipCode": CAN_PATH}},
        "vendor": {"$elemMatch": {"vipCode": CAN_KEEP}}}}))
    E.append(L("COMMAND", "c4", 4, "arrays", {"ctxFilter": {
        "customer": [{"vipCode": CAN_PATH}, {"vipCode": CAN_PATH + "-2"}]}}))
    # 3 update operators on dotted / positional paths
    E.append(L("COMMAND", "c5", 5, "set", {"ctxUpdate": {
        "$set": {"customer.vipCode": CAN_PATH, "customer.items.$[e].vipCode": CAN_DEEP,
                 "grId": CAN_ADD, "tenantRef": CAN_SCHEMA, "loyalty.tier": CAN_NESTED,
                 "vendor.vipCode": CAN_KEEP}}}))
    # 4 comparisons against field references
    E.append(L("COMMAND", "c6", 6, "refs", {"check": [
        {"$eq": ["$grId", CAN_ADD]},
        {"$eq": ["$tenantRef", CAN_SCHEMA]},
        {"$eq": ["$customer.vipCode", CAN_PATH]},
        {"$eq": ["$vendor.vipCode", CAN_KEEP]}]}))
    # 5 a sub-document
    E.append(L("REPL", "c7", 7, "doc", {"ctxDoc": {
        "_": 1, "grId": CAN_ADD, "tenantRef": CAN_SCHEMA,
        "customer": {"vipCode": CAN_PATH}, "loyalty": {"tier": CAN_NESTED}}}))
    # 6 JSON serialised inside a string
    E.append(L("COMMAND", "c8", 8, "embedded", {"blob": json.dumps({
        "grId": CAN_ADD, "tenantRef": CAN_SCHEMA, "customer": {"vipCode": CAN_PATH},
        "vendor": {"vipCode": CAN_KEEP}})}))
    # 7 free text
    E.append(L("COMMAND", "c9", 9, "free text", {
        "freeText": f"bad value tenantRef: {CAN_SCHEMA} and grId: {CAN_ADD}"}))
    return E


def client_data_entry():
    """The same values inside real client data (a command)."""
    return L("COMMAND", "c10", 10, "Slow query", {"type": "command", "ns": "shop.cust", "command": {
        "find": "cust", "$db": "shop", "filter": {
            "email": CAN_DEFAULT, "grId": CAN_ADD, "tenantRef": CAN_SCHEMA,
            "customer.vipCode": CAN_PATH, "loyalty": {"tier": CAN_NESTED},
            "vendor.vipCode": CAN_KEEP, "customer.items.$[e].vipCode": CAN_DEEP}}})


COMBOS = {              # label -> (uses schema file, uses --addFields)
    'none': (False, False), 'schema': (True, False),
    'addFields': (False, True), 'schema+addFields': (True, True),
}


class SchemaFileTests(unittest.TestCase):
    """default | default+schema | default+fields | default+schema+fields"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.log = os.path.join(cls.tmp.name, 'schema.log')
        with open(cls.log, 'w') as fh:
            for e in schema_corpus():
                fh.write(json.dumps(e) + '\n')
        cls.schema = os.path.join(cls.tmp.name, 'schema.json')
        with open(cls.schema, 'w') as fh:
            json.dump(SCHEMA_DOC, fh)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_tool(self, *flags, log=None):
        return subprocess.run([sys.executable, SCRIPT, '--log_redact', log or self.log, *flags],
                              capture_output=True, text=True, timeout=120)

    def flags_for(self, combo, *extra):
        use_schema, use_add = COMBOS[combo]
        f = list(extra)
        if use_schema:
            f += ['--loadSchemaFile', self.schema]
        if use_add:
            f += ['--addFields', 'grId']
        return f

    def expected_gone(self, combo):
        use_schema, use_add = COMBOS[combo]
        gone = {CAN_DEFAULT}
        if use_add:
            gone.add(CAN_ADD)
        if use_schema:
            gone |= {CAN_SCHEMA, CAN_PATH, CAN_NESTED, CAN_PATH + '-2'}
        return gone

    ALL = [CAN_DEFAULT, CAN_ADD, CAN_SCHEMA, CAN_PATH, CAN_NESTED, CAN_PATH + '-2', CAN_DEEP]

    # ---- the rule, for every option combination x style x mode --------------------------
    def test_rule_matrix(self):
        """none -> default | schema -> default+schema | addFields -> default+fields |
        both -> default+schema+fields, in fruit and in x style."""
        for combo in COMBOS:
            for style in ([], ['--char_replacement']):
                flags = self.flags_for(combo, *style)
                r = self.run_tool(*flags)
                self.assertEqual(r.returncode, 0, (flags, r.stderr[-300:]))
                out = r.stdout
                for ln in out.splitlines():
                    json.loads(ln)
                gone = self.expected_gone(combo)
                for c in self.ALL:
                    if c in gone:
                        self.assertNotIn(c, out, f'LEAK {c!r} with {combo} {style}')
                    else:                 # not asked for -> the DEFAULT rules only: stays visible
                        self.assertIn(c, out, f'{c!r} wrongly redacted with {combo} {style}')
                self.assertIn(CAN_KEEP, out)         # never matched by any rule of any combination

    def test_client_data_is_always_masked_whatever_the_options(self):
        """Inside a command the default policy already masks every literal, so all four
        combinations give the same client-data result; the schema only adds reach."""
        p = os.path.join(self.tmp.name, 'client.log')
        with open(p, 'w') as fh:
            fh.write(json.dumps(client_data_entry()) + '\n')
        outs = set()
        for combo in COMBOS:
            for style in ([], ['--char_replacement']):
                r = self.run_tool(*self.flags_for(combo, *style), log=p)
                self.assertEqual(r.returncode, 0, r.stderr[-300:])
                for c in self.ALL + [CAN_KEEP]:
                    self.assertNotIn(c, r.stdout, (combo, style, c))
                filt = json.loads(r.stdout)['attr']['command']['filter']
                leaves = []
                walk = lambda n: ([walk(x) for x in n.values()] if isinstance(n, dict)
                                  else [walk(x) for x in n] if isinstance(n, list) else leaves.append(n))
                walk(filt)
                self.assertEqual(set(leaves), {MASK}, (combo, style))
                outs.add(json.dumps(filt, sort_keys=True))
        self.assertEqual(len(outs), 1, 'the mask of client data must not depend on schema / --addFields')

    def test_path_precision_vendor_not_redacted_by_customer_path(self):
        for combo in ('schema', 'schema+addFields'):
            out = self.run_tool(*self.flags_for(combo)).stdout
            self.assertIn(CAN_KEEP, out)
            # ... and in every context the vendor value stays (dotted key, $elemMatch, $set, $expr)
            self.assertGreaterEqual(out.count(CAN_KEEP), 6)
            self.assertIn(CAN_DEEP, out)         # contiguous path: customer.items.*.vipCode is a different path

    def test_path_is_contiguous_bare_name_matches_any_depth(self):
        out = self.run_tool('--loadSchemaFile', self.schema).stdout
        self.assertIn(CAN_DEEP, out)                              # customer.items.$[e].vipCode
        p = self.write_schema('bare_vip.json', {"fields": ["vipCode"]})
        out2 = self.run_tool('--loadSchemaFile', p).stdout
        for c in (CAN_PATH, CAN_DEEP, CAN_KEEP):                  # any depth, any parent
            self.assertNotIn(c, out2)

    def test_path_in_aggregation_field_reference_and_free_text(self):
        ent = L("COMMAND", "c1", 1, "refs and text", {
            "freeText": f"bad value customer.vipCode: {CAN_PATH} but vendor.vipCode: {CAN_KEEP}",
            "check": [{"$eq": ["$customer.vipCode", CAN_PATH]},
                      {"$in": [CAN_PATH + "-9", ["$customer.vipCode"]]},
                      {"$eq": ["$vendor.vipCode", CAN_KEEP]}]})
        p = os.path.join(self.tmp.name, 'ref.log')
        with open(p, 'w') as fh:
            fh.write(json.dumps(ent) + '\n')
        out = self.run_tool('--loadSchemaFile', self.schema, log=p).stdout
        self.assertNotIn(CAN_PATH, out)
        self.assertNotIn(CAN_PATH + '-9', out)
        self.assertIn(CAN_KEEP, out)                      # vendor.vipCode is a different path

    def test_flat_names_and_builtin_pii_in_comparisons_outside_client_data(self):
        """{"$eq": ["$grId", <v>]} in a container that is not client data: the literal is a
        value of the --addFields / schema field (or of a built-in PII key such as $email)."""
        ent = L("COMMAND", "c1", 1, "refs", {"check": [
            {"$eq": ["$grId", CAN_ADD]}, {"$in": [CAN_ADD + "-2", ["$grId"]]},
            {"$eq": ["$email", CAN_DEFAULT]}, {"$eq": ["$other", CAN_KEEP]}]})
        p = os.path.join(self.tmp.name, 'ref2.log')
        with open(p, 'w') as fh:
            fh.write(json.dumps(ent) + '\n')
        none = self.run_tool(log=p).stdout
        self.assertIn(CAN_ADD, none)                       # not requested -> default rules only
        self.assertNotIn(CAN_DEFAULT, none)                # built-in PII key reference
        added = self.run_tool('--addFields', 'grId', log=p).stdout
        self.assertNotIn(CAN_ADD, added)
        self.assertNotIn(CAN_ADD + '-2', added)
        self.assertIn(CAN_KEEP, added)

    def test_flat_schema_field_matches_like_add_fields_everywhere(self):
        out = self.run_tool('--loadSchemaFile', self.schema).stdout
        self.assertNotIn(CAN_SCHEMA, out)         # $in operand, $set, $expr ref, CRUD.o, JSON string, free text

    def test_style_fruit_vs_x_for_schema_values(self):
        fruit = json.loads(self.run_tool('--loadSchemaFile', self.schema).stdout.splitlines()[0])
        xpat = json.loads(self.run_tool('--loadSchemaFile', self.schema,
                                        '--char_replacement').stdout.splitlines()[0])
        for key, path in (('tenantRef', ('attr', 'tenantRef')),
                          ('vipCode', ('attr', 'customer', 'vipCode')),
                          ('tier', ('attr', 'loyalty', 'tier'))):
            fv, xv = fruit, xpat
            for seg in path:
                fv, xv = fv[seg], xv[seg]
            self.assertNotEqual(fv, SCHEMA_PLAIN[key])
            self.assertRegex(xv, r'^[x\-]+$', (key, xv))       # x-pattern keeps punctuation only
            self.assertNotRegex(fv, r'^[x\-]+$', (key, fv))    # fruit / colour words

    def test_union_equals_add_fields_with_the_same_names(self):
        """schema fields + --addFields == one --addFields with both lists."""
        a = self.run_tool('--seed', 's', '--loadSchemaFile', self.schema,
                          '--addFields', 'grId').stdout
        # the dotted path can only come from the file: compare on the flat names
        flat = os.path.join(self.tmp.name, 'flat.json')
        with open(flat, 'w') as fh:
            json.dump({"fields": ["tenantRef"]}, fh)
        b = self.run_tool('--seed', 's', '--loadSchemaFile', flat, '--addFields', 'grId').stdout
        c = self.run_tool('--seed', 's', '--addFields', 'grId,tenantRef').stdout
        self.assertEqual(b, c)
        self.assertNotEqual(a, c)                  # the path/nested part adds redactions

    def test_deterministic_with_seed(self):
        f = self.flags_for('schema+addFields', '--seed', 'abc')
        self.assertEqual(self.run_tool(*f).stdout, self.run_tool(*f).stdout)

    def test_works_with_redact_namespaces_and_seed(self):
        f = self.flags_for('schema+addFields', '--redactNamespaces', '--seed', 'k')
        out = self.run_tool(*f).stdout
        for c in self.ALL:
            if c != CAN_DEEP:                  # contiguous path: customer.items.$[e].vipCode is another path
                self.assertNotIn(c, out)
        self.assertIn(CAN_DEEP, out)

    # ---- file formats ---------------------------------------------------------------------
    def write_schema(self, name, content):
        p = os.path.join(self.tmp.name, name)
        with open(p, 'w') as fh:
            fh.write(content if isinstance(content, str) else json.dumps(content))
        return p

    def test_file_formats(self):
        variants = {
            'array.json': ["tenantRef", "$grId", "CUSTOMER.vipcode"][:2],         # shorthand for "fields"
            'bare_nested.json': {"customer": {"vipCode": True}, "loyalty": {"tier": {}}},
            'fields_only.json': {"fields": ["tenantRef"]},
            'paths_only.json': {"paths": ["customer.vipCode", "loyalty.tier"]},
            'one_segment_path.json': {"paths": ["tenantRef"]},
            'false_leaf.json': {"schema": {"customer": {"vipCode": True, "zip": False}}},
            'meta_keys.json': {"version": 1, "description": "x", "fields": ["tenantRef"]},
        }
        want = {
            'array.json': {CAN_SCHEMA, CAN_ADD},
            'bare_nested.json': {CAN_PATH, CAN_NESTED},
            'fields_only.json': {CAN_SCHEMA},
            'paths_only.json': {CAN_PATH, CAN_NESTED},
            'one_segment_path.json': {CAN_SCHEMA},
            'false_leaf.json': {CAN_PATH},
            'meta_keys.json': {CAN_SCHEMA},
        }
        for name, doc in variants.items():
            p = self.write_schema(name, doc)
            out = self.run_tool('--loadSchemaFile', p).stdout
            for c in want[name]:
                self.assertNotIn(c, out, (name, c))
            for c in {CAN_SCHEMA, CAN_PATH, CAN_NESTED, CAN_ADD} - want[name]:
                self.assertIn(c, out, (name, c))

    def test_case_insensitive_dollar_optional_and_dotted_match(self):
        p = self.write_schema('ci.json', {"fields": ["$TENANTREF", "GrId"], "paths": ["Customer.VIPCODE"]})
        out = self.run_tool('--loadSchemaFile', p).stdout
        for c in (CAN_SCHEMA, CAN_ADD, CAN_PATH, CAN_PATH + '-2', CAN_PATH + '-3'):
            self.assertNotIn(c, out)
        self.assertIn(CAN_KEEP, out)

    def test_empty_schema_is_a_noop(self):
        base = self.run_tool('--seed', 's').stdout
        for doc in ({}, {"fields": []}, [], {"paths": []}):
            p = self.write_schema('empty.json', doc)
            self.assertEqual(self.run_tool('--seed', 's', '--loadSchemaFile', p).stdout, base)

    def test_legacy_text_log(self):
        tl = os.path.join(self.tmp.name, 'legacy.log')
        with open(tl, 'w') as fh:
            fh.write('2019-03-01T10:00:00.123+0000 I COMMAND  [conn7] command db.c command: find '
                     '{ find: "c", filter: { tenantRef: "legacy-canary-tenant", grId: "legacy-canary-grid" } } '
                     'planSummary: COLLSCAN 12ms\n')
        for flags, gone, kept in (
                ([], [], ["legacy-canary-tenant"]),
                (['--loadSchemaFile', self.schema], ["legacy-canary-tenant"], []),
                (['--addFields', 'grId'], ["legacy-canary-grid"], []),
                (['--loadSchemaFile', self.schema, '--addFields', 'grId'],
                 ["legacy-canary-tenant", "legacy-canary-grid"], [])):
            out = self.run_tool(*flags, log=tl).stdout
            for g in gone:
                self.assertNotIn(g, out, flags)
            self.assertIn('COLLSCAN', out)

    # ---- validation: clean one-line errors, exit code 2, no traceback -----------------------------
    def assert_rejected(self, path_or_doc, needle, name='bad.json'):
        p = path_or_doc if isinstance(path_or_doc, str) and os.path.isabs(path_or_doc) \
            else self.write_schema(name, path_or_doc)
        r = self.run_tool('--loadSchemaFile', p)
        self.assertEqual(r.returncode, 2, r.stderr[-300:])
        self.assertIn('--loadSchemaFile', r.stderr)
        self.assertIn(needle, r.stderr)
        self.assertNotIn('Traceback', r.stderr)
        self.assertEqual(r.stdout, '')

    def test_rejects_missing_file(self):
        self.assert_rejected(os.path.join(self.tmp.name, 'nope.json'), 'not found')

    def test_rejects_invalid_json(self):
        self.assert_rejected('{"fields": [', 'not valid JSON')

    def test_rejects_wrong_types(self):
        self.assert_rejected({"fields": "grId"}, '"fields" must be a list')
        self.assert_rejected({"fields": ["ok", ""]}, '"fields" must be a list')
        self.assert_rejected({"fields": [1]}, '"fields" must be a list')
        self.assert_rejected({"paths": ["a.b", 5]}, '"paths" must be a list')
        self.assert_rejected({"paths": ["..."]}, 'empty path')
        self.assert_rejected({"schema": {"a": 5}}, 'must be true, an object, or null')
        self.assert_rejected({"schema": ["a"]}, '"schema" must be an object')
        self.assert_rejected('"just a string"', 'JSON object or array')
        self.assert_rejected('42', 'JSON object or array')

    def test_rejects_binary_garbage(self):
        p = os.path.join(self.tmp.name, 'bin.json')
        with open(p, 'wb') as fh:
            fh.write(b'\xff\xfe\x00\x01garbage')
        self.assert_rejected(p, 'schema file')

    def test_rejected_for_ftdc(self):
        r = subprocess.run([sys.executable, SCRIPT, '--ftdc_redact', '--input_dir', self.tmp.name,
                            '--output_dir', self.tmp.name + '/o', '--loadSchemaFile', self.schema],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('only valid with --log_redact', r.stderr)

    def test_schema_file_content_never_echoed_on_error(self):
        secret = "SCHEMA-SECRET-FIELD-NAME-123"
        p = self.write_schema('secret.json', '{"fields": ["' + secret + '", 5]}')
        r = self.run_tool('--loadSchemaFile', p)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn(secret, r.stderr)


SCHEMA_PLAIN = {'tenantRef': CAN_SCHEMA, 'vipCode': CAN_PATH, 'tier': CAN_NESTED}
SRC_FIRST_LINE = {CAN_DEFAULT, CAN_ADD, CAN_SCHEMA, CAN_PATH, CAN_NESTED, CAN_KEEP}


if __name__ == '__main__':
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
test_integration_mongo.py - end-to-end PII test of ofuscator.py against REAL
mongod / mongos logs.

  * `m`      installs the requested MongoDB version (without permanently
             changing your active version - symlinks are restored).
  * `mtools` (mlaunch) spins up a minimal AUTH-ENABLED sharded cluster:
             1 shard (single-node replica set) + 1 config server + 1 mongos,
             with slowms=0 so every operation is logged.
  * A PII-heavy workload runs through the mongos (CRUD, aggregation, dup-key
    and validation errors, transactions, change streams, index builds, sharding
    admin, users / failed logins, several appNames ...).
  * The three real logs (mongos, shard mongod, config mongod) are then pushed
    through ofuscator.py under a matrix of flags and checked.

Usage
-----
    python3 test_integration_mongo.py 5.0            # newest installable 5.0.x
    python3 test_integration_mongo.py 5.0.31 -v      # exact version
    python3 test_integration_mongo.py 7.0 --shards 2 # 2 shards (adds moveChunk)
    python3 test_integration_mongo.py 5.0 --keep     # keep cluster dir + logs
    python3 test_integration_mongo.py 5.0 --use-logs DIR   # re-test saved logs
    OFUSCATOR_MONGO_VERSION=5.0 python3 -m unittest test_integration_mongo

Needs: `m` (https://github.com/aheckmann/m), `pip install mtools pymongo`.
"""
import argparse
import base64
import collections
import getpass
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'ofuscator.py')

CONFIG = {
    'version': os.environ.get('OFUSCATOR_MONGO_VERSION'),
    'keep': False,
    'shards': 1,
    'use_logs': None,
    'port': None,
    'ground_truth': False,
}

# ══════════════════════════════════════════════════════════════════════════════
# Canaries - fake PII the workload pushes into the cluster
# ══════════════════════════════════════════════════════════════════════════════

JWT_CANARY = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl'
# BinData subtype 6 (Encrypt) / 8 (Sensitive): the server masks them in its own logs
# only from a certain version on (and subtype 8 always); older servers print the
# base64.  ofuscator must mask them whatever the source version does.
BIN6_BYTES = b'bindata-cipher-canary-6'
BIN8_BYTES = b'bindata-sensitive-canary-8'
B64_BIN6 = base64.b64encode(BIN6_BYTES).decode()
B64_BIN8 = base64.b64encode(BIN8_BYTES).decode()
SCHEMA_DOC = {"fields": ["tenantRef"],
              "paths": ["customer.vipCode"],
              "schema": {"loyalty": {"tier": True}}}
ADMIN_USER = 'acme_root_user'
ADMIN_PASS = 'Secr3tPassw0rd'
UNKNOWN_USER = 'mary.watson'

C = {
    # values of (built-in) PII field names / PII shapes: must vanish in EVERY mode
    'listed': [
        'alice.smith@acme-corp.com', 'bob.jones@acme-corp.com',
        'carol.white@acme-corp.com', 'manager.x@acme-corp.com',
        'dup-key-canary@acme-corp.com', 'acme-corp.com',
        '123-45-6789', '987654321', '555-44-3333',
        '4111111111111111', '4111 1111 1111 1111',
        '+1-555-010-9999', '555-010-9999',
        'GB82WEST12345698765432',
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl',
        'tok_live_9f8e7d6c5b4a', '$2b$12$canaryBcryptHashValue0123456789',
        'Alice Smith', 'Wonderland Street 42', '203.0.113.77',
        '00:1A:2B:3C:4D:5E', 'P1234567X', 'C-99887766', 'C-99887755',
        'C-dup-canary-0001', 'validation-canary-ssn-abc',
        'comment-canary-tenant-42', 'hello-regex-canary',
        'chunk-split-canary-5000', 'inc-canary-value', 'push-canary-doc-id',
        'where-canary-bob', 'text-search-canary',
        'resume-stream-canary',
    ],
    # names: users, apps, db / collection / index names, secrets
    'names': [
        'AcmeBillingService', 'AcmeReportsApp', 'AcmeShardDirect',
        ADMIN_USER, ADMIN_PASS, UNKNOWN_USER, 'jsmith_admin',
        'acmeshopdb', 'customer_profiles', 'acme_orders',
        'acme_orders_renamed', 'acme_archive_db', 'customer_profiles_archive',
        'ssn_lookup_idx', 'email_unique_idx', 'notes_secret_index',
    ],
    # values of UNLISTED field names: only --strict is expected to remove them
    'strict': [
        'unlisted-free-text-canary', 'another-unlisted-canary-77',
        'nickname-like-canary-zed', 'filter-unlisted-canary-9',
        'txn-canary-order-7781',
    ],
    # custom field removed via --addFields grId
    'addfields': ['grid-canary-xyz-001', 'grid-canary-xyz-002'],
    # --loadSchemaFile: flat field / dotted path / nested form; 'keep' = vendor.vipCode is NOT in the path
    'schema': ['schema-canary-tenantref-77', 'schema-canary-path-vip-1', 'schema-canary-nested-tier-9'],
    'schema_keep': ['keep-canary-vendor-vip-5'],
    # BinData 6 / 8 payloads (may be masked by the server itself on newer versions)
    'bindata': [B64_BIN6, B64_BIN8],
}


def environment_canaries(workdir):
    """Machine-specific strings that must never survive either."""
    env = {getpass.getuser(), socket.gethostname(), workdir}
    env.add(socket.gethostname().split('.')[0])
    return sorted(x for x in env if x and len(x) >= 4)


# ══════════════════════════════════════════════════════════════════════════════
# m: resolve + install a version (restoring the user's active version)
# ══════════════════════════════════════════════════════════════════════════════

def run(cmd, **kw):
    kw.setdefault('capture_output', True)
    kw.setdefault('text', True)
    return subprocess.run(cmd, **kw)


def m_installed():
    out = run(['m', 'installed', '--json'])
    if out.returncode:
        raise RuntimeError('`m installed` failed: ' + out.stderr)
    return {e['name']: e['path'].strip() for e in json.loads(out.stdout)}


class ActiveVersionGuard:
    """`m <ver>` re-points mongod/mongos/mongo... symlinks.  Snapshot and
    restore them so running this test never changes the user's active version."""

    def __init__(self):
        exe = shutil.which('mongod')
        self.dir = os.path.dirname(exe) if exe else None
        self.snap = {}

    def __enter__(self):
        if self.dir:
            for f in os.listdir(self.dir):
                p = os.path.join(self.dir, f)
                if os.path.islink(p):
                    self.snap[p] = os.readlink(p)
        return self

    def __exit__(self, *exc):
        for p, target in self.snap.items():
            try:
                if not os.path.islink(p) or os.readlink(p) != target:
                    if os.path.lexists(p):
                        os.remove(p)
                    os.symlink(target, p)
            except OSError as e:          # pragma: no cover
                sys.stderr.write(f'WARNING: could not restore {p}: {e}\n')


def resolve_and_install(spec):
    """'5.0' -> newest 5.0.x that can be installed on THIS platform (e.g. the
    last 5.0 with macOS binaries); 'X.Y.Z' -> exactly that.  Returns
    (version, bin_dir)."""
    exact = re.fullmatch(r'\d+\.\d+\.\d+(?:-ent)?', spec)
    if exact:
        cands = [spec]
    else:
        listing = run(['m', 'ls']).stdout
        found = set(re.findall(r'(?m)^\s*\*?\s*(%s\.\d+)\s*$' % re.escape(spec), listing))
        cands = sorted(found, key=lambda v: tuple(int(x) for x in v.split('.')),
                       reverse=True)
        if not cands:
            raise RuntimeError(f'`m ls` lists no {spec}.x versions')
    with ActiveVersionGuard():
        installed = m_installed()
        for ver in cands:
            if ver in installed:
                return ver, installed[ver]
            sys.stderr.write(f'[m] installing {ver} ...\n')
            r = run(['m', ver], env=dict(os.environ, M_CONFIRM='0'),
                    timeout=1800)
            if r.returncode == 0 and ver in m_installed():
                return ver, m_installed()[ver]
            sys.stderr.write(f'[m] {ver} not installable on this platform, '
                             f'trying the next older one\n')
    raise RuntimeError(f'none of {cands[:5]}... could be installed')


# ══════════════════════════════════════════════════════════════════════════════
# mtools: minimal sharded cluster
# ══════════════════════════════════════════════════════════════════════════════

def free_port_block(n=12, start=27700):
    for base in range(start, start + 2000, 20):
        ok = True
        for p in range(base, base + n):
            with socket.socket() as s:
                if s.connect_ex(('127.0.0.1', p)) == 0:
                    ok = False
                    break
        if ok:
            return base
    raise RuntimeError('no free port block')


class Cluster:
    def __init__(self, bin_dir, workdir, shards, port=None):
        self.bin_dir, self.dir, self.shards = bin_dir, workdir, shards
        self.port = port or free_port_block()

    def start(self):
        names = ['shard%d' % i for i in range(1, self.shards + 1)]
        cmd = ['mlaunch', 'init', '--dir', self.dir, '--binarypath', self.bin_dir,
               '--replicaset', '--nodes', '1', '--sharded', *names,
               '--config', '1', '--mongos', '1', '--port', str(self.port),
               '--hostname', 'localhost', '--auth', '--username', ADMIN_USER,
               '--password', ADMIN_PASS, '--auth-db', 'admin']
        r = run(cmd, timeout=600)
        if r.returncode:
            raise RuntimeError('mlaunch init failed:\n' + r.stdout[-2000:] + r.stderr[-2000:])

    def uri(self, user=ADMIN_USER, pw=ADMIN_PASS, **kw):
        auth = f'{user}:{pw}@' if user else ''
        q = 'authSource=admin' + ''.join(f'&{k}={v}' for k, v in kw.items())
        return f'mongodb://{auth}localhost:{self.port}/?{q}'

    def _procs(self):
        import psutil
        out = []
        for p in psutil.process_iter(['pid', 'cmdline']):
            try:
                if any(self.dir in part for part in (p.info['cmdline'] or [])):
                    out.append(p)
            except (psutil.Error, OSError):
                pass
        return out

    def stop(self):
        """Stop every process of the cluster and PROVE they are gone.
        (mongos keeps running through a quiesce period after SIGTERM.)"""
        import psutil
        if os.path.isdir(self.dir):
            run(['mlaunch', 'stop', '--dir', self.dir], timeout=180)
        deadline = time.time() + 60
        while self._procs() and time.time() < deadline:
            time.sleep(0.5)
        for p in self._procs():                       # still alive: escalate
            try:
                p.terminate()
            except psutil.Error:
                pass
        gone, alive = psutil.wait_procs(self._procs(), timeout=10)
        for p in alive:
            try:
                p.kill()
            except psutil.Error:
                pass
        if self._procs():
            sys.stderr.write('[test] WARNING: cluster processes still running\n')

    def logs(self):
        found = sorted(glob.glob(os.path.join(self.dir, '**', '*.log'), recursive=True))
        return {os.path.relpath(p, self.dir).replace(os.sep, '_'): p for p in found
                if os.path.getsize(p) > 0}


# ══════════════════════════════════════════════════════════════════════════════
# Workload
# ══════════════════════════════════════════════════════════════════════════════

def customer(i, **over):
    doc = {
        '_id': f'C-{99887766 - i * 11}' if i < 2 else f'cust-{i:05d}',
        'customerId': 'C-99887766' if i == 0 else 'C-99887755' if i == 1 else f'C-{i:08d}',
        'name': 'Alice Smith' if i == 0 else f'Person {i}',
        'email': 'alice.smith@acme-corp.com' if i == 0 else
                 'bob.jones@acme-corp.com' if i == 1 else f'user{i}@acme-corp.com',
        'alternateEmails': ['carol.white@acme-corp.com'],
        'phone': '+1-555-010-9999',
        'address': 'Wonderland Street 42',
        'identity': {'ssn': '123-45-6789' if i == 0 else '987654321',
                     'passportNumber': 'P1234567X',
                     'email': 'alice.smith@acme-corp.com'},
        'financial': {'creditCard': '4111 1111 1111 1111' if i == 0 else '4111111111111111',
                      'iban': 'GB82WEST12345698765432'},
        'auth': {'apiKey': 'tok_live_9f8e7d6c5b4a',
                 'passwordHash': '$2b$12$canaryBcryptHashValue0123456789',
                 'bearerToken': JWT_CANARY,
                 'lastLoginIp': '203.0.113.77', 'macAddress': '00:1A:2B:3C:4D:5E'},
        'tenant': 'tenant-canary-acme-42',
        'tags': ['vip'],
        'notes': 'unlisted-free-text-canary',
        'profile': {'nickname': 'nickname-like-canary-zed',
                    'misc': {'x': 'another-unlisted-canary-77'}},
        'grId': 'grid-canary-xyz-001',
        'age': 20 + i,
        'cards': [{'kind': 'visa', 'number': '4111111111111111'}],
        'manager': {'email': 'manager.x@acme-corp.com'},
        'tenantRef': 'schema-canary-tenantref-77',
        'customer': {'vipCode': 'schema-canary-path-vip-1'},
        'loyalty': {'tier': 'schema-canary-nested-tier-9'},
        'vendor': {'vipCode': 'keep-canary-vendor-vip-5'},
        'secretBlob': Binary(BIN6_BYTES, 6),
        'sensitiveBlob': Binary(BIN8_BYTES, 8),
    }
    doc.update(over)
    return doc


def run_workload(cluster, log=print, redact_client_log_data=False):
    from pymongo import MongoClient, UpdateOne, DeleteOne, InsertOne, ReplaceOne
    from pymongo.errors import PyMongoError
    global Binary
    from bson.binary import Binary

    errors = []

    def step(name, fn):
        try:
            fn()
        except PyMongoError as e:
            errors.append((name, type(e).__name__, str(e)[:160]))
        except Exception as e:                       # pragma: no cover
            errors.append((name, type(e).__name__, str(e)[:160]))

    # --- slowms = 0 on every process so every operation is logged ---------
    root = MongoClient(cluster.uri(appName='AcmeBillingService'))
    root.admin.command('profile', 0, slowms=0)
    if redact_client_log_data:
        root.admin.command('setParameter', 1, redactClientLogData=True)
    hello = root.admin.command('hello')
    shard_ports = []
    for sh in root.admin.command('listShards')['shards']:
        host = sh['host'].split('/')[-1].split(',')[0]
        shard_ports.append(int(host.split(':')[1]))
    csrs = root.admin.command('getShardMap')['map']['config'].split('/')[-1]
    for port in shard_ports + [int(csrs.split(',')[0].split(':')[1])]:
        d = MongoClient(cluster.uri(directConnection='true').replace(
            str(cluster.port), str(port)), appName='AcmeShardDirect')
        d.admin.command('profile', 0, slowms=0)
        if redact_client_log_data:          # enterprise: security.redactClientLogData
            d.admin.command('setParameter', 1, redactClientLogData=True)
        d.close()

    db = root['acmeshopdb']
    cp = db['customer_profiles']
    docs = [customer(i) for i in range(12)]

    # --- schema, sharding, indexes ----------------------------------------
    step('enableSharding', lambda: root.admin.command('enableSharding', 'acmeshopdb'))
    step('create', lambda: db.create_collection(
        'customer_profiles',
        validator={'$jsonSchema': {'bsonType': 'object', 'properties': {
            'identity': {'bsonType': 'object', 'properties': {
                'ssn': {'bsonType': 'string', 'pattern': '^[0-9-]+$'}}}}}},
        validationAction='error'))
    step('idx_shardkey', lambda: cp.create_index([('customerId', 1)]))
    step('shardCollection', lambda: root.admin.command(
        'shardCollection', 'acmeshopdb.customer_profiles', key={'customerId': 1}))
    step('idx_unique', lambda: cp.create_index(
        [('customerId', 1), ('email', 1)], unique=True, name='email_unique_idx'))
    step('idx_partial', lambda: cp.create_index(
        [('identity.ssn', 1)], name='ssn_lookup_idx',
        partialFilterExpression={'tenant': 'tenant-canary-acme-42', 'age': {'$gt': 18}}))
    step('idx_text', lambda: cp.create_index([('name', 'text'), ('notes', 'text')],
                                             name='notes_secret_index'))
    step('split', lambda: root.admin.command(
        'split', 'acmeshopdb.customer_profiles',
        middle={'customerId': 'chunk-split-canary-5000'}))
    if cluster.shards >= 2:
        shard_names = [s['_id'] for s in root.admin.command('listShards')['shards']]
        step('moveChunk', lambda: root.admin.command(
            'moveChunk', 'acmeshopdb.customer_profiles',
            find={'customerId': 'chunk-split-canary-5000'}, to=shard_names[-1],
            _waitForDelete=True))

    # --- inserts and write errors -----------------------------------------
    step('insert_many', lambda: cp.insert_many(docs))
    step('insert_dup_id', lambda: cp.insert_one(customer(0, _id='C-dup-canary-0001',
                                                         email='dup-key-canary@acme-corp.com')))
    step('insert_dup_id2', lambda: cp.insert_one(customer(0, _id='C-dup-canary-0002',
                                                          email='dup-key-canary@acme-corp.com')))
    step('insert_invalid', lambda: cp.insert_one(customer(
        50, identity={'ssn': 'validation-canary-ssn-abc'})))

    # --- reads --------------------------------------------------------------
    def reads():
        list(cp.find({'email': 'alice.smith@acme-corp.com'}))
        list(cp.find({'identity.ssn': {'$in': ['123-45-6789', '987654321']}}))
        list(cp.find({'financial.creditCard': {'$eq': '4111 1111 1111 1111'}}))
        list(cp.find({'name': {'$regex': 'hello-regex-canary', '$options': 'i'}}))
        list(cp.find({'$or': [{'email': 'bob.jones@acme-corp.com'},
                               {'phone': '+1-555-010-9999'}]}))
        list(cp.find({'$expr': {'$eq': ['$identity.ssn', '555-44-3333']}}))
        list(cp.find({'unlistedField': 'filter-unlisted-canary-9'}))
        list(cp.find({'email': 'alice.smith@acme-corp.com'}, {'identity.ssn': 1})
             .sort('notes', 1).hint('ssn_lookup_idx').comment('comment-canary-tenant-42')
             .limit(5).skip(0).batch_size(1))
        list(cp.find({'$text': {'$search': 'text-search-canary'}}))
        list(cp.find({'secretBlob': Binary(BIN6_BYTES, 6), 'sensitiveBlob': Binary(BIN8_BYTES, 8)}))
    step('reads', reads)

    def schema_ops():
        cp.find_one({'tenantRef': 'schema-canary-tenantref-77', 'customer.vipCode': 'schema-canary-path-vip-1',
                     'loyalty.tier': 'schema-canary-nested-tier-9', 'vendor.vipCode': 'keep-canary-vendor-vip-5',
                     'grId': 'grid-canary-xyz-001'})
        list(cp.find({'customer': {'$elemMatch': {'vipCode': 'schema-canary-path-vip-1'}},
                      'vendor': {'$elemMatch': {'vipCode': 'keep-canary-vendor-vip-5'}}}))
        cp.update_many({'tenantRef': 'schema-canary-tenantref-77', 'customerId': 'C-99887766'},
                       {'$set': {'customer.vipCode': 'schema-canary-path-vip-1',
                                 'loyalty.tier': 'schema-canary-nested-tier-9',
                                 'vendor.vipCode': 'keep-canary-vendor-vip-5', 'grId': 'grid-canary-xyz-001'}})
        list(cp.aggregate([
            {'$match': {'$expr': {'$eq': ['$customer.vipCode', 'schema-canary-path-vip-1']}}},
            {'$match': {'$expr': {'$eq': ['$vendor.vipCode', 'keep-canary-vendor-vip-5']}}},
            {'$match': {'$expr': {'$eq': ['$grId', 'grid-canary-xyz-001']}}},
            {'$limit': 2}]))
    step('schema_ops', schema_ops)
    step('where', lambda: list(cp.find({'$where': "this.email == 'where-canary-bob'"})))
    step('distinct', lambda: cp.distinct('email', {'tenant': 'tenant-canary-acme-42'}))
    step('count', lambda: cp.count_documents({'identity.ssn': '123-45-6789'}))
    step('estimated', lambda: cp.estimated_document_count())

    # --- updates / deletes --------------------------------------------------
    step('update_one_upsert', lambda: cp.update_one(
        {'email': 'carol.white@acme-corp.com', 'customerId': 'C-99887744'},
        {'$set': {'phone': '555-010-9999', 'notes': 'unlisted-free-text-canary'},
         '$setOnInsert': {'identity.ssn': '555-44-3333'}}, upsert=True))
    step('update_many_arrayFilters', lambda: cp.update_many(
        {'tenant': 'tenant-canary-acme-42'},
        {'$set': {'cards.$[c].number': '4111111111111111'}},
        array_filters=[{'c.kind': 'visa'}]))
    step('update_bad_inc', lambda: cp.update_one(
        {'customerId': 'C-99887766'}, {'$inc': {'identity.ssn': 'inc-canary-value'}}))
    step('update_bad_push', lambda: cp.update_one(
        {'customerId': 'C-99887766'}, {'$push': {'name': 'push-canary-doc-id'}}))
    step('find_and_modify', lambda: cp.find_one_and_update(
        {'email': 'alice.smith@acme-corp.com'}, {'$set': {'phone': '+1-555-010-9999'}},
        projection={'identity.ssn': 1}, return_document=True))
    step('replace_one', lambda: cp.replace_one(
        {'customerId': 'C-99887755', 'email': 'bob.jones@acme-corp.com'},
        customer(1, grId='grid-canary-xyz-002')))
    step('bulk', lambda: cp.bulk_write([
        InsertOne(customer(60)), UpdateOne({'customerId': 'C-00000060', 'email': 'user60@acme-corp.com'},
                                           {'$set': {'name': 'Alice Smith'}}),
        DeleteOne({'customerId': 'C-00000060', 'email': 'user60@acme-corp.com'})]))
    step('delete_many', lambda: cp.delete_many(
        {'financial.creditCard': '4111111111111111', 'customerId': 'C-00000011'}))
    step('find_and_delete', lambda: cp.find_one_and_delete(
        {'customerId': 'C-00000010', 'email': 'user10@acme-corp.com'}))

    # --- aggregation ---------------------------------------------------------
    orders = db['acme_orders']
    step('orders_insert', lambda: orders.insert_many([
        {'custId': 'C-99887766', 'orderNo': 'txn-canary-order-7781',
         'email': 'alice.smith@acme-corp.com', 'total': 10},
        {'custId': 'C-99887755', 'orderNo': 'O-2', 'total': 20}]))
    step('aggregate', lambda: list(cp.aggregate([
        {'$match': {'email': 'alice.smith@acme-corp.com'}},
        {'$match': {'$expr': {'$eq': ['$identity.ssn', '123-45-6789']}}},
        {'$lookup': {'from': 'acme_orders', 'localField': 'customerId',
                     'foreignField': 'custId', 'as': 'orders'}},
        {'$group': {'_id': '$identity.email', 'n': {'$sum': 1}}},
        {'$addFields': {'tag': 'unlisted-free-text-canary'}}])))
    step('aggregate_out', lambda: list(cp.aggregate([
        {'$match': {'tenant': 'tenant-canary-acme-42'}},
        {'$project': {'email': 1, 'phone': 1}},
        {'$out': 'customer_profiles_archive'}])))
    step('aggregate_union', lambda: list(cp.aggregate([
        {'$unionWith': 'acme_orders'}, {'$limit': 3}])))
    step('rename', lambda: orders.rename('acme_orders_renamed'))
    step('other_db', lambda: MongoClient(cluster.uri(appName='AcmeReportsApp'))
         ['acme_archive_db']['customer_profiles'].insert_one(
             {'email': 'alice.smith@acme-corp.com', 'ssn': '123-45-6789'}))

    # --- transactions and change streams ------------------------------------
    def txn():
        with root.start_session() as s:
            def cb(s_):
                db['acme_orders_renamed'].insert_one(
                    {'custId': 'C-99887766', 'orderNo': 'txn-canary-order-7781',
                     'email': 'alice.smith@acme-corp.com'}, session=s_)
                db['acme_orders_renamed'].update_one(
                    {'orderNo': 'txn-canary-order-7781'},
                    {'$set': {'phone': '555-010-9999'}}, session=s_)
            s.with_transaction(cb)
    step('transaction', txn)

    def stream():
        coll = db['acme_orders_renamed']
        with coll.watch(full_document='updateLookup', max_await_time_ms=500) as st:
            coll.insert_one({'custId': 'resume-stream-canary',
                             'email': 'alice.smith@acme-corp.com'})
            for _ in range(4):
                st.try_next()
            tok = st.resume_token
        with coll.watch(resume_after=tok, max_await_time_ms=300) as st2:
            coll.insert_one({'custId': 'resume-stream-canary-2'})
            for _ in range(3):
                st2.try_next()
    step('changestream', stream)

    # --- users / auth / admin -----------------------------------------------
    step('createUser', lambda: root.admin.command(
        'createUser', 'jsmith_admin', pwd=ADMIN_PASS, roles=[{'role': 'readAnyDatabase', 'db': 'admin'}]))
    step('login_ok', lambda: MongoClient(cluster.uri(user='jsmith_admin', appName='AcmeReportsApp'))
         .admin.command('ping'))
    step('login_unknown', lambda: MongoClient(cluster.uri(user=UNKNOWN_USER, pw='bad-pass-123'),
                                              serverSelectionTimeoutMS=4000, appName='AcmeReportsApp')
         .admin.command('ping'))
    step('login_badpw', lambda: MongoClient(cluster.uri(user=ADMIN_USER, pw='wrong-pass-999'),
                                            serverSelectionTimeoutMS=4000)
         .admin.command('ping'))
    step('unauthorized', lambda: MongoClient(cluster.uri(user='jsmith_admin'))['acmeshopdb']
         ['customer_profiles'].insert_one({'email': 'alice.smith@acme-corp.com'}))
    step('usersInfo', lambda: root.admin.command('usersInfo', {'forAllDBs': True}))
    step('dropUser', lambda: root.admin.command('dropUser', 'jsmith_admin'))
    step('currentOp', lambda: root.admin.command('currentOp'))
    step('connPoolStats', lambda: root.admin.command('connPoolStats'))
    step('listCollections', lambda: list(db.list_collections()))
    step('listIndexes', lambda: list(cp.list_indexes()))
    step('dropIndex', lambda: cp.drop_index('ssn_lookup_idx'))
    step('collMod', lambda: db.command('collMod', 'customer_profiles', validationLevel='moderate'))
    step('flushRouter', lambda: root.admin.command('flushRouterConfig'))
    step('balancer', lambda: root.admin.command('balancerStatus'))
    step('dropColl', lambda: db.drop_collection('customer_profiles_archive'))
    step('dropDb', lambda: root.drop_database('acme_archive_db'))
    time.sleep(2.0)
    root.close()
    log('workload done; %d steps raised server errors (expected)' % len(errors))
    return errors


# ══════════════════════════════════════════════════════════════════════════════
# Test fixture (module level: ONE cluster for all tests)
# ══════════════════════════════════════════════════════════════════════════════

STATE = {}


def _ofuscate(logpath, *flags):
    key = (logpath, flags)
    cache = STATE.setdefault('runs', {})
    if key not in cache:
        p = run([sys.executable, SCRIPT, '--log_redact', logpath, *flags],
                timeout=1200)
        cache[key] = p
    return cache[key]


def _run_ground_truth_cluster(version, bin_dir, base):
    """Second, identical cluster whose SERVER redacts its own logs
    (enterprise security.redactClientLogData=true): the reference for --server_redaction."""
    if not version.endswith('-ent'):
        sys.stderr.write('[test] --ground-truth needs an enterprise build (e.g. 5.0.31-ent); '
                         'ground-truth tests will be skipped\n')
        return
    gt = Cluster(bin_dir, os.path.join(base, 'cluster_gt'), CONFIG['shards'])
    try:
        gt.start()
        run_workload(gt, log=lambda m: sys.stderr.write('[test][gt] ' + m + '\n'),
                     redact_client_log_data=True)
    finally:
        gt.stop()
    gdir = os.path.join(base, 'logs_gt')
    os.makedirs(gdir)
    STATE['gt_logs'] = {}
    for name, path in gt.logs().items():
        dst = os.path.join(gdir, name)
        shutil.copy(path, dst)
        STATE['gt_logs'][name] = dst


def _detect_json(logs):
    first = next(iter(logs.values()))
    return read_lines(first)[0].lstrip().startswith('{')


def setUpModule():
    if not CONFIG['version'] and not CONFIG['use_logs']:
        raise unittest.SkipTest('give a MongoDB version: '
                                'python3 test_integration_mongo.py 5.0')
    if CONFIG['use_logs']:
        d = CONFIG['use_logs']
        meta = json.load(open(os.path.join(d, 'meta.json')))
        STATE.update(meta, workdir=d)
        STATE['logs'] = {n: os.path.join(d, 'logs', n) for n in meta['sources']}
        STATE['derived'] = tempfile.mkdtemp(prefix='ofuscator_it_derived_')
        STATE['is_json'] = _detect_json(STATE['logs'])
        if meta.get('gt_sources'):
            STATE['gt_logs'] = {n: os.path.join(d, 'logs_gt', n) for n in meta['gt_sources']}
        return
    for tool in ('m', 'mlaunch', 'mloginfo'):
        if not shutil.which(tool):
            raise unittest.SkipTest(f'`{tool}` not found (pip install mtools; https://github.com/aheckmann/m)')
    version, bin_dir = resolve_and_install(CONFIG['version'])
    sys.stderr.write(f'[test] MongoDB {version} ({bin_dir})\n')
    base = tempfile.mkdtemp(prefix='ofuscator_it_')
    cdir = os.path.join(base, 'cluster')
    cluster = Cluster(bin_dir, cdir, CONFIG['shards'], CONFIG['port'])
    STATE.update(version=version, base=base, cluster=cluster)
    try:
        cluster.start()
        errors = run_workload(cluster, log=lambda s: sys.stderr.write('[test] ' + s + '\n'))
    finally:
        cluster.stop()
    logs_dir = os.path.join(base, 'logs')
    os.makedirs(logs_dir)
    STATE['logs'] = {}
    for name, path in cluster.logs().items():
        dst = os.path.join(logs_dir, name)
        shutil.copy(path, dst)
        STATE['logs'][name] = dst
    STATE['workload_errors'] = errors
    STATE['workdir'] = cdir
    STATE['derived'] = os.path.join(base, 'derived')      # generated files live here,
    os.makedirs(STATE['derived'])                         # never next to the sources
    STATE['is_json'] = _detect_json(STATE['logs'])
    if CONFIG['ground_truth']:
        _run_ground_truth_cluster(version, bin_dir, base)
    json.dump({'version': version, 'workload_errors': errors, 'workdir': cdir,
               'sources': sorted(STATE['logs']),
               'gt_sources': sorted(STATE.get('gt_logs') or [])},
              open(os.path.join(base, 'meta.json'), 'w'))
    sys.stderr.write(f'[test] logs: ' + ', '.join(
        f'{n}={sum(1 for _ in open(p))}' for n, p in STATE['logs'].items()) + '\n')


def tearDownModule():
    if CONFIG['use_logs'] and STATE.get('derived'):
        shutil.rmtree(STATE['derived'], ignore_errors=True)
    base = STATE.get('base')
    if base and not CONFIG['keep']:
        shutil.rmtree(base, ignore_errors=True)
    elif base:
        sys.stderr.write(f'[test] kept: {base}\n')


# ══════════════════════════════════════════════════════════════════════════════
# helpers
# ══════════════════════════════════════════════════════════════════════════════

def read_lines(path):
    with open(path, encoding='utf-8', errors='replace') as fh:
        return [ln for ln in fh.read().splitlines() if ln.strip()]


def flatten(node, acc):
    if isinstance(node, dict):
        for k, v in node.items():
            acc.append(('k', k))
            flatten(v, acc)
    elif isinstance(node, list):
        for v in node:
            flatten(v, acc)
    else:
        acc.append(('v', node))
    return acc


def all_strings(node, acc):
    if isinstance(node, dict):
        for k, v in node.items():
            acc.add(k)
            all_strings(v, acc)
    elif isinstance(node, list):
        for v in node:
            all_strings(v, acc)
    elif isinstance(node, str):
        acc.add(node)
    return acc


def logv2_problems(e):
    """Structural conformance to the logv2 schema (docs/logging.md)."""
    bad = []
    if not isinstance(e, dict):
        return ['not an object']
    t = e.get('t')
    if not (isinstance(t, dict) and isinstance(t.get('$date'), str)):
        bad.append('t')
    if e.get('s') not in ('D1', 'D2', 'D3', 'D4', 'D5', 'I', 'W', 'E', 'F'):
        bad.append('s')
    if not isinstance(e.get('c'), str):
        bad.append('c')
    if not isinstance(e.get('id'), int):
        bad.append('id')
    if not isinstance(e.get('ctx'), str):
        bad.append('ctx')
    if not isinstance(e.get('msg'), str):
        bad.append('msg')
    if 'attr' in e and not isinstance(e['attr'], dict):
        bad.append('attr')
    if 'tags' in e and not isinstance(e['tags'], list):
        bad.append('tags')
    return bad


def is_mask(s):
    """True for an x-pattern placeholder (only x and punctuation)."""
    return not re.search(r'[A-Za-wyzA-WYZ0-9]', s)


def mask_for(flags):
    """What '###' becomes: itself by default, CHAR*3 with --char_replacement [CHAR]."""
    if '--char_replacement' in flags:
        i = flags.index('--char_replacement')
        nxt = flags[i + 1] if i + 1 < len(flags) else ''
        return (nxt if len(nxt) == 1 and not nxt.startswith('-') else 'x') * 3
    return '###'


IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
EMAIL = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}')
SSN = re.compile(r'(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])')
JWT = re.compile(r'\beyJ[\w\-]{5,}\.[\w\-]{5,}\.[\w\-]*')
DIGITS = re.compile(r'(?<![\w.\-])\d(?:[ \-]?\d){12,18}(?![\w\-])')


def luhn(d):
    s = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        s += n
    return s % 10 == 0


# ══════════════════════════════════════════════════════════════════════════════
# Tests
# ══════════════════════════════════════════════════════════════════════════════

MATRIX = {          # the DEFAULT policy (deep PII + every literal + server-style) always applies
    'default':              [],
    'seed':                 ['--seed', 'it-seed'],
    'redactns':             ['--redactNamespaces'],
    'x':                    ['--char_replacement'],
    'everything':           ['--seed', 'it', '--char_replacement',
                             '--redactNamespaces', '--addFields', '$comment,_tid,grId'],
    'x_redactns_seed':      ['--char_replacement', '--redactNamespaces', '--seed', 'k'],
    'star':                 ['--char_replacement', '*'],
    'single_pass':          ['--single_pass'],
}

SCHEMA_CMD_KEYS = ('sort', 'hint', 'projection', 'fields', 'key')


def strip_schema(cmd):
    """sort / hint / projection keys are field & index NAMES: ofuscator obfuscates
    them in every mode (the server keeps them) - excluded from exact comparisons."""
    return {k: v for k, v in cmd.items() if k not in SCHEMA_CMD_KEYS}


def server_redact_all(v, mask='###'):
    """Reference model of BSONObj::redact(RedactLevel::all) (bsonobj.cpp): keys and
    structure kept, arrays walked, every scalar -> "###"; an extended-JSON wrapper is
    one BSON scalar."""
    ext = {'$oid', '$date', '$numberLong', '$numberInt', '$numberDouble', '$numberDecimal',
           '$timestamp', '$binary', '$uuid', '$regularExpression', '$minKey',
           '$maxKey', '$undefined', '$symbol', '$code', '$dbPointer'}
    if isinstance(v, dict):
        ks = set(v)
        if (len(ks) == 1 and next(iter(ks)) in ext) or ks in (
                {'$binary', '$type'}, {'$code', '$scope'}):
            return mask
        return {k: server_redact_all(x, mask) for k, x in v.items()}
    if isinstance(v, list):
        return [server_redact_all(x, mask) for x in v]
    return mask


STATUS_OUT_RE = re.compile(r'^(?:OK|###|[A-Za-z][A-Za-z0-9]*:? ###)$')
STATUS_KEYS = ('error', 'errMsg', 'errmsg', 'exception', 'what')


class CompactAsserts(unittest.TestCase):
    """Real logs are large: on failure show a short snippet, never the log."""

    def assertNotIn(self, member, container, msg=None):
        if isinstance(container, str) and isinstance(member, str) and member in container:
            i = container.find(member)
            snip = container[max(0, i - 160): i + len(member) + 160]
            self.fail(f'{msg or ""} {member!r} present: ...{snip}...')
        elif not isinstance(container, str):
            super().assertNotIn(member, container, msg)

    def assertIn(self, member, container, msg=None):
        if isinstance(container, str) and isinstance(member, str):
            if member not in container:
                self.fail(f'{msg or ""} {member!r} not found (output {len(container)} chars)')
        else:
            super().assertIn(member, container, msg)


class RealLogs(CompactAsserts):
    maxDiff = None

    # -- helpers -----------------------------------------------------------
    def canaries(self, *groups):
        out = []
        for g in groups:
            out += C[g]
        return out

    def env_canaries(self):
        return environment_canaries(STATE['workdir'])

    def source_text(self):
        if 'src_text' not in STATE:
            STATE['src_text'] = {n: open(p, encoding='utf-8', errors='replace').read()
                                 for n, p in STATE['logs'].items()}
        return STATE['src_text']

    def source_hosts_and_ips(self):
        """Every non-loopback IPv4 and every FQDN / host:port in the SOURCE."""
        ips, hosts = set(), set()
        for text in self.source_text().values():
            for m in IPV4.findall(text):
                parts = m.split('.')
                if all(int(x) <= 255 for x in parts) and not m.startswith(('127.', '0.')):
                    ips.add(m)
        for name in ('hostname',):
            hosts.add(socket.gethostname())
        return ips, hosts

    def assert_canaries_gone(self, out, canaries, label):
        leaked = [c for c in canaries
                  if c in out or json.dumps(c)[1:-1] in out]
        self.assertEqual(leaked, [], f'{label}: LEAKED {leaked}')

    # -- 0. the fixture itself must be meaningful ----------------------------
    def test_00_cluster_and_source_logs(self):
        self.assertTrue(STATE['logs'], 'no logs collected')
        names = ' '.join(STATE['logs'])
        self.assertIn('mongos', names)
        self.assertGreaterEqual(len(STATE['logs']), 3, names)
        for n, p in STATE['logs'].items():
            lines = read_lines(p)
            self.assertGreater(len(lines), 50, n)
            if STATE['is_json']:
                for ln in lines[:200]:
                    json.loads(ln)                   # 4.4+ logs are logv2 JSON
        sys.stderr.write('\n[test] version under test: %s\n' % STATE['version'])

    def test_01_canaries_actually_reach_the_logs(self):
        """Guards against a vacuous test: the fake PII must really be in the
        logs produced by this server version."""
        text = '\n'.join(self.source_text().values())
        missing = {}
        for group in ('listed', 'names', 'strict', 'addfields'):
            missing[group] = [c for c in C[group] if c not in text
                              and json.dumps(c)[1:-1] not in text]
        total = sum(len(v) for v in C.values())
        absent = sum(len(v) for v in missing.values())
        sys.stderr.write(f'[test] canaries present in source logs: {total - absent}/{total}\n')
        for g, v in missing.items():
            if v:
                sys.stderr.write(f'[test]   not logged by this server ({g}): {v}\n')
        # the essential ones must be there
        for must in ('alice.smith@acme-corp.com', '123-45-6789', 'acmeshopdb',
                     'customer_profiles', 'AcmeBillingService', ADMIN_USER,
                     'chunk-split-canary-5000', 'C-dup-canary-0001'):
            self.assertIn(must, text, f'{must!r} never reached the logs')
        self.assertGreater((total - absent) / total, 0.75)

    # -- 1. leak matrix ---------------------------------------------------------
    def _matrix_case(self, label):
        flags = MATRIX[label]
        single = '--single_pass' in flags      # names are order-dependent by design
        canaries = (self.canaries('listed') + self.canaries('bindata')
                    + ([] if single else self.canaries('names'))
                    + ([] if single else self.env_canaries())
                    + self.canaries('strict')          # unlisted fields: default policy removes them
                    + (self.canaries('addfields') if '--addFields' in flags else []))
        ips, _ = self.source_hosts_and_ips()
        problems = []
        for name, path in STATE['logs'].items():
            p = _ofuscate(path, *flags)
            if p.returncode != 0:
                problems.append(f'{name}: exit {p.returncode}: {p.stderr[-300:]}')
                continue
            for bad in ('WARNING', 'were not valid structured'):
                if bad in p.stderr:
                    problems.append(f'{name}: stderr contains {bad!r}')
            out = p.stdout
            src = read_lines(path)
            outl = [ln for ln in out.splitlines() if ln.strip()]
            if len(outl) != len(src):
                problems.append(f'{name}: line count {len(src)} -> {len(outl)}')
                continue
            for c in canaries:
                for text, where in ((out, 'stdout'), (p.stderr, 'stderr')):
                    if c in text or json.dumps(c)[1:-1] in text:
                        i = text.find(c)
                        problems.append(f'{name}/{where}: LEAK {c!r}  ...{text[max(0, i - 90):i + len(c) + 60]}...')
                        break
            for ip in ips:
                if ip in out:
                    problems.append(f'{name}: source IP {ip} survived')
            if STATE['is_json']:
                for s_ln, o_ln in zip(src, outl):
                    so, oo = json.loads(s_ln), json.loads(o_ln)
                    bad = logv2_problems(oo)
                    if bad:
                        problems.append(f'{name}: logv2 violation {bad}: {o_ln[:160]}')
                    if oo.get('msg') == 'Unparseable log line redacted':
                        problems.append(f'{name}: line fell back to text: {so.get("id")}')
                    for k in ('t', 's', 'c', 'id'):
                        if so.get(k) != oo.get(k):
                            problems.append(f'{name}: {k} changed on id={so.get("id")}')
                    if sorted(so.get('attr', {})) != sorted(oo.get('attr', {})):
                        problems.append(f'{name}: top-level attr keys changed on id={so.get("id")}')
        self.assertEqual(problems[:12], [], f'{label}: {len(problems)} problem(s)')

    def test_10_matrix_default(self):           self._matrix_case('default')
    def test_11_matrix_seed(self):              self._matrix_case('seed')
    def test_12_matrix_redactns(self):          self._matrix_case('redactns')
    def test_13_matrix_x(self):                 self._matrix_case('x')
    def test_14_matrix_everything(self):        self._matrix_case('everything')
    def test_15_matrix_x_redactns_seed(self):   self._matrix_case('x_redactns_seed')
    def test_16_matrix_single_pass(self):       self._matrix_case('single_pass')
    def test_17_matrix_custom_char(self):       self._matrix_case('star')

    def test_19_addfields_removes_custom_field(self):
        with_af = ''.join(_ofuscate(p, '--addFields', 'grId').stdout
                          for p in STATE['logs'].values())
        for c in C['addfields']:
            self.assertNotIn(c, with_af)

    def test_20_default_removes_values_of_unlisted_fields(self):
        """Used to need --strict: values of field names the tool has never heard of
        ('unlistedField', 'notes', 'nickname' ...) are removed by the DEFAULT policy."""
        out = ''.join(_ofuscate(p).stdout for p in STATE['logs'].values())
        for c in C['strict']:
            self.assertNotIn(c, out, f'default policy left {c}')

    def test_21_deprecated_flags_are_accepted_and_ignored(self):
        path = STATE['logs'][sorted(STATE['logs'])[0]]
        base = _ofuscate(path, '--seed', 'z')
        for flags in (['--pii'], ['--strict'], ['--server_redaction'], ['--redactClientLogData']):
            p = _ofuscate(path, *flags, '--seed', 'z')
            self.assertEqual(p.returncode, 0)
            self.assertEqual(p.stdout, base.stdout, flags)
            self.assertIn('ignored', p.stderr)

    # -- 2. independent shape scan (does not know our canaries) ------------
    def _string_leaves(self, text):
        acc = set()
        for ln in text.splitlines():
            if ln.strip():
                all_strings(json.loads(ln), acc)
        return acc

    def test_30_shape_scan_x_mode(self):
        """In x-pattern mode no PII *shape* may remain in any string."""
        for name, path in STATE['logs'].items():
            strings = self._string_leaves(_ofuscate(path, '--char_replacement').stdout)
            for s_ in strings:
                self.assertEqual([e for e in EMAIL.findall(s_) if not is_mask(e)], [], (name, s_[:80]))
                self.assertEqual(SSN.findall(s_), [], (name, s_[:80]))
                self.assertEqual(JWT.findall(s_), [], (name, s_[:80]))
                for m in DIGITS.findall(s_):
                    digits = re.sub(r'\D', '', m)
                    self.assertFalse(13 <= len(digits) <= 19 and luhn(digits), (name, s_[:80]))
                for ip in IPV4.findall(s_):
                    self.assertTrue(ip.startswith(('127.', '0.')) or set(ip) <= set('x.'),
                                    f'{name}: raw IP {ip} in {s_[:80]!r}')

    def test_31_shape_scan_default_mask(self):
        """Default policy: no replacement words exist, so no email / SSN / JWT shape and no
        fake host / IP can appear in any string."""
        for name, path in STATE['logs'].items():
            for s_ in self._string_leaves(_ofuscate(path).stdout):
                self.assertEqual(EMAIL.findall(s_), [], (name, s_[:80]))
                self.assertEqual(SSN.findall(s_), [], (name, s_[:80]))
                self.assertEqual(JWT.findall(s_), [], (name, s_[:80]))
                self.assertNotIn('.invalid', s_)
                for ip in IPV4.findall(s_):
                    self.assertTrue(ip.startswith(('127.', '0.')), f'{name}: IP {ip} in {s_[:80]!r}')

    def test_32_char_replacement_covers_everything_on_real_logs(self):
        """--char_replacement [CHAR]: not a single '###' is left; client data is CHAR*3 and
        names / hosts / users keep their shape with CHAR; valid logv2 JSON line by line."""
        for ch in (None, '*'):
            flags = ['--char_replacement'] + ([ch] if ch else [])
            m = (ch or 'x') * 3
            for name, path in STATE['logs'].items():
                p = _ofuscate(path, *flags)
                self.assertEqual(p.returncode, 0, p.stderr[-300:])
                self.assertNotIn('###', p.stdout, (name, flags))
                src = [json.loads(x) for x in read_lines(path)]
                out = [json.loads(x) for x in p.stdout.splitlines()]
                self.assertEqual(len(src), len(out))
                checked = 0
                for so, oo in zip(src, out):
                    self.assertEqual(logv2_problems(oo), [], (name, flags))
                    cmd = so.get('attr', {}).get('command')
                    if isinstance(cmd, dict):
                        self.assertEqual(strip_schema(oo['attr']['command']),
                                         server_redact_all(strip_schema(cmd), m), (name, flags, so['id']))
                        checked += 1
                    for key in ('ns', 'appName'):
                        v = so.get('attr', {}).get(key)
                        if isinstance(v, str) and v and not v.startswith(('config.', 'local.', 'admin.')):
                            w = oo['attr'][key]
                            self.assertEqual(len(w), len(v), (key, v, w))      # shape kept
                            c = ch or 'x'
                            if key == 'appName':      # the whole value keeps its shape
                                self.assertEqual(w, re.sub(r'[^\W_]', c, v), (key, v, w))
                            else:                     # namespace: the db part is replaced
                                first = v.split('.')[0]
                                self.assertNotIn(first, w)
                                self.assertTrue(w.startswith(re.sub(r'[^\W_]', c, first)), (key, v, w))
                self.assertGreater(checked, 5)

    # -- 3. the default '###' and the char pattern have identical coverage --------------------
    def _parity(self, *flags):
        for name, path in STATE['logs'].items():
            src = [json.loads(x) for x in read_lines(path)]
            word = _ofuscate(path, *flags).stdout.splitlines()
            xpat = _ofuscate(path, *flags, '--char_replacement').stdout.splitlines()
            self.assertEqual(len(word), len(xpat))
            bad = []
            for i, (so, w, x) in enumerate(zip(src, word, xpat)):
                fo, fw, fx = (flatten(so, []), flatten(json.loads(w), []),
                              flatten(json.loads(x), []))
                if len(fw) != len(fx):
                    bad.append((i, 'shape', len(fw), len(fx)))
                    continue
                if len(fo) != len(fw):
                    if [k for k, _ in fw] != [k for k, _ in fx]:
                        bad.append((i, 'kinds'))
                    continue
                for (_, o), (_, a), (_, b) in zip(fo, fw, fx):
                    if not isinstance(o, str) or not any(ch.isalnum() for ch in o) or is_mask(o):
                        continue
                    if (o != a) != (o != b):
                        bad.append((i, o[:50], str(a)[:50], str(b)[:50]))
            self.assertEqual(bad[:5], [], f'{name}: coverage differs between styles ({len(bad)})')

    def test_40_parity_default(self):       self._parity()
    def test_41_parity_redactns(self):      self._parity('--redactNamespaces')

    # -- 4. the redacted log is still a usable log ------------------------------
    def test_50_redacted_logs_remain_parseable(self):
        """JSON logs: every line validates against logv2 (checked in the matrix
        too).  Logs that mtools can parse (legacy text, <4.4): mloginfo must
        parse the redacted file and report the same number of lines."""
        from mtools.util.logevent import LogEvent
        for name, path in STATE['logs'].items():
            red = os.path.join(STATE['derived'], 'redacted_' + name)
            with open(red, 'w') as fh:
                fh.write(_ofuscate(path).stdout)
            first = read_lines(red)[0]
            if STATE['is_json']:
                self.assertEqual(logv2_problems(json.loads(first)), [])
            src_ok = LogEvent(read_lines(path)[0]).datetime is not None
            if not src_ok:
                sys.stderr.write(f'\n[test] mtools {self._mtools_version()} cannot parse '
                                 f'{"4.4+ JSON" if STATE["is_json"] else "this"} logs; '
                                 f'using the built-in logv2 validator for {name}\n')
                continue
            r = run(['mloginfo', red], timeout=300)
            self.assertEqual(r.returncode, 0, f'{name}: {r.stdout[-300:]} {r.stderr[-300:]}')
            m = re.search(r'length:\s*(\d+)', r.stdout)
            self.assertTrue(m, r.stdout[:400])
            self.assertEqual(int(m.group(1)), len(read_lines(path)), name)

    @staticmethod
    def _mtools_version():
        import mtools
        return getattr(mtools, '__version__', '?')

    def test_51_operational_metrics_preserved(self):
        safe = ('durationMillis', 'nreturned', 'keysExamined', 'docsExamined',
                'numYields', 'reslen', 'nMatched', 'nModified', 'ninserted',
                'ndeleted', 'cursorExhausted', 'connectionId', 'connectionCount',
                'ok', 'queryHash', 'planCacheKey')
        for name, path in STATE['logs'].items():
            src = [json.loads(x) for x in read_lines(path)]
            out = [json.loads(x) for x in _ofuscate(path).stdout.splitlines()]
            for so, oo in zip(src, out):
                for k in safe:
                    if k in so.get('attr', {}) and isinstance(so['attr'][k], (int, float)):
                        self.assertEqual(so['attr'][k], oo['attr'].get(k), f'{name}:{k}')
            # the operation mix is unchanged: same message + severity histogram
            self.assertEqual([(e['c'], e['id'], e['msg']) for e in src],
                             [(e['c'], e['id'], e['msg']) for e in out])

    def test_52_system_namespaces_and_loopback_kept(self):
        """Namespace ATTRIBUTES (ns / namespace) of system databases stay readable and
        loopback addresses stay; a user namespace embedded in an internal cache collection
        is redacted.  (Namespaces inside command bodies are client data: masked, like the
        server does.)"""
        system_prefixes = ('config.', 'local.', 'admin.$cmd', 'admin.system.')
        kept = 0
        loop = 0
        for name, path in STATE['logs'].items():
            src = [json.loads(x) for x in read_lines(path)]
            out = [json.loads(x) for x in _ofuscate(path, '--redactNamespaces').stdout.splitlines()]
            for so, oo in zip(src, out):
                for key in ('ns', 'namespace'):
                    v = so.get('attr', {}).get(key)
                    if isinstance(v, str) and v.startswith(system_prefixes) \
                            and not v.startswith('config.cache.chunks.'):
                        self.assertEqual(oo['attr'][key], v, (name, key, v))
                        kept += 1
                r = so.get('attr', {}).get('remote')
                if isinstance(r, str) and r.startswith('127.0.0.1:'):
                    self.assertEqual(oo['attr']['remote'], r)
                    loop += 1
        sys.stderr.write(f'\n[test] system namespace attrs kept: {kept}; loopback remotes kept: {loop}\n')
        self.assertGreater(kept, 20)
        self.assertGreater(loop, 5)
        out = ''.join(_ofuscate(p, '--redactNamespaces').stdout for p in STATE['logs'].values())
        self.assertNotRegex(out, r'config\.cache\.chunks\.acmeshopdb')

    # -- 4b. server-side redaction policy (redaction.cpp / log_util.cpp / bsonobj.cpp) --------
    def test_53_bindata_6_and_8_masked_by_default_in_every_mode(self):
        """S1: the server masks BinData Encrypt / Sensitive even with
        redactClientLogData off - but only on newer versions.  ofuscator does it
        for every source version."""
        src = '\n'.join(self.source_text().values())
        shown = {c: c in src for c in C['bindata']}
        sys.stderr.write(f'\n[test] BinData 6/8 base64 present in the SOURCE logs of this '
                         f'server version: {shown}  (False = the server already masked it)\n')
        for flags in ([], ['--char_replacement'], ['--char_replacement', '*']):
            out = ''.join(_ofuscate(p, *flags).stdout for p in STATE['logs'].values())
            for c in C['bindata']:
                self.assertNotIn(c, out, (flags, c))

    def test_54_default_equals_server_reference_model_on_real_logs(self):
        """The DEFAULT output of every real command == the model of BSONObj::redact(all)
        (what the server writes with redactClientLogData=true): all leaves '###',
        keys / structure identical."""
        checked = 0
        for name, path in STATE['logs'].items():
            src = [json.loads(x) for x in read_lines(path)]
            out = [json.loads(x) for x in _ofuscate(path).stdout.splitlines()]
            for so, oo in zip(src, out):
                for ck in ('command', 'originatingCommand'):
                    sc = so.get('attr', {}).get(ck)
                    if isinstance(sc, dict):
                        self.assertEqual(strip_schema(oo['attr'][ck]),
                                         server_redact_all(strip_schema(sc)),
                                         f'{name} id={so["id"]} {ck}')
                        checked += 1
        self.assertGreater(checked, 50)

    def test_55_default_status_forms_and_fixpoint(self):
        forms = collections.Counter()
        for name, path in STATE['logs'].items():
            first = _ofuscate(path).stdout
            again = os.path.join(STATE['derived'], 'sr_' + name)
            with open(again, 'w') as fh:
                fh.write(first)
            second = _ofuscate(again).stdout
            for a, b in zip(first.splitlines(), second.splitlines()):
                a, b = json.loads(a), json.loads(b)
                for ck in ('command', 'originatingCommand'):      # fixpoint on client data
                    if ck in a.get('attr', {}):
                        self.assertEqual(strip_schema(a['attr'][ck]), strip_schema(b['attr'][ck]),
                                         (name, ck))
                for k in STATUS_KEYS:
                    v = a.get('attr', {}).get(k)
                    if isinstance(v, str):
                        self.assertRegex(v, STATUS_OUT_RE, (name, k, v))
                        forms[v if v == '###' else v.split(':')[0] + ': ###'] += 1
                    elif isinstance(v, dict) and isinstance(v.get('errmsg'), str):
                        self.assertEqual(v['errmsg'], '###', (name, k))
                        forms['{code, codeName, errmsg:###}'] += 1
        sys.stderr.write(f'\n[test] server-redaction status forms seen in real logs: {dict(forms)}\n')
        self.assertGreater(sum(forms.values()), 3)

    # -- 4c. --loadSchemaFile x --addFields: default | +schema | +fields | +both ----------------
    def _derived_log_with_schema_fields(self):
        """A REAL mongos log plus one injected entry that carries the schema fields in a
        container that is not client data (client data is masked by the default policy
        whatever the options are, so only such containers can show the rule)."""
        src = STATE['logs'][sorted(STATE['logs'])[-2]]            # a real log
        lines = read_lines(src)
        probe = {"t": {"$date": "2026-10-07T12:00:00.000+00:00"}, "s": "I", "c": "COMMAND", "id": 99999,
                 "ctx": "conn1", "msg": "generic attrs", "attr": {
                     "grId": 'grid-canary-xyz-001', "tenantRef": 'schema-canary-tenantref-77',
                     "customer": {"vipCode": 'schema-canary-path-vip-1'},
                     "loyalty": {"tier": 'schema-canary-nested-tier-9'},
                     "vendor": {"vipCode": 'keep-canary-vendor-vip-5'}}}
        path = os.path.join(STATE['derived'], 'with_probe.log')
        with open(path, 'w') as fh:
            fh.write('\n'.join(lines + [json.dumps(probe)]) + '\n')
        return path

    def test_56_schema_file_and_add_fields_combinations(self):
        schema = os.path.join(STATE['derived'], 'schema.json')
        with open(schema, 'w') as fh:
            json.dump(SCHEMA_DOC, fh)
        src = '\n'.join(self.source_text().values())
        for c in C['schema'] + C['schema_keep'] + C['addfields'][:1]:
            self.assertIn(c, src, f'{c!r} never reached the logs')
        derived = self._derived_log_with_schema_fields()
        combos = {'none': ([], False), 'schema': (['--loadSchemaFile', schema], True),
                  'addFields': (['--addFields', 'grId'], False),
                  'schema+addFields': (['--loadSchemaFile', schema, '--addFields', 'grId'], True)}
        for label, (opts, use_schema) in combos.items():
            use_add = 'grId' in opts
            for style in ([], ['--char_replacement']):
                for extra in ([], ['--redactNamespaces', '--seed', 'k']):
                    tag = (label, style, extra)
                    # (a) the injected entry: default | +schema | +fields | +both
                    p = _ofuscate(derived, *opts, *extra, *style)
                    self.assertEqual(p.returncode, 0, p.stderr[-300:])
                    probe_out = p.stdout.splitlines()[-1]
                    for c in C['schema']:
                        (self.assertNotIn if use_schema else self.assertIn)(c, probe_out, tag + (c,))
                    for c in C['addfields'][:1]:
                        (self.assertNotIn if use_add else self.assertIn)(c, probe_out, tag + (c,))
                    self.assertIn('keep-canary-vendor-vip-5', probe_out, tag)   # no rule matches it
                    # (b) the real client data of all three logs: masked in EVERY combination
                    out = ''.join(_ofuscate(path, *opts, *extra, *style).stdout
                                  for path in STATE['logs'].values())
                    for c in C['schema'] + C['schema_keep'] + C['addfields'] + [
                            'alice.smith@acme-corp.com', '123-45-6789', '4111111111111111']:
                        self.assertNotIn(c, out, tag + (c,))

    def test_57_schema_file_with_addfields_is_additive_and_deterministic(self):
        schema = os.path.join(STATE['derived'], 'schema.json')
        with open(schema, 'w') as fh:
            json.dump(SCHEMA_DOC, fh)
        derived = self._derived_log_with_schema_fields()
        flags = ['--loadSchemaFile', schema, '--addFields', 'grId', '--seed', 'abc']
        a = _ofuscate(derived, *flags).stdout
        b = run([sys.executable, SCRIPT, '--log_redact', derived, *flags]).stdout
        self.assertEqual(a, b)                                           # same seed -> same output
        base = _ofuscate(derived, '--seed', 'abc').stdout.splitlines()
        added = a.splitlines()
        self.assertEqual(base[:-1], added[:-1])      # the real lines do not change at all
        self.assertNotEqual(base[-1], added[-1])     # only the injected entry gains redactions

    # -- 5. determinism, salting, robustness -----------------------------------
    def test_60_seed_determinism_and_salting(self):
        path = next(iter(STATE['logs'].values()))
        a = run([sys.executable, SCRIPT, '--log_redact', path, '--seed', 'abc']).stdout
        b = run([sys.executable, SCRIPT, '--log_redact', path, '--seed', 'abc']).stdout
        c = run([sys.executable, SCRIPT, '--log_redact', path, '--seed', 'abd']).stdout
        self.assertEqual(a, b)
        self.assertEqual(a, c, 'by default every redacted value is ###: the seed changes nothing')
        ns = lambda seed: run([sys.executable, SCRIPT, '--log_redact', path, '--redactNamespaces']
                              + (['--seed', seed] if seed else [])).stdout
        self.assertEqual(ns('abc'), ns('abc'))
        self.assertNotEqual(ns('abc'), ns('abd'), 'the seed keys the REDACTED_ tokens')
        self.assertNotEqual(ns(None), ns(None), 'unseeded tokens must use a random per-run key')

    def test_61_no_unsalted_md5_of_sensitive_values(self):
        import hashlib
        text = ''.join(_ofuscate(p).stdout + _ofuscate(p).stdout
                       for p in STATE['logs'].values())
        for v in C['listed'] + C['names']:
            md5 = hashlib.md5(v.encode()).hexdigest()
            self.assertNotIn(md5, text, v)
            self.assertNotIn(md5[:8], text, v)

    def test_62_idempotent_and_still_json_on_second_pass(self):
        path = next(p for n, p in STATE['logs'].items() if 'mongos' in n)
        first = os.path.join(STATE['derived'], 'pass1_' + os.path.basename(path))
        with open(first, 'w') as fh:
            fh.write(_ofuscate(path).stdout)
        again = run([sys.executable, SCRIPT, '--log_redact', first])
        self.assertEqual(again.returncode, 0, again.stderr[-500:])
        for ln in again.stdout.splitlines():
            json.loads(ln)

    def test_63_damaged_real_log_fails_closed_and_stays_json(self):
        path = next(p for n, p in STATE['logs'].items() if 'mongos' in n)
        lines = read_lines(path)
        damaged = os.path.join(STATE['derived'], 'damaged.log')
        with open(damaged, 'w') as fh:
            fh.write('\n')                                   # blank first line
            for i, ln in enumerate(lines[:300]):
                if i % 50 == 7:
                    fh.write(ln[: len(ln) // 2] + '\n')     # truncated JSON
                elif i % 50 == 9:
                    fh.write('Oct  7 host mongos[1]: ' + ln + '\n')   # syslog prefix
                else:
                    fh.write(ln + '\n')
        p = run([sys.executable, SCRIPT, '--log_redact', damaged])
        self.assertEqual(p.returncode, 0, p.stderr[-500:])
        out = [x for x in p.stdout.splitlines() if x.strip()]
        self.assertEqual(len(out), len(lines[:300]))
        for ln in out:
            self.assertIsInstance(json.loads(ln), dict)
        self.assert_canaries_gone(p.stdout + p.stderr,
                                  self.canaries('listed', 'names'), 'damaged')


class GroundTruth(CompactAsserts):
    """Compare --server_redaction with what an ENTERPRISE server writes itself when
    security.redactClientLogData=true, for the same workload on two clusters.
    Run with:  python3 test_integration_mongo.py 5.0.31-ent --ground-truth"""
    maxDiff = None

    def setUp(self):
        if not STATE.get('gt_logs'):
            self.skipTest('needs an enterprise version and --ground-truth (e.g. 5.0.31-ent)')

    APPS = ('AcmeBillingService', 'AcmeReportsApp')

    @staticmethod
    def _lines(path):
        return [json.loads(x) for x in read_lines(path)]

    def _commands(self, entries, selector=None):
        """Counter of command skeletons of the user ops. `selector[i]` gives the
        entry whose appName decides (ofuscator obfuscates appName in its output)."""
        c = collections.Counter()
        sel = selector or entries
        for e, s_ in zip(entries, sel):
            a = e.get('attr', {})
            cmd = a.get('command')
            if e.get('msg') == 'Slow query' and s_.get('attr', {}).get('appName') in self.APPS \
                    and isinstance(cmd, dict):
                first = next(iter(s_['attr']['command']), '')      # name in the SOURCE
                if first in ('profile', 'setParameter'):            # harness orchestration
                    continue
                pl = s_['attr']['command'].get('pipeline')          # server-generated, its stage
                if isinstance(pl, list) and any(                     # list varies with timing/plan
                        isinstance(st, dict) and any(str(k).startswith(('$_internal', '$changeStream'))
                                                     for k in st) for st in pl):
                    continue
                c[json.dumps(strip_schema(cmd), sort_keys=True)] += 1
        return c

    def test_g0_server_really_redacts_and_what_it_leaves_visible(self):
        text = '\n'.join(open(p, encoding='utf-8', errors='replace').read()
                         for p in STATE['gt_logs'].values())
        self.assertGreater(text.count('"###"'), 200, 'server did not redact')
        for c in ('alice.smith@acme-corp.com', '123-45-6789', '4111111111111111',
                  '+1-555-010-9999', 'GB82WEST12345698765432', 'tok_live_9f8e7d6c5b4a'):
            self.assertNotIn(c, text, c)                      # server policy works on values
        visible = [c for c in C['names'] if c in text]
        sys.stderr.write(f'\n[test][gt] names the SERVER leaves visible even with '
                         f'redactClientLogData=true: {visible}\n')
        self.assertIn('acmeshopdb', visible)                  # namespaces: not server-redacted
        self.assertIn('AcmeBillingService', visible)          # appName: not server-redacted

    def test_g1_our_command_masks_equal_the_servers_masks(self):
        plain = STATE['logs']
        for name, gpath in STATE['gt_logs'].items():
            ours = self._commands([json.loads(x) for x in
                                   _ofuscate(plain[name]).stdout.splitlines()],
                                  selector=self._lines(plain[name]))
            theirs = self._commands(self._lines(gpath))
            only_ours = set(ours) - set(theirs)
            only_theirs = set(theirs) - set(ours)
            self.assertGreater(sum(theirs.values()), 10, name)
            self.assertEqual(
                (sorted(only_ours)[:2], sorted(only_theirs)[:2]), ([], []),
                f'{name}: command masks differ between ofuscator and the server')
            drift = sum(abs(ours[k] - theirs[k]) for k in set(ours) | set(theirs))
            self.assertLessEqual(drift, max(3, int(0.05 * sum(theirs.values()))), name)
            sys.stderr.write(f'\n[test][gt] {name}: {len(theirs)} distinct server-redacted commands '
                             f'({sum(theirs.values())} lines) == ours\n')

    def test_g2_status_forms_match_where_the_server_masks_and_we_are_never_weaker(self):
        """The server redacts a Status only at call sites that wrap it in redact()
        (bgsync.cpp wraps some, not all), so other `error` attrs stay in clear even
        with redactClientLogData=true.  Contract: wherever the server masks, we
        produce the same form; everywhere else we mask too (stricter)."""
        def forms(entries):
            out = collections.defaultdict(set)
            for e in entries:
                a = e.get('attr', {})
                for k in STATUS_KEYS:
                    v = a.get(k)
                    if isinstance(v, str):
                        out[(e['msg'], k)].add(v)
                    elif isinstance(v, dict) and isinstance(v.get('errmsg'), str):
                        out[(e['msg'], k)].add('{errmsg:%s}' % v['errmsg'])
            return out

        def masked(f):
            return bool(STATUS_OUT_RE.match(f)) or f == '{errmsg:###}'

        def shape(f):       # the POLICY form; the code name itself depends on shutdown races
            return ('struct' if f == '{errmsg:###}' else 'bare' if f == '###'
                    else 'status' if ': ###' in f else 'other')
        compared = matched = server_clear = 0
        shown = []
        for name, gpath in STATE['gt_logs'].items():
            ours = forms([json.loads(x) for x in
                          _ofuscate(STATE['logs'][name]).stdout.splitlines()])
            theirs = forms(self._lines(gpath))
            for key in set(ours) & set(theirs):     # timing noise exists in only one cluster
                compared += 1
                self.assertTrue(all(masked(f) for f in ours[key]), (name, key, ours[key]))
                srv_masked = {f for f in theirs[key] if masked(f)}
                # same policy FORM wherever the server masks (code names of shutdown races differ)
                self.assertTrue({shape(f) for f in srv_masked} <= {shape(f) for f in ours[key]},
                                (name, key, srv_masked, ours[key]))
                matched += bool(srv_masked)
                clear = {f for f in theirs[key] if not masked(f)}
                if clear:
                    server_clear += 1
                    if len(shown) < 4:
                        shown.append((key[0][:48], sorted(clear)[0][:70]))
        sys.stderr.write(f'\n[test][gt] status attrs compared: {compared}; server masked (and we match): '
                         f'{matched}; server left the reason IN CLEAR (we mask): {server_clear}\n')
        for m_, t_ in shown:
            sys.stderr.write(f'[test][gt]    server kept visible: {m_!r} -> {t_!r}\n')
        self.assertGreater(compared, 5)
        self.assertGreaterEqual(matched, 1)

    def test_g3_idempotent_on_server_redacted_logs_and_stricter_elsewhere(self):
        visible = ['acmeshopdb', 'customer_profiles', 'AcmeBillingService', ADMIN_USER, UNKNOWN_USER]
        for name, gpath in STATE['gt_logs'].items():
            src_masks = open(gpath, encoding='utf-8', errors='replace').read().count('"###"')
            for flags in ([], ['--char_replacement'], ['--char_replacement', '*']):
                p = _ofuscate(gpath, *flags)
                self.assertEqual(p.returncode, 0, p.stderr[-300:])
                outl = [json.loads(x) for x in p.stdout.splitlines()]
                self.assertEqual(len(outl), len(read_lines(gpath)))
                # every server mask survives (as CHAR*3 with --char_replacement)
                self.assertGreaterEqual(p.stdout.count('"%s"' % mask_for(flags)), src_masks, (name, flags))
                for n in visible:               # what the server left visible is now gone
                    self.assertNotIn(n, p.stdout, (name, flags, n))
            fix = _ofuscate(gpath).stdout.splitlines()
            glines = self._lines(gpath)
            # the first commands (profile / setParameter) ran BEFORE redactClientLogData
            # was switched on: the server logged those in clear
            start = next(i for i, e in enumerate(glines)
                         if '"###"' in json.dumps(e.get('attr', {}).get('command', {})))
            for s_ln, o_ln in list(zip(glines, fix))[start:]:
                o = json.loads(o_ln)
                for ck in ('command', 'originatingCommand'):
                    if isinstance(s_ln.get('attr', {}).get(ck), dict):
                        # ours == reference model applied to the server's own line: identical
                        # where the server masked, and STRICTER where the server left it in
                        # clear (e.g. an internal createIndexes logged unredacted)
                        self.assertEqual(strip_schema(o['attr'][ck]),
                                         server_redact_all(strip_schema(s_ln['attr'][ck])),
                                         (name, s_ln['id']))


    def test_g4_char_replacement_on_the_servers_own_redacted_logs(self):
        """The real server writes '###'; --char_replacement [CHAR] turns exactly those masks
        into CHAR*3 (and nothing else of the client data survives)."""
        for ch in (None, '*'):
            flags = ['--char_replacement'] + ([ch] if ch else [])
            m = (ch or 'x') * 3
            for name, gpath in STATE['gt_logs'].items():
                p = _ofuscate(gpath, *flags)
                self.assertEqual(p.returncode, 0, p.stderr[-300:])
                self.assertNotIn('###', p.stdout, (name, flags))
                glines = self._lines(gpath)
                start = next(i for i, e in enumerate(glines)
                             if '"###"' in json.dumps(e.get('attr', {}).get('command', {})))
                out = [json.loads(x) for x in p.stdout.splitlines()]
                n = 0
                for g, o in list(zip(glines, out))[start:]:
                    cmd = g.get('attr', {}).get('command')
                    if isinstance(cmd, dict):
                        self.assertEqual(strip_schema(o['attr']['command']),
                                         server_redact_all(strip_schema(cmd), m), (name, flags, g['id']))
                        n += 1
                self.assertGreater(n, 10)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('version', nargs='?', default=CONFIG['version'],
                    help='MongoDB version: X.Y (newest installable patch) or X.Y.Z')
    ap.add_argument('--keep', action='store_true', help='keep cluster dir and logs')
    ap.add_argument('--shards', type=int, default=1, help='number of shards (default 1)')
    ap.add_argument('--port', type=int, default=None, help='mongos port (default: first free block)')
    ap.add_argument('--use-logs', metavar='DIR', help='reuse the dir printed by --keep (skips cluster)')
    ap.add_argument('--ground-truth', action='store_true',
                    help='also run a 2nd cluster whose ENTERPRISE server redacts its own logs '
                         '(redactClientLogData=true) and compare with --server_redaction '
                         '(version must be exact and -ent, e.g. 5.0.31-ent)')
    args, rest = ap.parse_known_args()
    CONFIG.update(version=args.version, keep=args.keep, shards=args.shards,
                  use_logs=args.use_logs, port=args.port, ground_truth=args.ground_truth)
    if not args.version and not args.use_logs:
        ap.error('a MongoDB version is required, e.g.  5.0  or  5.0.31')
    unittest.main(argv=[sys.argv[0]] + rest, verbosity=2)


if __name__ == '__main__':
    main()

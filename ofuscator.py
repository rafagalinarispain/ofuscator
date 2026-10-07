#!/usr/bin/env python3
"""
ofuscator.py - Enhanced MongoDB log and FTDC obfuscation tool.

Based on fruitsalad (https://github.com/rueckstiess/fruitsalad) by Thomas Rueckstiess.

Two main operating modes, selected by a required top-level flag:

  --log_redact <logfile>
        Obfuscate a MongoDB log file (JSON structured or legacy text format).
        All options below apply only to this mode.

        --seed S / -s S          Seed the random number generator with S.
        --pii                    Deep PII obfuscation (field-by-field walk).
        --strict                 Implies --pii; redact every literal in data subtrees.
        --single_pass            Skip the name-learning pre-pass (faster).
        --addFields FIELDS       Extra command-level fields to obfuscate.
        --redactNamespaces       Replace db/collection names with REDACTED_<hash>.
        --char_replacement       Use x-pattern instead of fruit/colour names.
        --char_fields FIELDS     Fields that get x-pattern in selective mode.

  --ftdc_redact
        Redact hostInfo from FTDC diagnostic.data metrics.* files.

        --input_dir DIR   (required) Directory containing metrics.* files.
        --output_dir DIR  (required) Directory to write redacted files into.

        For each metrics.* file found in --input_dir the tool will:
          1. Read the raw BSON documents.
          2. In every type-0 (metadata) chunk, redact hostInfo:
               - All scalar string/numeric/bool field values are replaced with "#".
               - hostInfo.system.hostname is replaced with
                 "redacted_hostname_redacted_port_number" always.
                 the hostname string (host:port) or from getCmdLineOpts.
               - datetime fields (start/end/currentTime) are preserved.
               - The "ok" field is preserved.
          3. Re-encode the documents back to BSON.
          4. Write the result to --output_dir/<same filename>.

        Requires: pymongo  (pip install pymongo)
"""

from enum import Enum
from random import seed as rseed, randrange, choice
from functools import reduce
import argparse
import re
import hashlib
import sys
import traceback
import json
import operator
import os
import struct
import hmac
import ipaddress
import glob as _glob

# ── Word lists from fruitsalad ────────────────────────────────────────────────
adjectives = [
    "acerbic", "acidic", "acrid", "aged", "ambrosial", "ample", "appealing",
    "appetizing", "aromatic", "astringent", "baked", "balsamic", "beautiful",
    "bite-size", "bitter", "bland", "blazed", "blended", "blunt", "boiled",
    "brackish", "briny", "brown", "browned", "burnt", "buttered", "caked",
    "candied", "caramelized", "caustic", "center-cut", "char-broiled", "cheesy",
    "chilled", "chocolate", "chunked", "cinnamon", "classic", "classy", "coated",
    "cold", "cool", "copious", "country", "crafted", "creamed", "creamy",
    "crisp", "crunchy", "cured", "dazzling", "deep-fried", "delicious",
    "delightful", "distinctive", "doughy", "dressed", "dripping", "drizzled",
    "dry", "edible", "elastic", "encrusted", "ethnic", "famous", "fantastic",
    "fiery", "fizzy", "flaky", "flat", "flavored", "flavorful", "fleshy",
    "fluffy", "fragile", "fresh", "fried", "frosty", "frozen", "fruity",
    "full", "garlicky", "generous", "gingery", "glazed", "golden", "gourmet",
    "greasy", "grilled", "gritty", "harsh", "heady", "heaping", "hearty",
    "homemade", "honeyed", "honey-glazed", "hot", "ice-cold", "icy",
    "indulgent", "infused", "intense", "juicy", "jumbo", "kosher", "large",
    "lavish", "layered", "lean", "light", "lip-smacking", "lively", "low",
    "luscious", "lush", "marinated", "mashed", "mellow", "mild", "minty",
    "mixed", "moist", "mouth-watering", "natural", "nectarous", "nutty",
    "oily", "organic", "peppery", "pickled", "piquant", "plain", "pleasant",
    "plump", "poached", "pounded", "pulpy", "pungent", "pureed", "rich",
    "ripe", "roasted", "robust", "rubbery", "saline", "salty", "sauteed",
    "savory", "scrumptious", "seared", "seasoned", "sharp", "silky",
    "simmered", "sizzling", "small", "smoked", "smoky", "smooth", "smothered",
    "soothing", "sour", "special", "spiced", "spicy", "spongy", "sprinkled",
    "stale", "steamed", "sticky", "strong", "stuffed", "succulent",
    "sugary", "superb", "sweet", "sweetened", "syrupy", "tangy", "tart",
    "tasty", "tender", "thick", "thin", "toasted", "toothsome", "topped",
    "tossed", "tough", "traditional", "velvety", "vinegary", "warm",
    "whipped", "whole", "wonderful", "yummy", "zesty", "zingy",
]
colors = [
    'aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige',
    'bisque', 'black', 'blanchedalmond', 'blue', 'blueviolet', 'brown',
    'burlywood', 'cadetblue', 'chartreuse', 'chocolate', 'coral',
    'cornflowerblue', 'cornsilk', 'crimson', 'cyan', 'darkblue', 'darkcyan',
    'darkgoldenrod', 'darkgray', 'darkgreen', 'darkkhaki', 'darkmagenta',
    'darkolivegreen', 'darkorange', 'darkorchid', 'darkred', 'darksalmon',
    'darkseagreen', 'darkslateblue', 'darkslategray', 'darkturquoise',
    'darkviolet', 'deeppink', 'deepskyblue', 'dimgray', 'dodgerblue',
    'firebrick', 'floralwhite', 'forestgreen', 'fuchsia', 'gainsboro',
    'ghostwhite', 'gold', 'goldenrod', 'gray', 'green', 'greenyellow',
    'honeydew', 'hotpink', 'indianred', 'indigo', 'ivory', 'khaki',
    'lavender', 'lavenderblush', 'lawngreen', 'lemonchiffon', 'lightblue',
    'lightcoral', 'lightcyan', 'lightgoldenrodyellow', 'lightgray',
    'lightgreen', 'lightpink', 'lightsalmon', 'lightseagreen', 'lightskyblue',
    'lightslategray', 'lightsteelblue', 'lightyellow', 'lime', 'limegreen',
    'linen', 'magenta', 'maroon', 'mediumaquamarine', 'mediumblue',
    'mediumorchid', 'mediumpurple', 'mediumseagreen', 'mediumslateblue',
    'mediumspringgreen', 'mediumturquoise', 'mediumvioletred', 'midnightblue',
    'mintcream', 'mistyrose', 'moccasin', 'navajowhite', 'navy', 'oldlace',
    'olive', 'olivedrab', 'orange', 'orangered', 'orchid', 'palegoldenrod',
    'palegreen', 'paleturquoise', 'palevioletred', 'papayawhip', 'peachpuff',
    'peru', 'pink', 'plum', 'powderblue', 'purple', 'red', 'rosybrown',
    'royalblue', 'saddlebrown', 'salmon', 'sandybrown', 'seagreen', 'seashell',
    'sienna', 'silver', 'skyblue', 'slateblue', 'slategray', 'snow',
    'springgreen', 'steelblue', 'tan', 'teal', 'thistle', 'tomato',
    'turquoise', 'violet', 'wheat', 'white', 'whitesmoke', 'yellow',
    'yellowgreen',
]
fruits = [
    'apple', 'apricot', 'avocado', 'banana', 'breadfruit', 'bilberry',
    'blackberry', 'blackcurrant', 'blueberry', 'boysenberry', 'cantaloupe',
    'currant', 'cherry', 'cherimoya', 'cloudberry', 'coconut', 'cranberry',
    'cucumber', 'damson', 'date', 'dragonfruit', 'durian', 'eggplant',
    'elderberry', 'feijoa', 'fig', 'goji.berry', 'gooseberry', 'grape',
    'raisin', 'grapefruit', 'guava', 'huckleberry', 'honeydew', 'jackfruit',
    'jambul', 'jujube', 'kiwi.fruit', 'kumquat', 'lemon', 'lime', 'loquat',
    'lychee', 'mango', 'marion.berry', 'melon', 'watermelon', 'rock.melon',
    'miracle.fruit', 'mulberry', 'nectarine', 'nut', 'olive', 'orange',
    'clementine', 'mandarine', 'blood.orange', 'tangerine', 'papaya',
    'passionfruit', 'peach', 'pepper', 'chili.pepper', 'bell.pepper', 'pear',
    'persimmon', 'physalis', 'pineapple', 'pomegranate', 'pomelo',
    'mangosteen', 'quince', 'raspberry', 'western.raspberry', 'rambutan',
    'redcurrant', 'salal.berry', 'salmon.berry', 'satsuma', 'star.fruit',
    'strawberry', 'tamarillo', 'tomato', 'ugli.fruit', 'watermelon',
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _char_replace(value):
    """Replace every alphanumeric character with 'x', keep separators."""
    return re.sub(r'[a-zA-Z0-9]', 'x', str(value))


def _char_replace_email(value):
    """Obfuscate email while keeping the structure visible: xxxxx@xxxxx.xxx"""
    if '@' in str(value):
        parts = str(value).split('@', 1)
        local = re.sub(r'[a-zA-Z0-9]', 'x', parts[0])
        domain_parts = parts[1].split('.')
        domain = '.'.join(re.sub(r'[a-zA-Z0-9]', 'x', p) for p in domain_parts)
        return local + '@' + domain
    return _char_replace(value)


def _char_replace_url(value):
    """Obfuscate URL: keep scheme and structural chars, replace the rest."""
    s = str(value)
    # keep scheme (http://, https://) intact for readability
    m = re.match(r'^(https?://)(.+)$', s)
    if m:
        scheme = m.group(1)
        rest = re.sub(r'[a-zA-Z0-9]', 'x', m.group(2))
        return scheme + rest
    return _char_replace(s)


# ── Main class ────────────────────────────────────────────────────────────────

class LogType(Enum):
    TEXT = 0
    JSON = 1


# Fields inside attr.command (and nested structures) that are considered PII
# when --pii is active.  These are matched against both exact keys and the
# last segment of dotted-path keys (e.g. "identity.ssn" → "ssn").
_PII_VALUE_KEYS = {
    # Identity
    'email', 'emails', 'alternateEmails',
    'user', 'users', 'username', 'userId',
    'name', 'names', 'firstName', 'lastName', 'fullName',
    'phone', 'phoneNumber', 'mobile', 'telephone',
    'dateOfBirth', 'dob', 'birthDate',
    'ssn', 'socialSecurityNumber',
    'passportNumber', 'passport',
    'driverLicence', 'driverLicense', 'driversLicense',
    'nationalId', 'taxId',
    # Contact
    'address', 'street', 'city', 'state', 'zip', 'zipCode', 'postalCode', 'country',
    'gps', 'lat', 'lng', 'latitude', 'longitude', 'geohash',
    # Financial
    'creditCard', 'cardNumber', 'cvv', 'cardExpiry',
    'bankAccount', 'accountNumber', 'routingNumber', 'iban', 'swift',
    'salary', 'wage', 'income',
    'cryptoWallet', 'walletAddress',
    # Auth / credentials
    'passwordHash', 'password', 'secret', 'apiKey', 'bearerToken', 'token',
    'sessionId', 'sessionToken', 'refreshToken', 'accessToken',
    'macAddress', 'deviceFingerprint', 'userAgent',
    'lastLoginIp', 'loginIp',
    # Health (HIPAA)
    'hivStatus', 'diagnosisCodes', 'diagnosis', 'prescriptions',
    'insuranceId', 'bloodType', 'medicalRecord',
    # HR
    'employeeId', 'hireDate', 'performanceRating',
    # Auth / access
    'collaborators', 'externalShares', 'owner', 'owners', 'author', 'authors',
    # Generic PII patterns
    'alternateLink', 'url', 'uri', 'link', 'href',
    'id', 'appId', 'fileId', 'objectId',
    '_tid', 'tid', 'recordId', 'tenant',
    'domains', 'domain',
    'groupIds', 'groups',
    # Timestamps that could identify individuals
    'lastNrtTimestamp', 'lastNrtSwTimestamp', 'prvNrtTimestamp',
    'dbInsertTime', 'modifiedDate',
    'fileSize', 'mimeType',
}

# Structural/operator keys to skip (MongoDB operators, BSON extended JSON)
_SKIP_KEYS = {
    '$set', '$unset', '$setOnInsert', '$currentDate', '$inc', '$push',
    '$pull', '$addToSet', '$each', '$slice', '$sort', '$position',
    '$and', '$or', '$nor', '$not', '$exists', '$type', '$mod', '$regex',
    '$text', '$where', '$elemMatch', '$all', '$in', '$nin', '$size',
    '$gt', '$gte', '$lt', '$lte', '$ne', '$eq',
    '$date', '$oid', '$timestamp', '$binary', '$numberLong', '$numberDecimal',
    '$minKey', '$maxKey', '$undefined', '$dbPointer', '$code', '$ref', '$id',
    'ordered', 'upsert', 'multi', 'writeConcern', 'bypassDocumentValidation',
    'q', 'u', 'updates', 'runtimeConstants', 'shardVersion', 'writeConcern',
}


# ══════════════════════════════════════════════════════════════════════════════
# Context tables for the universal sweep
#
# Log entries follow the mongod/mongos structured schema
#   {t, s, c, ctx, id, msg, attr, tags, truncated, size}
# (https://github.com/mongodb/mongo/blob/master/docs/logging.md).
# `attr` is free-form, so the sweep classifies every key it meets, at any
# depth, instead of relying on a fixed list of paths.  Keys are compared in a
# normalised form (lower-case, alphanumerics only): "_id"/"$id" -> "id",
# "firstName"/"FIRSTNAME"/"first_name" -> "firstname".
#
# NOTE: these tables only decide WHAT is redacted.  HOW it is replaced
# (fruit/colour words or x-pattern) is decided in one place
# (Obfuscator._replacement), so both styles have identical coverage.
# ══════════════════════════════════════════════════════════════════════════════

def _nk(key):
    return re.sub(r'[^a-z0-9]', '', str(key).lower())


def _nset(*names):
    return frozenset(_nk(n) for n in names)


# ══════════════════════════════════════════════════════════════════════════════
# Server-side redaction policy, mirrored from the MongoDB server
#   src/mongo/logv2/redaction.cpp      kRedactionDefaultMask = "###"
#   src/mongo/logv2/log_util.cpp       redactionEnabled=false, redactBinDataEncrypt=TRUE
#   src/mongo/bson/bsonobj.cpp         BSONObj::redact(all | encryptedAndSensitive | sensitiveOnly)
#   enterprise .../log_redact_options  security.redactClientLogData
#   src/mongo/db/repl/bgsync.cpp       redact(Status) / redact(DBException) / redact(what()) / redact(oplogEntry)
#
#  S1  BinData subtype 6 (Encrypt) and 8 (Sensitive) -> "###" at any depth, EVEN
#      when redactClientLogData is off (redactEncryptedFields defaults to true;
#      subtype 8 is masked unconditionally).                       [always on here]
#  S2  redactClientLogData=true: every scalar of ANY type (string, number, bool,
#      null, date, oid, bindata ...) -> the string "###"; keys / structure kept,
#      arrays walked.                                   [--server_redaction here;
#      payload documents get the same type-erasure in --pii]
#  S3  redact(Status) -> "CodeName: ###" (OK stays OK), redact(DBException) ->
#      "CodeName ###", redact(e.what()) -> "###".       [--server_redaction here]
# ══════════════════════════════════════════════════════════════════════════════

_MASK = '###'
_BINDATA_MASKED_SUBTYPES = frozenset({6, 8})
_EXT_SCALAR_KEYS = frozenset({
    '$oid', '$date', '$numberLong', '$numberInt', '$numberDouble',
    '$numberDecimal', '$timestamp', '$binary', '$uuid', '$regularExpression',
    '$minKey', '$maxKey', '$undefined', '$symbol', '$code', '$dbPointer'})
# NOTE: {"$regex": .., "$options": ..} is deliberately NOT here.  logv2 writes a BSON
# regex scalar as $regularExpression; {$regex, $options} is a query-operator document
# whose fields the server masks one by one (verified against a real enterprise server).
# "###", "Code: ###" (Status), "Code ###" (DBException), "OK"
_MASKED_RE = re.compile(r'^(?:OK|[A-Za-z][A-Za-z0-9]*:? ###)$')
# Status::toString(): "CodeName: reason" or, with extra info, "CodeName{ k: v }: reason"
_STATUS_LEAD_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9]*)(?:\{[^{}]*\})?:\s')


class SchemaFileError(ValueError):
    """Raised for an unusable --loadSchemaFile (reported without a traceback)."""


def load_schema_file(path):
    """Parse a --loadSchemaFile JSON file.

    Accepted shapes (any mix, all optional):
        ["grId", "$comment"]                       top-level array  = "fields"
        {"fields": ["grId", "tenantRef"],          bare names, any depth, same semantics
                                                   as --addFields (case-insensitive, '$'
                                                   optional, dotted / positional keys)
         "paths":  ["customer.vipCode"],           dotted paths: the key must end with these
                                                   segments ('$operators', array indexes and
                                                   positional '$[x]' are transparent)
         "schema": {"customer": {"vipCode": true,  nested object: every leaf whose value is
                                 "address": {"zip": true}}}}   true (or {} / null) is a path
    Returns (names, paths) where paths is a list of lists of segments.
    """
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        raise SchemaFileError(f'schema file not found: {path}')
    except (OSError, UnicodeDecodeError) as exc:
        raise SchemaFileError(f'cannot read schema file {path}: {exc.__class__.__name__}')
    except ValueError as exc:
        raise SchemaFileError(f'schema file {path} is not valid JSON: {exc}')

    names, paths = [], []

    def _names(seq, where):
        if not isinstance(seq, list) or not all(isinstance(x, str) and x.strip() for x in seq):
            raise SchemaFileError(f'{where} must be a list of non-empty strings')
        names.extend(x.strip() for x in seq)

    def _path(text):
        segs = [x for x in (t.strip() for t in text.split('.')) if x]
        if not segs:
            raise SchemaFileError('empty path in "paths"')
        paths.append(segs)

    def _nested(node, prefix, where):
        if not isinstance(node, dict):
            raise SchemaFileError(f'{where} must be an object')
        for key, val in node.items():
            if not isinstance(key, str) or not key.strip():
                raise SchemaFileError(f'{where} has an empty field name')
            here = prefix + [key.strip()]
            if isinstance(val, dict) and val:
                _nested(val, here, where)
            elif val is True or val is None or val == {} or val == 'redact':
                paths.append(here)
            elif val is False:
                continue                         # explicit "do not add"
            else:
                raise SchemaFileError(
                    f'{where}: value of "{".".join(here)}" must be true, an object, or null')

    if isinstance(doc, list):
        _names(doc, 'the top-level array')
    elif isinstance(doc, dict):
        known = {'fields', 'paths', 'schema', 'version', 'description', 'comment'}
        if 'fields' in doc:
            _names(doc['fields'], '"fields"')
        if 'paths' in doc:
            if not isinstance(doc['paths'], list) or not all(isinstance(x, str) for x in doc['paths']):
                raise SchemaFileError('"paths" must be a list of dotted-path strings')
            for text in doc['paths']:
                _path(text)
        if 'schema' in doc:
            _nested(doc['schema'], [], '"schema"')
        if not (known & set(doc)):                 # bare nested form: {"customer": {"vipCode": true}}
            _nested(doc, [], 'the schema file')
    else:
        raise SchemaFileError('the schema file must be a JSON object or array')

    # a one-segment path is just a field name
    flat = [p[0] for p in paths if len(p) == 1]
    deep = [p for p in paths if len(p) > 1]
    return names + flat, deep


def _is_masked(value):
    return isinstance(value, str) and (value == _MASK or _MASKED_RE.match(value) is not None)


def _all_masked(obj):
    """True when every leaf is already a server mask (so hashing it again would
    make the output of a server-redacted log non-idempotent)."""
    if isinstance(obj, dict):
        return all(_all_masked(v) for v in obj.values())
    if isinstance(obj, list):
        return all(_all_masked(v) for v in obj)
    return _is_masked(obj)


def _bin_subtype(d):
    """Subtype (int) of an extended-JSON BinData dict, else None."""
    if not isinstance(d, dict) or '$binary' not in d:
        return None
    inner = d['$binary']
    raw = None
    if isinstance(inner, dict) and set(inner) <= {'base64', 'subType'}:
        raw = inner.get('subType')                       # relaxed / canonical v2
    elif isinstance(inner, str) and set(d) <= {'$binary', '$type'}:
        raw = d.get('$type')                             # legacy v1
    if raw is None:
        return None
    try:
        return int(str(raw), 16)
    except ValueError:
        return None


def _mask_bindata(obj):
    """S1: BinData Encrypt(6) / Sensitive(8) -> "###" at any depth."""
    if isinstance(obj, dict):
        if _bin_subtype(obj) in _BINDATA_MASKED_SUBTYPES:
            return _MASK
        return {k: _mask_bindata(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_bindata(v) for v in obj]
    return obj


def _is_ext_scalar(d):
    """{"$oid": ..}, {"$date": ..}, {"$binary": ..} ... = ONE BSON scalar."""
    ks = set(d)
    if len(ks) == 1 and next(iter(ks)) in _EXT_SCALAR_KEYS:
        return True
    return ks in ({'$binary', '$type'}, {'$code', '$scope'})


_PII_EXTRA_KEYS = {
    'givenName', 'familyName', 'surname', 'middleName', 'nickname',
    'displayName', 'ipAddress', 'ip', 'ipv4', 'ipv6', 'hostname', 'gender',
    'ethnicity', 'religion', 'nationality', 'birthday', 'location',
    'coordinates', 'loc', 'patientId', 'mrn', 'npi', 'licensePlate', 'vin',
    'pin', 'otp', 'privateKey', 'clientSecret', 'credentials',
    'authorization', 'cookie', 'jwt', 'sessionKey', 'customerId', 'clientId',
    'accountId', 'memberId', 'subscriberId', 'policyNumber', 'notes', 'note',
    'comment', 'comments', 'description', 'message', 'bio', 'nin', 'tin',
    'mail', 'cell', 'fax', 'msisdn', 'imei', 'imsi', 'uuid', 'pwd', 'passwd',
    'pass', 'roles_', '$search', '$regex', '$where', '$function',
    '$accumulator', 'creditCardNumber', 'ccNumber', 'cc', 'pan', 'expiry',
    'expiration', 'dateOfDeath', 'maidenName', 'employer', 'company',
    'remoteIp', 'clientIp', 'sourceIp', 'ssid', 'bssid',
}
_PII_EXTRA_KEYS.discard('roles_')
_PII_NORM = frozenset(_nk(k) for k in (_PII_VALUE_KEYS | _PII_EXTRA_KEYS))

# Operator keys whose scalar operand is structure, not data.
_KEEP_SCALAR_OPS = _nset('$exists', '$type', '$size', '$options', '$mod',
                         '$meta', '$natural', '$limit', '$skip', '$sample',
                         '$maxDistance', '$minDistance', '$v')

# Key holds a command-like document.
_COMMAND_KEYS = _nset('command', 'commandSpec', 'cmd', 'originatingCommand',
                      'getMoreCommand', 'request', 'cmdObj')
# Inside a command: keys that carry no user data and are kept.
_CMD_SAFE_KEYS = _nset(
    'limit', 'skip', 'batchSize', 'maxTimeMS', 'maxAwaitTimeMS', 'singleBatch',
    'tailable', 'awaitData', 'allowDiskUse', 'ordered',
    'bypassDocumentValidation', 'writeConcern', 'readConcern', 'txnNumber',
    'startTransaction', 'autocommit', 'apiVersion', 'apiStrict',
    'apiDeprecationErrors', 'shardVersion', 'databaseVersion',
    '$readPreference', 'runtimeConstants', 'allowPartialResults',
    'noCursorTimeout', 'returnKey', 'showRecordId', 'readOnce', 'new',
    'upsert', 'multi', 'cursor', '$clusterTime', '$configTime',
    '$topologyTime', 'oplogReplay', 'needsMerge', 'fromMongos', 'explain',
    'remove', 'maxTimeMSOpOnly', 'allowSpeculativeMajorityRead')
# Inside a command: value is a collection name / full namespace.
_CMD_COLL_KEYS = _nset(
    'find', 'aggregate', 'update', 'insert', 'delete', 'findAndModify',
    'distinct', 'count', 'create', 'createIndexes', 'drop', 'dropIndexes',
    'listIndexes', 'collMod', 'validate', 'compact', 'killCursors',
    'mapReduce', 'reIndex', 'collection', 'coll', 'collName',
    'collectionName', 'collStats', 'convertToCapped', 'planCacheClear')
_CMD_FULLNS_KEYS = _nset(
    'renameCollection', 'to', 'shardCollection', 'ns', 'fromNs', 'toNs',
    'moveChunk', 'refineCollectionShardKey', 'reshardCollection')
# Field / index names in commands: keys and string values are obfuscated.
_CMD_SCHEMA_KEYS = _nset('projection', 'hint', 'fields', 'key', 'sort')

# Keys whose value is user data (filters, updates, documents, bounds ...).
_DATA_KEYS = _nset(
    'filter', 'query', 'q', 'u', 'updates', 'deletes', 'documents', 'doc',
    'o', 'o2', 'crud', 'oplogEntry', 'pipeline', 'let', 'comment',
    'firstBatch', 'nextBatch', 'errInfo', 'document', 'record', 'keyValue',
    'values', 'replacement', 'newDoc', 'oldDoc', 'preImage', 'postImage',
    'fullDocument', 'fullDocumentBeforeChange', 'min', 'max', 'splitKeys',
    'splitPoints', 'bounds', 'boundaries', 'startKey', 'endKey',
    'lowerBound', 'upperBound', 'shardKeyValue', 'resumeToken', 'resumeAfter',
    'startAfter', 'arrayFilters', 'expr', 'indexBounds', 'failingDocumentId',
    'docKey', 'documentKey', 'update', 'sortKey', 'partialFilterExpression',
    'wildcardProjection', 'queryShape', 'representativeQuery', 'batch',
    'variables', 'constants', 'data', 'body', 'payload', 'input', 'output',
    'args', 'arguments', 'params', 'parameters', 'extra', 'extraInfo',
    'splitPoint', 'coordinatorDoc', 'event', 'response')
# Payload documents: in --pii mode EVERY leaf is redacted (no field-name
# heuristics), since there is nothing structural worth preserving.
_DATA_FORCE_KEYS = _nset(
    'documents', 'document', 'doc', 'o', 'o2', 'crud', 'oplogEntry',
    'firstBatch', 'nextBatch', 'errInfo', 'keyValue', 'values', 'replacement',
    'newDoc', 'oldDoc', 'preImage', 'postImage', 'fullDocument',
    'fullDocumentBeforeChange', 'min', 'max', 'splitKeys', 'splitPoints',
    'bounds', 'boundaries', 'startKey', 'endKey', 'lowerBound', 'upperBound',
    'shardKeyValue', 'resumeToken', 'resumeAfter', 'startAfter',
    'failingDocumentId', 'docKey', 'documentKey', 'sortKey', 'record',
    'batch', 'variables', 'constants', 'data', 'body', 'payload', 'input',
    'output', 'extra', 'extraInfo', 'splitPoint')
# Strings under these keys are only scrubbed, not treated as data.
_DATA_STR_SCRUB_ONLY = _nset('update')

_NS_DOTTED_KEYS = _nset(
    'ns', 'namespace', 'nss', 'fromNs', 'toNs', 'sourceNamespace',
    'targetNamespace', 'nsName', 'fullns', 'fromName', 'toName', 'srcNs',
    'dstNs', 'targetNs', 'sourceNs', 'namespaceString', 'oldNamespace',
    'newNamespace', 'originalNamespace', 'lockName')
_NS_SINGLE_KEYS = _nset(
    'collection', 'coll', 'collName', 'collectionName', '$db', 'db', 'dbName',
    'database', 'authenticationDatabase', 'authDb', 'authSource', 'sourceDb',
    'targetDb', 'fromDb', 'toDb', 'primaryDb', 'dbs', 'databases',
    'collections')
# Identity-bearing keys (user / principal / application / replica-set names).
_IDENT_KEYS = _nset(
    'user', 'users', 'userName', 'principalName', 'principal', 'authUser',
    'authenticatedUsers', 'authenticatedUser', 'requestedUser', 'currentUser',
    'appName', 'application', 'applicationName', 'issuer', 'subject',
    'peerSubject', 'peerSubjectName', 'commonName', 'cn', 'email', 'emails',
    'mail', 'phone', 'firstName', 'lastName', 'fullName', 'realm',
    'replicaSet', 'replSet', 'setName', 'replicaSetName', 'clusterName',
    'shardName', 'shardId', 'shard', 'fromShard', 'toShard',
    'recipientShard', 'donorShard', 'primaryShard', 'owner', 'tenant',
    'tenantId', 'organization', 'dn', 'bindDn', 'queryUser',
    'kerberosPrincipal', 'sessionId', 'owningShard', 'processId')
_HOST_KEYS = _nset(
    'host', 'hosts', 'hostname', 'hostAndPort', 'hostPort', 'remote',
    'remoteAddr', 'remoteAddress', 'remoteHost', 'client', 'clientAddr',
    'clientAddress', 'peer', 'peerAddress', 'syncSource', 'syncSourceHost',
    'primary', 'me', 'targetHost', 'sourceHost', 'connString',
    'connectionString', 'uri', 'url', 'seedList', 'seeds', 'server',
    'servers', 'serverAddress', 'configServer', 'configServers', 'bindIp',
    'address', 'addr', 'endpoint', 'node', 'nodes', 'ipAddress', 'ip',
    'local', 'localAddress', 'proxyAddress', 'donor', 'recipient',
    'donorConnectionString', 'recipientConnectionString', 'listenAddr',
    'clientAddr',
    'votedFor', 'newPrimary', 'oldPrimary', 'leader')
# Host keys where ANY bare token is a host (no need for a dot / port).
_HOST_STRICT_KEYS = _nset(
    'server', 'servers', 'host', 'hosts', 'hostname', 'hostAndPort', 'hostPort', 'syncSource',
    'syncSourceHost', 'me', 'connString', 'connectionString', 'uri', 'url',
    'seedList', 'seeds', 'configServer', 'configServers', 'primary',
    'newPrimary', 'oldPrimary', 'votedFor', 'leader', 'donor', 'recipient')
# Subtrees holding configuration / credentials: every string leaf redacted.
_SENSITIVE_TREE_KEYS = _nset(
    'options', 'parsed', 'cmdLine', 'argv', 'env', 'environment',
    'setParameter', 'security', 'ldap', 'kmip', 'tls', 'ssl', 'net',
    'processManagement', 'systemLog', 'auditLog', 'config', 'startupOptions',
    'originalArgv', 'parsedOptions')
_SECRET_HINT_RE = re.compile(
    r'(password|passwd|pwd|passphrase|secret|token|apikey|accesskey|'
    r'privatekey|credential|authorization|cookie|bearer|salt|certificatekey|'
    r'pemkey|keyfile|masterkey|kmsprovider)')
_IDENT_HINT_RE = re.compile(r'(username|principal|email|phone|surname|'
                            r'firstname|lastname|fullname)')
_HOST_HINT_RE = re.compile(r'(hostname|hostandport|hostport|remoteaddr|'
                           r'clientaddr|ipaddr|connectionstring|connstring|'
                           r'syncsource|^host$|^hosts$|^remote$)')
_HINT_SAFE = _nset('userWriteBlockMode', 'tokenBucketLimit', 'tokenCount',
                   'tokens', 'numTokens', 'authenticationMechanism',
                   'authenticationMechanisms', 'saslSupportedMechs',
                   'mechanism', 'keyFileSize')
# Keys holding error / status text that may embed values.
_ERROR_KEYS = _nset(
    'error', 'errmsg', 'errorMessage', 'errorMsg', 'status', 'what',
    'exception', 'failure', 'failReason', 'statusMessage', 'errorString',
    'errorInfo', 'lastError', 'lastErr', 'warning', 'detail', 'description',
    'newTopologyDescription', 'previousTopologyDescription',
    'topologyDescription', 'newDescription', 'previousDescription',
    'serverDescription', 'message', 'explanation')
_INDEX_KEYS = _nset('indexName', 'index', 'indexNames', 'indexes')
# Strings holding BSON-ish documents: { field: value } (chunk ranges ...)
_DOC_TEXT_KEYS = _nset('chunkRange', 'range', 'minKeyRange')

# Aggregation stage options whose string value is a collection name
# ($lookup/$graphLookup.from, $merge.into, $out, $unionWith, {db, coll}).
_AGG_NS_KEYS = _nset('from', 'coll', 'into', 'out', 'unionWith', 'db')
# Public MongoDB documentation hosts appear inside static `msg` texts: not PII.
# (mongodb.net = Atlas cluster hosts ARE customer specific and stay redacted.)
_PUBLIC_DOMAINS = frozenset({'mongodb.com', 'mongodb.org'})
# Keys below which a boolean / 0 / 1 / -1 is query STRUCTURE (projection flag,
# sort direction, update option), not data: never type-erased in filters.
_STRUCT_KEYS = _nset('project', 'sort', 'projection', 'fields', 'unset', 'hint')
_FLAG_KEYS = _nset('multi', 'upsert', 'new', 'remove', 'ordered', 'limit', 'justOne',
                   'returnNewDocument', 'bypassDocumentValidation')
# Keys whose value is a Status / exception message (server: redact(Status))
_STATUS_KEYS = _nset('error', 'errmsg', 'errorMessage', 'errorMsg', 'status', 'what',
                     'exception', 'failure', 'failReason', 'statusMessage',
                     'errorString', 'lastError', 'lastErr', 'reason')
_NS_KEEP_DBS_FULL = frozenset({'config', 'local'})
_NS_KEEP_FIRST = frozenset({'system', 'local', 'admin', 'config'})
_SYSTEM_COLL_HEADS = frozenset({'profile', 'views', 'js', 'users', 'roles', 'version',
                                'keys', 'sessions', 'buckets', 'indexes', 'namespaces'})
# collection-name prefixes whose remainder is a user namespace
_NS_USER_TAIL_PREFIXES = ('config.cache.chunks.',)
_TLDS = frozenset(
    'com net org edu gov mil int info biz io co internal corp lan intranet '
    'home private cloud local localdomain example invalid'.split())
_FILE_EXTS = frozenset(
    'log conf cfg wt js py so cpp h pem key json yaml yml lock txt sh exe '
    'crt cer csv bson'.split())


class Obfuscator:
    """
    Enhanced MongoDB log obfuscator.

    Parameters
    ----------
    arg_logfile : str
        Path to the log file.
    arg_seed : str, optional
        Random seed for deterministic obfuscation.
    arg_pii : bool
        Enable deep PII obfuscation of values inside attr.command.
    arg_add_fields : list[str]
        Extra command-level field names to obfuscate (e.g. ['$comment', '_tid']).
    arg_char_replacement : bool
        Replace strings with x-pattern instead of fruit/colour names.
    """

    def __init__(self, arg_logfile, arg_seed=None, arg_pii=False,
                 arg_add_fields=None, arg_char_replacement=False,
                 arg_char_fields=None, arg_redact_namespaces=False,
                 arg_strict=False, arg_single_pass=False,
                 arg_server_redaction=False, arg_schema_file=None):
        self.logfile = arg_logfile
        self.seed = str(arg_seed) if arg_seed is not None else None
        self.server_redaction = bool(arg_server_redaction)
        self.strict = bool(arg_strict)
        self.single_pass = bool(arg_single_pass)
        self.pii = bool(arg_pii) or self.strict or self.server_redaction
        self.add_fields = [f.strip() for f in (arg_add_fields or [])]
        # --loadSchemaFile: default + schema + --addFields  (a plain union).  Flat names join
        # the --addFields set and so get exactly its scope-independent matching; dotted
        # paths are matched against the ancestor chain in _schema_paths_walk.
        self.schema_file = arg_schema_file
        self.schema_fields, self.schema_paths = [], []
        if arg_schema_file:
            self.schema_fields, self.schema_paths = load_schema_file(arg_schema_file)
            self.add_fields += [f for f in self.schema_fields if f not in self.add_fields]
        self._schema_path_norm = [[self._af_normalize(x) for x in p] for p in self.schema_paths]
        # Normalised names used for scope-independent matching
        # ('$comment' / 'Comment' / 'comment' all become 'comment').
        self._af_norm = set(self._af_normalize(f) for f in self.add_fields if f)
        self._af_text_re = self._build_af_text_regex()
        self.char_replacement = arg_char_replacement
        # char_fields: only meaningful when char_replacement + seed are both set.
        # When char_fields is populated, x-pattern applies only to those fields;
        # everything else uses fruit/colour names (seeded).
        # When char_fields is empty/None and char_replacement is True, ALL values
        # get x-pattern (no fruit/colour at all).
        self.char_fields = set(f.strip() for f in (arg_char_fields or []))
        # redact_namespaces: replace every db/collection name with a stable
        # opaque REDACTED_<hash> token instead of fruit/colour words.
        self.redact_namespaces = arg_redact_namespaces
        self.replacements = {}
        self._ns_tokens = {}   # learned raw name (ns/host/user/app) -> replacement
        self._ipmap = {}
        self._pending_local = set()
        self._rx = None
        self._rx_msg = None
        self._rx_n = -1
        self._stats_depth = 0
        self.fallbacks = 0
        self._learn_local_identity()
        # Hash key.  Seeded runs are reproducible across files; unseeded runs
        # get a random per-run key so hashes cannot be dictionary-attacked.
        self._salt = (self.seed if self.seed is not None
                      else os.urandom(16).hex()).encode('utf-8')
        self.logtype = self._get_logtype()

    def _use_char_replace_for_key(self, key=None):
        """
        Return True when the current value should be x-pattern substituted.

        Rules:
          - char_replacement=False  → never x-pattern
          - char_replacement=True, char_fields empty → always x-pattern
          - char_replacement=True, char_fields set   → x-pattern only for
            fields listed in char_fields (key must match)
        """
        if not self.char_replacement:
            return False
        if not self.char_fields:
            return True          # blanket replacement
        return key in self.char_fields

    # ── Low-level utilities ───────────────────────────────────────────────────

    def _get_by_path(self, data, path):
        if isinstance(path, str):
            keys = path.split('.')
        elif isinstance(path, list):
            keys = path
        else:
            raise TypeError('_get_by_path expects str or list')
        try:
            return reduce(operator.getitem, keys, data)
        except Exception:
            return None

    def _set_by_path(self, data, path, value):
        keys = path.split('.')
        obj = self._get_by_path(data, keys[:-1])
        if isinstance(obj, dict):
            obj[keys[-1]] = value

    # ── Replacement strategies ────────────────────────────────────────────────

    def _fruit_for(self, raw):
        """Map raw string to a deterministic fruit/colour/adjective word."""
        return self.replacements.setdefault(raw, choice(fruits))

    def _color_for(self, raw):
        return self.replacements.setdefault(raw, choice(colors))

    def _hash_for(self, raw):
        key = json.dumps(raw, sort_keys=True) if not isinstance(raw, str) else raw
        return self.replacements.setdefault(key, self._h(key))

    def _obfuscate_scalar(self, value, key=None):
        """Obfuscate a scalar value according to the chosen strategy.

        key is the field name that owns this value; used to decide whether
        x-pattern or fruit/colour substitution applies when char_fields is set.
        """
        if value is None:
            return value
        if isinstance(value, bool):
            return value
        if _is_masked(value):
            return value                   # already redacted (e.g. by the server)
        use_x = self._use_char_replace_for_key(key)
        if isinstance(value, (int, float)):
            if use_x:
                return re.sub(r'\d', 'x', str(value))
            else:
                return self._hash_for(str(value))
        if isinstance(value, str):
            if not value:
                return value
            if use_x:
                # Detect sub-type for nicer output
                if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', value):
                    return _char_replace_email(value)
                if re.match(r'^https?://', value):
                    return _char_replace_url(value)
                return _char_replace(value)
            else:
                # Default: use fruit-salad mapping
                if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', value):
                    local, domain = value.split('@', 1)
                    return (self._fruit_for(local) + '@' +
                            self._color_for(domain.split('.')[0]) + '.com')
                if re.match(r'^https?://', value):
                    return 'https://' + self._color_for(value) + '.' + self._fruit_for(value[::-1]) + '.com'
                return self._fruit_for(value)
        return value

    # ── PII: deep obfuscation of command internals ────────────────────────────

    # ── Original fruitsalad obfuscation methods ───────────────────────────────

    def _redact_ns_part(self, part):
        """Return a stable opaque token for a namespace segment.

        Uses an 8-character truncated MD5 so the same input always produces
        the same token within a run (and across runs with the same seed, since
        the token is hash-based, not random).  Format: REDACTED_<8hex>.
        """
        token = 'REDACTED_' + self._h(part, 8)
        self._ns_tokens[part] = token
        # Store in replacements so other code can look it up if needed
        self.replacements.setdefault(part, token)
        return token

    # ── IP / hostname helpers (TEXT mode) ─────────────────────────────────────

    def _replace_dottedname(self, match):
        parts = match.group(0).split('.')
        replaced = []
        for i, part in enumerate(parts):
            if i == 0 and part in ['system', 'local', 'admin', 'config']:
                return '.'.join(parts)
            if part not in ['$cmd', 'com', 'net', 'org', 'edu', 'gov']:
                if self.redact_namespaces:
                    part = self._redact_ns_part(part)
                elif self._use_char_replace_for_key():
                    part = _char_replace(part)
                elif i == len(parts) - 1:
                    part = self.replacements.setdefault(part, choice(fruits))
                elif i == len(parts) - 2:
                    part = self.replacements.setdefault(part, choice(colors))
                else:
                    part = self.replacements.setdefault(part, choice(adjectives))
            replaced.append(part)
        return '.'.join(replaced)

    def _replace_string(self, match):
        if self._use_char_replace_for_key():
            return '"' + _char_replace(match.group(0).strip('"')) + '"'
        return '"' + self._h(str(match.group(0))) + '"'

    # ── Command-level field obfuscation (--addFields) ─────────────────────────

    # Comparison operators whose array form is [<"$fieldPath">, <literal>, ...]
    _AF_CMP_OPS = {'$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
                   '$cmp'}

    @staticmethod
    def _af_normalize(name):
        return str(name).strip().lstrip('$').lower()

    def _af_key_matches(self, key):
        """True if `key` (or any dotted/positional segment of it) is an addField.

        Handles 'grId', '$comment', 'a.grId', 'arr.0.grId', 'a.$[e].grId',
        'grId.sub' and is case-insensitive.
        """
        if not self._af_norm or not isinstance(key, str):
            return False
        if self._af_normalize(key) in self._af_norm:
            return True
        if '.' in key:
            for seg in key.split('.'):
                if self._af_normalize(seg) in self._af_norm:
                    return True
        return False

    def _af_is_field_ref(self, value):
        """True for aggregation field references such as '$grId' / '$a.grId'."""
        return (isinstance(value, str) and value.startswith('$')
                and not value.startswith('$$') and self._af_key_matches(value))

    def _af_redact_deep(self, value, key=None):
        """Redact EVERY scalar under `value`, including values nested in
        operator documents ({"$in": [...]}, {"$gt": ...}, extended JSON)."""
        if isinstance(value, dict):
            return {k: self._af_redact_deep(v, key=key) for k, v in value.items()}
        if isinstance(value, list):
            return [self._af_redact_deep(v, key=key) for v in value]
        if isinstance(value, str):
            parsed = self._af_try_parse_json(value)
            if parsed is not None:
                return json.dumps(self._af_redact_deep(parsed, key=key))
        return self._obfuscate_scalar(value, key=key)

    @staticmethod
    def _af_try_parse_json(text):
        t = text.lstrip()
        if not t or t[0] not in '{[':
            return None
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return None
        return _mask_bindata(parsed) if isinstance(parsed, (dict, list)) else None

    def _af_walk(self, obj):
        """Mutate/return `obj`: redact addFields wherever they appear.

        Scope-independent: works on any dict/list depth (commands, oplog
        CRUD o/o2, originatingCommand, errors, ...), inside JSON that was
        serialised into a string, in aggregation expressions like
        {"$eq": ["$grId", "abc"]}, and in free text ("grId: abc").
        """
        if isinstance(obj, dict):
            for k in list(obj.keys()):
                v = obj[k]
                if self._af_key_matches(k):
                    obj[k] = self._af_redact_deep(v, key=k)
                    continue
                if k in self._AF_CMP_OPS and isinstance(v, list) and \
                        any(self._af_is_field_ref(x) for x in v):
                    obj[k] = [x if self._af_is_field_ref(x)
                              else self._af_redact_deep(x, key=k) for x in v]
                    continue
                obj[k] = self._af_walk(v)
            return obj
        if isinstance(obj, list):
            for i, item in enumerate(obj):
                obj[i] = self._af_walk(item)
            return obj
        if isinstance(obj, str):
            return self._af_walk_string(obj)
        return obj

    def _af_walk_string(self, text):
        if not text:
            return text
        parsed = self._af_try_parse_json(text)
        if parsed is not None:
            return json.dumps(self._af_walk(parsed))
        return self._af_redact_text(text)

    # -- free-text handling ("grId: abc", "\"grId\": \"abc\"", grId=123) ------

    def _build_af_text_regex(self):
        names = sorted({re.escape(f.strip().lstrip('$')) for f in self.add_fields
                        if f.strip()} |
                       {re.escape('.'.join(p)) for p in self.schema_paths},
                       key=len, reverse=True)
        if not names:
            return None
        value = (r'(?:\\"(?:(?!\\").)*\\"'            # \"escaped\" string
                 r'|"(?:[^"\\]|\\.)*"'                 # "plain" string
                 r"|'(?:[^'\\]|\\.)*'"                 # 'single' string
                 r'|\{[^{}]*\}|\[[^\[\]]*\]'             # one-level {..} / [..]
                 r'|[A-Za-z_]\w*\([^)]*\)'                # ObjectId("..") etc.
                 r'|[^\s,}\]\)"\']+)')                    # bare token / number
        pattern = (r'(?P<pre>(?<![\w])(?:\\?["\']?)\$?(?:' + '|'.join(names) +
                   r')(?:\\?["\']?)\s*[:=]\s*)(?P<val>' + value + ')')
        return re.compile(pattern, re.IGNORECASE | re.DOTALL)

    def _af_text_value(self, val):
        if val[:2] == '\\"' and val.endswith('\\"') and len(val) >= 4:
            return '\\"' + str(self._af_redact_deep(val[2:-2])) + '\\"'
        if val[:1] in ('"', "'") and val[-1:] == val[:1] and len(val) >= 2:
            return val[0] + str(self._af_redact_deep(val[1:-1])) + val[0]
        if val[:1] in '{[':
            parsed = self._af_try_parse_json(val)
            if parsed is not None:
                return json.dumps(self._af_redact_deep(parsed))
        if re.fullmatch(r'-?\d+(\.\d+)?', val):
            num = float(val) if '.' in val else int(val)
            return str(self._af_redact_deep(num))
        return str(self._af_redact_deep(val))

    def _af_redact_text(self, text):
        if not self._af_text_re or not text:
            return text
        return self._af_text_re.sub(
            lambda m: m.group('pre') + self._af_text_value(m.group('val')), text)

    def _obfuscate_add_fields(self, command_obj):
        """Backwards-compatible wrapper around the scope-independent walk."""
        if not self._af_norm:
            return command_obj
        return self._af_walk(command_obj)

    # ══════════════════════════════════════════════════════════════════════════
    # Replacement style - the ONLY place that decides fruit-salad vs x-pattern.
    # Every detection path below calls _replacement()/_obfuscate_scalar(), so
    # both styles have identical coverage.
    # ══════════════════════════════════════════════════════════════════════════

    def _h(self, raw, n=32):
        """Salted HMAC-SHA256 (hex, truncated).  Never plain MD5: low-entropy
        values (SSNs, phone numbers, db names) must not be brute-forceable."""
        if not isinstance(raw, bytes):
            raw = str(raw).encode('utf-8', 'replace')
        return hmac.new(self._salt, raw, hashlib.sha256).hexdigest()[:n]

    def _replacement(self, raw, kind='word', key=None):
        raw = str(raw)
        if _is_masked(raw):
            return raw
        if self._use_char_replace_for_key(key):
            if kind == 'email':
                return _char_replace_email(raw)
            if kind == 'url':
                return _char_replace_url(raw)
            return _char_replace(raw)
        return self._word_for(raw, kind)

    def _word_for(self, raw, kind):
        if kind in ('email', 'url'):
            return self._obfuscate_scalar(raw)
        if kind == 'host':
            k = 'host:' + raw
            v = self.replacements.get(k)
            if v is None:
                v = choice(colors) + '.' + choice(fruits) + '.invalid'
                self.replacements[k] = v
            return v
        return self.replacements.setdefault(raw, choice(fruits))

    def _learn_local_identity(self):
        """The operator's own hostname / OS user commonly end up in logs
        (event ids, dbPath, process details): always treat them as names."""
        import getpass
        import socket
        names = set()
        try:
            h = socket.gethostname()
            names |= {(h, 'host'), (h.split('.')[0], 'host')}
        except OSError:
            pass
        try:
            names.add((getpass.getuser(), 'word'))
        except Exception:
            pass
        for n, kind in names:
            if (n and len(n) >= 4 and n.lower() not in
                    {'root', 'mongod', 'mongodb', 'admin', 'localhost', 'ubuntu',
                     'ec2-user', 'user', 'daemon', 'nobody'}):
                self._pending_local.add((n, kind))

    def _learn(self, raw, repl):
        """Remember raw->replacement so the same name is also replaced inside
        free text that appears later (error strings, descriptions, ...)."""
        if (isinstance(raw, str) and len(raw) >= 3 and raw != repl
                and raw not in _NS_KEEP_FIRST and raw != '$cmd'
                and not raw.isdigit() and raw not in self._ns_tokens
                and not raw.startswith('REDACTED_')
                and not re.fullmatch(r'[x\W_]+', raw)):   # never learn a mask
            self._ns_tokens[raw] = repl

    def _alias(self, raw, kind='word', key=None):
        if not isinstance(raw, str) or not raw or raw == '__system':
            return raw
        red = self._replacement(raw, kind, key)
        self._learn(raw, red)
        return red

    def _blob(self, obj, key=None):
        """Replace a whole value by a salted hash (x-pattern in char mode)."""
        if obj is None or isinstance(obj, (bool, int, float)) \
                or obj in ('', {}, []) or _all_masked(obj):
            return obj
        text = obj if isinstance(obj, str) else json.dumps(obj, sort_keys=True)
        if self._use_char_replace_for_key(key):
            return _char_replace(text)
        return self.replacements.setdefault(text, self._h(text))

    def _map_ip(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if addr.is_loopback or addr.is_unspecified:
            return ip
        if ip in self._ipmap:
            return self._ipmap[ip]
        if self._use_char_replace_for_key():
            fake = 'xxx.xxx.xxx.xxx' if addr.version == 4 else _char_replace(ip)
        else:
            d = bytes.fromhex(self._h('ip:' + ip, 8))
            if addr.version == 4:
                fake = '192.168.%d.%d' % (d[0], d[1])
            else:
                fake = 'fd00::%x:%x' % (d[0] << 8 | d[1], d[2] << 8 | d[3])
        self._ipmap[ip] = fake
        return fake

    # ══════════════════════════════════════════════════════════════════════════
    # Content scanner: PII shapes in ANY string, whatever key it sits under
    # ══════════════════════════════════════════════════════════════════════════

    _RE_URI_CRED = re.compile(
        r'(?P<s>[A-Za-z][A-Za-z0-9+.\-]*://)(?P<u>[^/\s"\'@]+)@')
    _RE_EMAIL = re.compile(
        r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}')
    _RE_JWT = re.compile(r'\beyJ[\w\-]{5,}\.[\w\-]{5,}\.[\w\-]*')
    _RE_BEARER = re.compile(r'(?i)\b(bearer|basic)(\s+)([A-Za-z0-9._~+/=\-]{8,})')
    _RE_AWS = re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b')
    _RE_IBAN = re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b')
    _RE_SSN = re.compile(r'(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])')
    _RE_CARD = re.compile(r'(?<![\w.\-])(?:\d[ \-]?){12,18}\d(?![\w\-])')
    _RE_MAC = re.compile(r'(?<![\w:\-])(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}(?![\w:\-])')
    _RE_IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w)(?!\.\d)')
    _RE_IPV6 = re.compile(r'(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])')
    _RE_PHONE = re.compile(
        r'(?<![\w.])(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.\-]\d{3,4}'
        r'[\s.\-]\d{3,4}(?!\w)(?!\.\d)')
    _LABEL = r'[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?'
    _RE_HOST_PORT = re.compile(
        r'(?<![\w@.\-])(?=[^\s:]*[A-Za-z])(?:' + _LABEL + r'\.)+' + _LABEL +
        r'(?P<port>:\d{2,5})(?!\w)')
    _RE_HOST_TLD = re.compile(
        r'(?<![\w@.\-])(?:' + _LABEL + r'\.)+(?:' + '|'.join(sorted(_TLDS)) +
        r')(?![\w\-])(?!\.\w)', re.IGNORECASE)
    _RE_PATH = re.compile(
        r'(?<![\w.:/\\\-])(?:/(?:[\w.\-@+]+/)+[\w.\-@+]*|'
        r'[A-Za-z]:\\(?:[^\s"\'\\]+\\)*[^\s"\'\\]*)')
    _RE_KEY_SUSPECT = re.compile(r'[@:]|\d\.\d|\d{9}')
    _LEARN_SEP = re.compile(r'[\s.:/,@=;()\[\]{}"\'|]')
    _FIELD_REF = re.compile(r'^\$[A-Za-z_][\w.]*$')

    @staticmethod
    def _luhn_ok(digits):
        total = 0
        for i, ch in enumerate(reversed(digits)):
            n = int(ch)
            if i % 2:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    @staticmethod
    def _iban_ok(text):
        s = text[4:] + text[:4]
        try:
            num = int(''.join(str(int(c, 36)) for c in s))
        except ValueError:
            return False
        return num % 97 == 1

    def _scrub_patterns(self, text):
        """Replace PII-shaped substrings (emails, cards, SSNs, JWTs, tokens,
        MACs, IPs v4/v6, host:port, FQDNs, URI credentials ...)."""
        if not text or not isinstance(text, str):
            return text
        rep = self._replacement

        text = self._RE_URI_CRED.sub(
            lambda m: m.group('s') + rep(m.group('u'), 'word') + '@', text)
        text = self._RE_EMAIL.sub(lambda m: rep(m.group(0), 'email'), text)
        text = self._RE_JWT.sub(lambda m: rep(m.group(0), 'word'), text)
        text = self._RE_BEARER.sub(
            lambda m: m.group(1) + m.group(2) + rep(m.group(3), 'word'), text)
        text = self._RE_AWS.sub(lambda m: rep(m.group(0), 'word'), text)
        text = self._RE_IBAN.sub(
            lambda m: rep(m.group(0), 'word') if self._iban_ok(m.group(0))
            else m.group(0), text)
        text = self._RE_SSN.sub(lambda m: rep(m.group(0), 'word'), text)

        def _card(m):
            raw = m.group(0)
            digits = re.sub(r'\D', '', raw)
            if 13 <= len(digits) <= 19 and (
                    self._luhn_ok(digits) or
                    re.fullmatch(r'\d{4}[ \-]\d{4}[ \-]\d{4}[ \-]\d{1,7}', raw)):
                return rep(raw, 'word')
            return raw
        text = self._RE_CARD.sub(_card, text)
        text = self._RE_MAC.sub(lambda m: rep(m.group(0), 'word'), text)

        def _v4(m):
            parts = m.group(0).split('.')
            if any(int(p) > 255 for p in parts):
                return m.group(0)
            return self._map_ip(m.group(0))
        text = self._RE_IPV4.sub(_v4, text)
        text = self._RE_IPV6.sub(lambda m: self._map_ip(m.group(0)), text)
        text = self._RE_PHONE.sub(lambda m: rep(m.group(0), 'word'), text)

        def _host(m):
            raw = m.group(0)
            port = m.groupdict().get('port') or ''
            host = raw[:len(raw) - len(port)]
            hl = host.lower()
            if (hl.endswith('.invalid') or host.startswith('REDACTED_')
                    or hl in _PUBLIC_DOMAINS
                    or any(hl.endswith('.' + d) for d in _PUBLIC_DOMAINS)):
                return raw                  # own output / public MongoDB docs links
            return self._alias(host, 'host') + port
        text = self._RE_PATH.sub(
            lambda m: m.group(0) if m.group(0).endswith('.sock')
            else rep(m.group(0), 'word'), text)
        text = self._RE_HOST_PORT.sub(_host, text)
        text = self._RE_HOST_TLD.sub(_host, text)
        return text

    @staticmethod
    def _unique_key(out, key):
        """Renaming keys can make two different fields collide (few fruit words,
        x-pattern of 'ab' == 'cd'): never drop a field, suffix on collision."""
        if key not in out:
            return key
        n = 2
        while f'{key}_{n}' in out:
            n += 1
        return f'{key}_{n}'

    def _scrub_key(self, key):
        if isinstance(key, str) and self._RE_KEY_SUSPECT.search(key):
            return self._scrub_patterns(key)
        return key

    def _ns_learned(self, text, msg=False):
        """Replace names learned so far (db, collection, host, user, app) when
        they appear inside free text.  For the static `msg` field only
        identifier-like names are replaced (containing digits / upper case /
        _ - . @): plain lower-case words such as a collection called
        "collections" must not rewrite the sentence."""
        if not text or not self._ns_tokens:
            return text
        if not self._LEARN_SEP.search(text) and not (
                not msg and len(text) >= 8 and text in self._ns_tokens):
            return text
        n = len(self._ns_tokens)
        if n != self._rx_n:
            names = sorted((k for k in self._ns_tokens
                            if len(k) >= 3 and k not in _NS_KEEP_FIRST
                            and not k.isdigit()), key=len, reverse=True)

            def _rx(ns):
                return re.compile(
                    r'(?<![\w$])(' + '|'.join(re.escape(x) for x in ns) +
                    r')(?![\w$])') if ns else None
            self._rx = _rx(names)
            self._rx_msg = _rx([k for k in names if re.search(r'[\d_\-.@]', k)])
            self._rx_n = n
        rx = self._rx_msg if msg else self._rx
        if rx:
            text = rx.sub(lambda m: self._ns_tokens[m.group(1)], text)
        if self.redact_namespaces and 'REDACTED_' in text:
            text = re.sub(
                r'(REDACTED_[0-9a-f]{8})\.([A-Za-z_][\w$]*)(?![\w$.(])',
                lambda m: m.group(1) + '.' + (
                    m.group(2) if m.group(2).startswith('REDACTED_')
                    or m.group(2) == '$cmd'
                    else self._redact_ns_part(m.group(2))), text)
        return text

    def _scrub_text(self, text, key=None, learned=True, msg=False):
        """Content-based scrub of ONE string, independent of its key."""
        if not text or not isinstance(text, str):
            return text
        parsed = self._af_try_parse_json(text)
        if parsed is not None:                 # JSON serialised in a string
            return json.dumps(self._sweep(parsed, key))
        return self._scrub_free(text, learned, msg)

    def _scrub_free(self, text, learned=True, msg=False):
        if self._af_text_re:
            text = self._af_redact_text(text)
        text = self._scrub_patterns(text)
        if learned:
            text = self._ns_learned(text, msg)
        return text

    # ── Error / status text ──────────────────────────────────────────────────

    _RE_QUOTED = re.compile(r'"([^"\n]{1,300})"|\'([^\'\s]{1,100})\'')
    _RE_BRACED = re.compile(r'\{([^{}]*)\}')
    _RE_PAIR = re.compile(r'([A-Za-z_$][\w.$]*)(\s*:\s*)([^,]+?)(\s*(?:,|$))')
    _RE_NSKV = re.compile(
        r'\b(collection|namespace|ns|database|db)(\s*[:=]\s*)([A-Za-z_][\w$.\-]*)')
    _RE_IDXKV = re.compile(r'\b(index|indexName)(\s*[:=]\s*)([^\s,}\]"\']+)')
    _RE_DOTTED = re.compile(
        r'(?<![\w@.$\-])([A-Za-z_][\w\-]+)\.([A-Za-z_$][\w.$\-]+)(?![\w@\-])')

    _RE_PROT = re.compile('\x02[^\x03]*\x03')

    @staticmethod
    def _protect(masked):
        """Wrap already-masked text so later regex passes skip it."""
        return '\x02' + masked + '\x03'

    def _protect_map(self, text, fn):
        out, pos = [], 0
        for m in self._RE_PROT.finditer(text):
            out.append(fn(text[pos:m.start()]))
            out.append(m.group(0))
            pos = m.end()
        out.append(fn(text[pos:]))
        return ''.join(out)

    def _mask_quoted(self, text):
        def _q(m):
            inner = m.group(1) if m.group(1) is not None else m.group(2)
            q = '"' if m.group(1) is not None else "'"
            if inner.startswith('REDACTED_'):
                return m.group(0)
            return q + self._protect(self._alias(inner, 'word')) + q
        return self._RE_QUOTED.sub(_q, text)

    def _mask_braced(self, text):
        """{ field: value, ... } -> keep field names, redact the values."""
        OPEN, CLOSE = '\x00', '\x01'
        for _ in range(6):
            def _b(m):
                body = m.group(1)

                def _p(pm):
                    v = pm.group(3)
                    if (v[:1] in ('"', "'", OPEN) or OPEN in v or CLOSE in v
                            or '\x02' in v
                            or v in ('true', 'false', 'null', '1', '-1', '0', 'MinKey', 'MaxKey')):
                        return pm.group(0)
                    return (pm.group(1) + pm.group(2) +
                            self._protect(self._alias(v.strip(), 'word')) +
                            pm.group(4))
                return OPEN + self._RE_PAIR.sub(_p, body) + CLOSE
            new = self._RE_BRACED.sub(_b, text)
            if new == text:
                break
            text = new
        return text.replace(OPEN, '{').replace(CLOSE, '}')

    def _mask_dotted_ns(self, text):
        def _d(m):
            whole = m.group(0)
            last = whole.split('.')[-1].lower()
            if last in _TLDS or last in _FILE_EXTS or whole.startswith('REDACTED_'):
                return whole
            if whole.lower().endswith('.invalid'):
                return whole
            return self._ns_apply(whole)
        return self._RE_DOTTED.sub(_d, text)

    def _scrub_error_text(self, text, key=None, parent=None):
        nk = _nk(key)
        if _is_masked(text):
            return text
        if self.server_redaction and nk in _STATUS_KEYS:
            return self._server_status(text)                        # S3
        if nk == 'reason' or (nk == 'errmsg' and _nk(parent) == 'error'):
            return self._blob(text, key)
        parsed = self._af_try_parse_json(text)
        if parsed is not None:
            return json.dumps(self._sweep(parsed, key))
        if self._af_text_re:                 # --addFields / --loadSchemaFile names FIRST:
            text = self._af_redact_text(text)  # 'customer.vipCode: x' must not be read as db.coll
        t = self._mask_quoted(text)
        t = self._mask_braced(t)
        pm = self._protect_map
        t = pm(t, lambda seg: self._RE_NSKV.sub(
            lambda m: m.group(1) + m.group(2) + self._ns_apply(
                m.group(3), single='.' not in m.group(3)), seg))
        t = pm(t, lambda seg: self._RE_IDXKV.sub(
            lambda m: m.group(1) + m.group(2) + self._blob(m.group(3), key),
            seg))
        t = pm(t, self._mask_dotted_ns)
        t = pm(t, self._scrub_free)
        return t.replace('\x02', '').replace('\x03', '')

    # ══════════════════════════════════════════════════════════════════════════
    # Namespaces (db / collection names) - same rules in both styles
    # ══════════════════════════════════════════════════════════════════════════

    def _ns_apply(self, ns, single=False):
        if not isinstance(ns, str) or not ns or _is_masked(ns):
            return ns
        if ns in ('local.oplog.rs', 'oplog.rs') or ns.startswith('REDACTED_'):
            return ns
        if single:
            parts = [ns]
        else:
            parts = ns.split('.')
            for pre in _NS_USER_TAIL_PREFIXES:          # config.cache.chunks.<db>.<coll>
                if ns.startswith(pre):
                    return pre + self._ns_apply(ns[len(pre):])
            if parts[0] in _NS_KEEP_DBS_FULL:
                return ns
            if len(parts) > 1 and parts[0] == 'admin' and parts[1] in ('system', '$cmd'):
                return ns
        # <db>.system.<profile|views|...|buckets.<coll>>: keep the system part
        keep_idx = set()
        if not single and len(parts) >= 3 and parts[1] == 'system' \
                and parts[2] in _SYSTEM_COLL_HEADS:
            keep_idx = {1, 2}
        out = []
        n = len(parts)
        for i, part in enumerate(parts):
            if (not part or part == '$cmd' or part.startswith('REDACTED_')
                    or i in keep_idx
                    or (i == 0 and part in _NS_KEEP_FIRST)):
                out.append(part)
                continue
            if self.redact_namespaces:
                r = self._redact_ns_part(part)
            elif self._use_char_replace_for_key():
                r = _char_replace(part)
            elif i == n - 1:
                r = self.replacements.setdefault(part, choice(fruits))
            elif i == n - 2:
                r = self.replacements.setdefault(part, choice(colors))
            else:
                r = self.replacements.setdefault(part, choice(adjectives))
            self._learn(part, r)
            out.append(r)
        return '.'.join(out)

    def _ns_value(self, v, dotted):
        if isinstance(v, str):
            return self._ns_apply(v, single=not (dotted and '.' in v))
        if isinstance(v, list):
            return [self._ns_value(x, dotted) for x in v]
        return v

    # ══════════════════════════════════════════════════════════════════════════
    # Universal sweep
    # ══════════════════════════════════════════════════════════════════════════

    def _is_pii_key(self, key):
        if not isinstance(key, str):
            return False
        n = _nk(key)
        if n in _PII_NORM:
            return True
        if n not in _HINT_SAFE and (_SECRET_HINT_RE.search(n)
                                    or _IDENT_HINT_RE.search(n)):
            return True
        if '.' in key:
            for seg in key.split('.'):
                if _nk(seg) in _PII_NORM:
                    return True
        return self._af_key_matches(key)

    @staticmethod
    def _any_ref(seq, pred):
        """Is there a field reference among the operands, also inside an operand
        array ({"$in": [<value>, ["$email"]]})?"""
        for x in seq:
            if pred(x) or (isinstance(x, list) and Obfuscator._any_ref(x, pred)):
                return True
        return False

    def _is_pii_ref(self, v):
        return (isinstance(v, str) and self._FIELD_REF.match(v) is not None
                and self._is_pii_key(v[1:]))

    def _pii_walk(self, v, key=None, forced=False, payload=False, structural=False):
        """Return a copy of `v` with PII redacted.  `forced` = everything
        below this point is a value to redact (keys/operators are kept).
        `payload` = user DOCUMENT (insert.documents, oplog o/o2 ...): nothing is
        structural, so booleans / null / 0 / 1 are erased too (server S2).
        `structural` = below $project / sort / hint ...: flags are kept."""
        if isinstance(v, dict):
            if _is_ext_scalar(v) and (forced or payload):
                return _MASK if payload else {k: self._pii_walk(x, k, True) for k, x in v.items()}
            out = {}
            for k, val in v.items():
                kk = self._unique_key(out, self._scrub_key(k))
                if (_nk(k) in _KEEP_SCALAR_OPS
                        and not isinstance(val, (dict, list))):
                    out[kk] = val
                    continue
                nk = _nk(k)
                if nk in _AGG_NS_KEYS and isinstance(val, str) and val:
                    out[kk] = self._ns_apply(val, single=True)   # $lookup.from, $out ...
                    continue
                if nk in _NS_DOTTED_KEYS and isinstance(val, str) and val:
                    out[kk] = self._ns_apply(val, single='.' not in val)  # CRUD.ns
                    continue
                if nk == 'op' and isinstance(val, str) and len(val) <= 1:
                    out[kk] = val                     # oplog op code (i/u/d/c/n)
                    continue
                pl = payload or (nk in _DATA_FORCE_KEYS and not k.startswith('$'))
                f = forced or self.strict or self._is_pii_key(k) or pl
                st = (structural or nk in _STRUCT_KEYS or nk in _FLAG_KEYS) and not pl
                out[kk] = self._pii_walk(val, k, f, pl, st)
            return out
        if isinstance(v, list):
            ref = self._any_ref(v, self._is_pii_ref)
            return [self._pii_walk(x, key, forced or ref, payload, structural) for x in v]
        if v is None or isinstance(v, bool):
            # S2: type erasure.  Payload: bool and null.  Elsewhere only a bool
            # under a PII key (hivStatus: true); null / flags stay structural.
            if forced and (payload or (isinstance(v, bool) and not structural)):
                return _MASK
            return v
        if isinstance(v, str):
            if not v or _is_masked(v):
                return v
            if self._FIELD_REF.match(v):
                return v                        # "$path" reference, not a value
            parsed = self._af_try_parse_json(v)
            if parsed is not None:
                return json.dumps(self._pii_walk(parsed, key, forced, payload, structural))
            if forced:
                return self._obfuscate_scalar(v, key=key)
            return self._scrub_text(v, key)
        if forced:
            if not payload and isinstance(v, int) and v in (-1, 0, 1):
                return v                 # inclusion flag / sort direction / constant
            return self._obfuscate_scalar(v, key=key)
        return v

    # ── S2 / S3 : --server_redaction (security.redactClientLogData=true) ─────

    def _server_redact_bson(self, v, alias_keys=False):
        """BSONObj::redact(RedactLevel::all): keys and structure kept, arrays
        walked, every scalar of ANY type becomes "###".
        alias_keys=True (deliberate deviation, sort / hint / projection / fields):
        the keys there are index and field NAMES, which the server leaves visible
        but every other mode of this tool obfuscates."""
        if isinstance(v, dict):
            if _is_ext_scalar(v):
                return _MASK                      # one BSON scalar (oid, date, bindata ...)
            out = {}
            for k, x in v.items():
                nk_ = k
                if alias_keys and not k.startswith('$') and k != '_id':
                    nk_ = self._replacement(k, 'word', k)
                out[self._unique_key(out, self._scrub_key(nk_))] = \
                    self._server_redact_bson(x, alias_keys)
            return out
        if isinstance(v, list):
            return [self._server_redact_bson(x, alias_keys) for x in v]
        return _MASK

    def _server_status(self, text):
        """redact(Status): keep the code name, drop the reason."""
        if not isinstance(text, str) or not text or text == 'OK' or _is_masked(text):
            return text
        m = _STATUS_LEAD_RE.match(text)
        return f'{m.group(1)}: {_MASK}' if m else _MASK

    def _server_status_dict(self, d):
        """Structured Status {code, codeName, errmsg}: keep codes, mask the reason."""
        out = {}
        for k, x in d.items():
            if _nk(k) in ('errmsg', 'message', 'reason', 'what') and isinstance(x, str):
                out[k] = _MASK if x else x
            else:
                out[k] = self._sweep(x, k) if isinstance(x, (dict, list, str)) else x
        return out

    def _sweep_data(self, v, key):
        """User-data subtree (filter, documents, pipeline, bounds ...)."""
        if v is None or isinstance(v, bool) or (
                isinstance(v, (str, dict, list)) and not v):
            return v
        if not isinstance(v, (dict, list, str)):          # number
            if self.pii and self._is_pii_key(key):
                return self._obfuscate_scalar(v, key=key)
            return v
        if self.server_redaction:
            if isinstance(v, str):
                parsed = self._af_try_parse_json(v)
                return (json.dumps(self._server_redact_bson(parsed)) if parsed is not None
                        else (v if _nk(key) in _DATA_STR_SCRUB_ONLY else _MASK))
            return self._server_redact_bson(v)
        if not self.pii:
            return self._blob(v, key)
        payload = _nk(key) in _DATA_FORCE_KEYS and not str(key).startswith('$')
        forced = self.strict or payload or self._is_pii_key(key)
        return self._pii_walk(v, key, forced, payload)

    def _sweep_schema(self, v, key=None):
        """Field / index names (sort, hint, projection ...): keys and string
        values are obfuscated; numbers, booleans and $operators are kept."""
        if isinstance(v, dict):
            out = {}
            for k, val in v.items():
                if k.startswith('$') or k == '_id':
                    nk_ = k
                else:
                    nk_ = self._replacement(k, 'word', k)
                out[self._unique_key(out, nk_)] = self._sweep_schema(val, k)
            return out
        if isinstance(v, list):
            return [self._sweep_schema(x, key) for x in v]
        if isinstance(v, str) and v and not self._FIELD_REF.match(v) \
                and v not in ('text', 'hashed', '2d', '2dsphere'):
            return self._replacement(v, 'word', key)
        return v

    def _redact_strings(self, v, key=None):
        if isinstance(v, str):
            if not v or v == '__system':
                return v
            return self._replacement(v, 'word', key)
        if isinstance(v, dict):
            out = {}
            for k, x in v.items():
                out[self._unique_key(out, self._scrub_key(k))] = self._redact_strings(x, k)
            return out
        if isinstance(v, list):
            return [self._redact_strings(x, key) for x in v]
        return v

    def _sweep_ident(self, v, key, parent=None):
        if isinstance(v, str):
            return self._alias(v, 'word', key)
        if isinstance(v, list):
            return [self._sweep_ident(x, key, parent) for x in v]
        if isinstance(v, dict):
            return self._sweep_dict(v, parent=_nk(key))
        return v

    def _redact_host_token(self, tok, strict, key=None):
        br = False
        m = re.match(r'^\[([^\]]+)\](?::(\d{1,5}))?$', tok)
        if m:
            host, port, br = m.group(1), m.group(2), True
        else:
            try:
                ipaddress.ip_address(tok)
                host, port = tok, None
            except ValueError:
                host, port = re.match(r'^(.+?)(?::(\d{1,5}))?$', tok).groups()
        if host in ('', 'localhost'):
            return tok
        try:
            ipaddress.ip_address(host)
            red = self._map_ip(host)
        except ValueError:
            if strict or port or '.' in host or host in self._ns_tokens:
                red = self._alias(host, 'host', key)
            else:
                return tok
        if br:
            red = '[' + red + ']'
        return red + (':' + port if port else '')

    def _redact_host_text(self, text, strict, key=None):
        if not text or text.startswith('/'):
            return text
        if '://' in text:
            return self._scrub_text(text, key, learned=False)
        prefix = ''
        m = re.match(r'^([A-Za-z0-9_.\-]+)/(.+)$', text)
        if m and (',' in m.group(2) or ':' in m.group(2)):
            prefix = self._alias(m.group(1), 'word', key) + '/'
            text = m.group(2)
        parts = re.split(r'(\s+|,)', text)
        return prefix + ''.join(
            p if (not p or p.isspace() or p == ',')
            else self._redact_host_token(p, strict, key) for p in parts)

    def _sweep_host(self, v, key, parent=None):
        if isinstance(v, str):
            return self._redact_host_text(v, _nk(key) in _HOST_STRICT_KEYS, key)
        if isinstance(v, list):
            return [self._sweep_host(x, key, parent) for x in v]
        if isinstance(v, dict):
            return self._sweep_dict(v, parent=_nk(key))
        return v

    def _plan_summary(self, v):
        if not isinstance(v, str):
            return self._sweep(v, 'planSummary')

        def _obf(match):
            ns = re.sub(r'([^\s]+):',
                        lambda x: self._replacement(x[1], 'word') + ':', match[2])
            return match[1] + ' ' + ns
        return self._scrub_text(re.sub(r'(\w+) ({[^}]+},?)', _obf, v),
                                'planSummary')

    @staticmethod
    def _looks_like_client_meta(v):
        return isinstance(v, dict) and any(
            k in v for k in ('driver', 'os', 'application', 'platform', 'mongos'))

    def _sweep_command(self, v, key=None):
        """Command-like document.  Default-deny: only known structural keys
        are kept; every other key is treated as user data."""
        if self.server_redaction:                      # S2: the whole command BSON
            if isinstance(v, dict):
                out = {}
                for k, x in v.items():
                    out[self._unique_key(out, self._scrub_key(k))] = self._server_redact_bson(
                        x, alias_keys=_nk(k) in _CMD_SCHEMA_KEYS)
                return out
            if isinstance(v, list):
                return [self._sweep_command(x, key) for x in v]
            if isinstance(v, str):
                parsed = self._af_try_parse_json(v)
                return (json.dumps(self._server_redact_bson(parsed)) if parsed is not None
                        else (v if _is_masked(v) or not v else _MASK))
            return v
        if isinstance(v, str):
            parsed = self._af_try_parse_json(v)
            if parsed is not None:
                return json.dumps(self._sweep_command(parsed, key))
            return self._blob(v, key)
        if isinstance(v, list):
            return [self._sweep_command(x, key) for x in v]
        if not isinstance(v, dict):
            return v
        out = {}
        first = True
        for k, val in v.items():
            kk = self._unique_key(out, self._scrub_key(k))
            nk = _nk(k)
            is_first, first = first, False
            if self._af_norm and self._af_key_matches(k):
                out[kk] = self._af_redact_deep(val, key=k)
            elif is_first and isinstance(val, str) and not k.startswith('$'):
                out[kk] = self._ns_apply(
                    val, single=not (nk in _CMD_FULLNS_KEYS and '.' in val))
            elif k == '$db' or nk == 'db':
                out[kk] = self._ns_value(val, False)
            elif nk in _CMD_COLL_KEYS and isinstance(val, str):
                out[kk] = self._ns_apply(val, single=True)
            elif nk in _CMD_FULLNS_KEYS and isinstance(val, str):
                out[kk] = self._ns_apply(val, single='.' not in val)
            elif nk == 'lsid':
                out[kk] = self._redact_strings(val, k)
            elif nk in _CMD_SCHEMA_KEYS:
                out[kk] = self._sweep_schema(val, k)
            elif nk in _CMD_SAFE_KEYS:
                out[kk] = self._sweep(val, k, parent=nk)
            elif nk in _INDEX_KEYS and isinstance(val, (str, list)):
                out[kk] = ([self._blob(x, k) for x in val] if isinstance(val, list)
                           else self._blob(val, k))                 # dropIndexes.index ...
            elif isinstance(val, str) and val and self.pii:
                # unknown top-level string ARGUMENT of a command: a name or a
                # value, never structure -> always redacted
                out[kk] = self._pii_walk(val, k, True)
            else:
                out[kk] = self._sweep_data(val, k)
        return out

    def _sweep_item(self, k, v, parent=None, index_spec=False):
        nk = _nk(k)
        if self._af_norm and self._af_key_matches(k):
            return self._af_redact_deep(v, key=k)
        if v is None or isinstance(v, bool):
            return v
        if nk in _COMMAND_KEYS:
            return self._sweep_command(v, k)
        if nk == 'plansummary':
            return self._plan_summary(v)
        if nk == 'doc' and self._looks_like_client_meta(v):
            return self._sweep(v, k, parent=nk)
        if nk in _DATA_KEYS and not (
                isinstance(v, str) and nk in _DATA_STR_SCRUB_ONLY):
            return self._sweep_data(v, k)
        if nk in _NS_DOTTED_KEYS and isinstance(v, (str, list)):
            return self._ns_value(v, True)
        if nk in _NS_SINGLE_KEYS and isinstance(v, dict):
            # e.g. "Registering new database": attr.db = {"_id": "<db name>", "primary": ...}
            out = {}
            for k2, x in v.items():
                out[self._unique_key(out, self._scrub_key(k2))] = (
                    self._ns_apply(x, single=True) if k2 == '_id' and isinstance(x, str)
                    else self._sweep_item(k2, x, nk))
            return out
        if nk in _NS_SINGLE_KEYS and isinstance(v, (str, list)):
            return self._ns_value(v, False)
        if nk in _INDEX_KEYS and isinstance(v, (str, list)):
            return ([self._blob(x, k) for x in v] if isinstance(v, list)
                    else self._blob(v, k))
        if nk == 'name' and isinstance(v, str) and (
                index_spec or 'index' in (parent or '') or parent in ('spec', 'specs')):
            return self._blob(v, k)
        if nk in _DOC_TEXT_KEYS and isinstance(v, str):
            return self._scrub_text(self._mask_braced(self._mask_quoted(v)).replace('\x02', '').replace('\x03', ''), k)
        if self._stats_depth and nk in ('keypattern', 'multikeypaths'):
            return self._blob(v, k)
        if parent == 'application' and nk == 'name':
            return self._sweep_ident(v, k)
        if nk in _IDENT_KEYS:
            return self._sweep_ident(v, k, parent)
        if nk in _HOST_KEYS:
            return self._sweep_host(v, k, parent)
        if self.server_redaction and nk in _STATUS_KEYS and isinstance(v, dict):
            return self._server_status_dict(v)
        if nk in _ERROR_KEYS and isinstance(v, str):
            return self._scrub_error_text(v, k, parent)
        if nk == 'reason' and isinstance(v, str):
            return self._blob(v, k)
        if nk in _SENSITIVE_TREE_KEYS and isinstance(v, (dict, list, str)):
            return self._redact_strings(v, k)
        if nk not in _HINT_SAFE and isinstance(v, (str, list, dict)):
            if _SECRET_HINT_RE.search(nk):
                return self._redact_strings(v, k)
            if _IDENT_HINT_RE.search(nk):
                return self._sweep_ident(v, k, parent)
            if _HOST_HINT_RE.search(nk):
                return self._sweep_host(v, k, parent)
        if nk == 'stats' and isinstance(v, dict):
            self._stats_depth += 1
            try:
                return self._sweep(v, k, parent=nk)
            finally:
                self._stats_depth -= 1
        return self._sweep(v, k, parent=nk)

    def _sweep_dict(self, d, parent=None):
        index_spec = (isinstance(d.get('key'), dict)
                      and isinstance(d.get('name'), str))
        out = {}
        for k, v in d.items():
            out[self._unique_key(out, self._scrub_key(k))] = self._sweep_item(
                k, v, parent, index_spec)
        return out

    def _sweep(self, v, key=None, parent=None):
        """Generic recursion.  Strings are content-scanned wherever they are."""
        if isinstance(v, dict):
            return self._sweep_dict(v, parent)
        if isinstance(v, list):
            return [self._sweep(x, key, parent) if not isinstance(x, dict)
                    else self._sweep_dict(x, parent) for x in v]
        if isinstance(v, str):
            return self._scrub_text(v, key)
        return v

    def _scrub_plain(self, v):
        """Content scan only (no key semantics) - used for `truncated`/`size`."""
        if isinstance(v, dict):
            out = {}
            for k, x in v.items():
                out[self._unique_key(out, self._scrub_key(k))] = self._scrub_plain(x)
            return out
        if isinstance(v, list):
            return [self._scrub_plain(x) for x in v]
        if isinstance(v, str):
            return self._scrub_text(v, learned=False)
        return v

    # ══════════════════════════════════════════════════════════════════════════
    # Entry / line processing
    # ══════════════════════════════════════════════════════════════════════════

    # ── --loadSchemaFile dotted paths ────────────────────────────────────────

    @staticmethod
    def _path_segments(key):
        """Segments a key contributes to the ancestor chain: 'a.0.b' -> a, b;
        '$set' / '$[e]' / '$' / numeric array indexes are transparent."""
        out = []
        for seg in str(key).split('.'):
            if not seg or seg.isdigit() or seg.startswith('$'):
                continue
            out.append(seg)
        return out

    def _schema_path_hit(self, chain):
        norm = [self._af_normalize(c) for c in chain]
        for spec in self._schema_path_norm:
            n = len(spec)
            if len(norm) >= n and norm[-n:] == spec:
                return True
        return False

    def _schema_ref_hit(self, value):
        """True for an aggregation field reference ('$customer.vipCode') that is a schema path."""
        if not (isinstance(value, str) and value.startswith('$') and not value.startswith('$$')
                and len(value) > 1):
            return False
        return self._schema_path_hit(tuple(self._path_segments(value[1:])))

    def _schema_paths_walk(self, obj, chain=()):
        """Redact the value of every key whose ancestor chain ends with a schema
        path, anywhere in the entry (also inside JSON serialised in a string)."""
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                chain2 = chain + tuple(self._path_segments(k))
                if chain2 != chain and self._schema_path_hit(chain2):
                    out[k] = self._af_redact_deep(v, key=k)
                elif k in self._AF_CMP_OPS and isinstance(v, list) and self._any_ref(
                        v, self._schema_ref_hit):
                    # {"$eq": ["$customer.vipCode", "<value>"]}: the literal is the value
                    out[k] = [x if self._schema_ref_hit(x) or (
                                  isinstance(x, list) and self._any_ref(x, self._schema_ref_hit))
                              else self._af_redact_deep(x, key=k) for x in v]
                else:
                    out[k] = self._schema_paths_walk(v, chain2)
            return out
        if isinstance(obj, list):
            return [self._schema_paths_walk(x, chain) for x in obj]
        if isinstance(obj, str):
            parsed = self._af_try_parse_json(obj)
            if parsed is not None:
                return json.dumps(self._schema_paths_walk(parsed, chain))
        return obj

    def _process_json_line(self, entry):
        """Redact ONE parsed log entry.  Every key at every depth is visited:
        t/s/c/ctx/id/msg/attr/tags/truncated/size and any unknown extras."""
        entry = _mask_bindata(entry)                 # S1, every context
        if self._schema_path_norm:
            entry = self._schema_paths_walk(entry)  # --loadSchemaFile dotted paths
        if not isinstance(entry, dict):
            return self._sweep(entry)
        out = {}
        for k, v in entry.items():
            kk = self._scrub_key(k)
            if k in ('s', 'c', 'id'):
                out[kk] = v
            elif k == 't':
                out[kk] = self._scrub_plain(v)
            elif k in ('msg', 'ctx'):
                out[kk] = self._scrub_text(v, k, msg=(k == 'msg'))
            elif k in ('truncated', 'size', 'tags'):
                out[kk] = self._scrub_plain(v)
            else:
                out[kk] = self._sweep_item(k, v, None)
        return out

    _RE_TEXT_KV = re.compile(
        r'(?P<k>[A-Za-z_$][\w.$]*)(?P<sep>\s*[:=]\s*)(?P<v>[^\s,}\])"\'][^\s,}\])]*)')
    _RE_TEXT_USER = re.compile(
        r'(?i)\b(?P<w>principal|user(?:name)?|(?:logged in|authenticated) as'
        r'(?!\s+(?:principal|user)\b))'
        r'(?P<sep>\s*[:=]?\s+)(?P<v>[A-Za-z0-9_.@\-]{2,})')
    _TEXT_STOP = frozenset(
        'is was has had not from on in to and the for with by at as name '
        'lookup authentication authenticated failed cache info list role '
        'roles id exists does doesnt cannot can'.split())

    def _redact_text_line(self, line):
        """Legacy (pre-4.4) text lines, and the fail-closed fallback."""
        def _kv(m):                         # unquoted  { ssn: 123456789 }
            v = m.group('v')
            if (not self._is_pii_key(m.group('k')) or v.startswith('REDACTED_')
                    or self._FIELD_REF.match(v)
                    or re.fullmatch(r'-?[01]', v)):       # index key direction
                return m.group(0)
            return m.group('k') + m.group('sep') + self._alias(v, 'word', m.group('k'))

        def _user(m):                       # "principal jsmith_admin"
            v = m.group('v')
            if v.lower() in self._TEXT_STOP:
                return m.group(0)
            return m.group('w') + m.group('sep') + self._alias(v, 'word', 'user')
        line = self._RE_TEXT_USER.sub(_user, line)
        line = self._RE_TEXT_KV.sub(_kv, line)
        line = self._scrub_patterns(line)
        if self._af_text_re:
            line = self._af_redact_text(line)
        line = re.sub(r'".+?"', self._replace_string, line)
        line = re.sub(
            r'[a-zA-Z$][^ \t\n\r\f\v:\'"]+(\.[a-zA-Z$][^ \t\n\r\f\v:\'"]+)+',
            self._replace_dottedname, line)
        return self._ns_learned(line)

    def _unparsed_entry(self, text, lineno):
        """A JSON source must produce JSON output on EVERY line.  Lines that
        cannot be parsed are redacted as text and wrapped in a logv2-shaped
        entry so downstream JSON tooling keeps working."""
        return json.dumps({"s": "W", "c": "REDACTOR", "ctx": "ofuscator",
                           "id": 0, "msg": "Unparseable log line redacted",
                           "attr": {"lineNumber": lineno, "line": text}})

    def _process_line(self, raw, lineno):
        """Return the redacted line.  Output format == source format:
        JSON log in -> JSON lines out; text log in -> text lines out."""
        json_source = self.logtype == LogType.JSON
        s = raw.strip()

        def _text(fragment):
            try:
                return self._redact_text_line(fragment)
            except Exception as exc:
                self.fallbacks += 1
                sys.stderr.write(f'WARNING: line {lineno}: '
                                 f'{type(exc).__name__}; line masked\n')
                return '<<REDACTED LINE %d>>' % lineno

        obj, parsed = None, False
        for cand in ((s,) if s[:1] in ('{', '[', '"') else
                     ((s[s.find('{'):],) if s.find('{') > 0 else ())):
            try:
                obj, parsed = json.loads(cand), True
                break
            except ValueError:
                pass                               # e.g. truncated / garbled
        if parsed:
            try:
                return json.dumps(self._process_json_line(obj))
            except Exception as exc:               # fail closed, never echo
                self.fallbacks += 1
                sys.stderr.write(
                    f'WARNING: line {lineno}: {type(exc).__name__} while '
                    f'processing JSON; emitted redacted fallback\n')
                parsed = False
        if s[:1] in ('{', '[') or json_source:
            self.fallbacks += 1
        text = _text(raw.rstrip('\r\n'))
        return self._unparsed_entry(text, lineno) if json_source else text

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self):
        if self.seed is not None:
            rseed(self.seed)
        for n, kind in sorted(self._pending_local):
            self._alias(n, kind)
        if not self.single_pass:
            # Pass 1 (output discarded): learn every db / collection / host /
            # user / app name in the file so free text is scrubbed even when
            # the name is first seen AFTER the line that mentions it.
            real_stderr, sys.stderr = sys.stderr, open(os.devnull, 'w')
            try:
                with open(self.logfile, 'r', encoding='utf-8',
                          errors='replace') as fh:
                    for lineno, line in enumerate(fh, 1):
                        if line.strip():
                            self._process_line(line, lineno)
            finally:
                sys.stderr.close()
                sys.stderr = real_stderr
            self.fallbacks = 0
        with open(self.logfile, 'r', encoding='utf-8', errors='replace') as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                sys.stdout.write(self._process_line(line, lineno) + '\n')
        if self.fallbacks:
            sys.stderr.write(
                f'NOTE: {self.fallbacks} line(s) were not valid structured '
                f'JSON and were redacted with the text-mode fallback.\n')

    def _get_logtype(self):
        with open(self.logfile, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.strip():
                    return LogType.JSON if line.lstrip().startswith('{') else LogType.TEXT
        return LogType.TEXT


# ══════════════════════════════════════════════════════════════════════════════
# FTDC redaction
# ══════════════════════════════════════════════════════════════════════════════

class FtdcRedactor:
    """
    Redact hostInfo fields from MongoDB FTDC metrics.* files.

    For every metrics.* file found in input_dir:
      - Read the raw BSON stream (sequence of length-prefixed BSON docs).
      - In each type-0 (metadata) chunk, replace the values inside the
        'hostInfo' sub-document with '#', except:
          * datetime fields (start / end / currentTime / any datetime.datetime)
            are preserved as-is.
          * The 'ok' field is preserved.
          * hostInfo.system.hostname is replaced with a stable label:
                 "redacted_hostname_redacted_port_number" always.
      - type-1 (metric delta) chunks are written unchanged — they contain
        only compressed numeric deltas and carry no hostInfo text.
      - Write the resulting BSON stream to output_dir/<original filename>.

    Requires pymongo (provides the bson package).
    """

    # Datetime type from Python's datetime module — used for isinstance checks
    # after bson decodes BSON Date values.
    _DATETIME_TYPE = None

    def __init__(self, input_dir, output_dir):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self._ensure_bson()

    @staticmethod
    def _ensure_bson():
        """Raise a clear error if pymongo/bson is not installed."""
        try:
            import bson  # noqa: F401
        except ImportError:
            sys.exit(
                'ERROR: --ftdc_redact requires the pymongo package.\n'
                '       Install it with:  pip install pymongo\n'
            )

    # ── BSON I/O ──────────────────────────────────────────────────────────────

    @staticmethod
    def _read_bson_docs(path):
        """
        Read a raw BSON file and return a list of (raw_bytes, decoded_dict) tuples.

        BSON format: each document is a 4-byte little-endian int32 length
        followed by (length - 4) bytes of data.  The length includes the 4
        length bytes themselves.
        """
        import bson

        docs = []
        with open(path, 'rb') as fh:
            data = fh.read()

        offset = 0
        while offset < len(data):
            if offset + 4 > len(data):
                break
            doc_size = struct.unpack_from('<i', data, offset)[0]
            if doc_size < 5 or offset + doc_size > len(data):
                # Malformed or trailing padding — stop
                break
            raw = data[offset:offset + doc_size]
            decoded = bson.decode(raw)
            docs.append((raw, decoded))
            offset += doc_size

        return docs

    @staticmethod
    def _encode_doc(doc):
        """Re-encode a decoded BSON dict back to bytes."""
        import bson
        return bson.encode(doc)

    # ── Member-id derivation ──────────────────────────────────────────────────

    @staticmethod
    def _derive_member_id(docs):
        """
        Return the replication member _id (integer) for this node by scanning
        the first type-1 (metric delta) chunk in the file.

        FTDC type-1 payload layout:
          bytes 0-3  : uint32 uncompressed length (little-endian)
          bytes 4-N  : zlib-compressed stream
          decompressed: BSON reference doc  followed by packed int64 deltas

        The reference doc contains a full serverStatus + replSetGetStatus
        snapshot.  replSetGetStatus.members is a list; the entry with
        self=True is this node.  Its _id field is the RS member id.

        Falls back to 'unknown' if the chunk cannot be decoded.
        """
        import zlib
        import bson as _bson

        for _raw, decoded in docs:
            if decoded.get('type') != 1:
                continue
            try:
                payload = bytes(decoded.get('data', b''))
                # First 4 bytes are the uncompressed length; zlib stream follows.
                decompressed = zlib.decompress(payload[4:])
                ref_sz = struct.unpack_from('<i', decompressed, 0)[0]
                if ref_sz < 5 or ref_sz > len(decompressed):
                    continue
                ref_doc = _bson.decode(decompressed[:ref_sz])
                members = ref_doc.get('replSetGetStatus', {}).get('members', [])
                for m in members:
                    if m.get('self'):
                        return str(int(m['_id']))
            except Exception:
                pass

        return 'unknown'

    # ── hostInfo redaction ────────────────────────────────────────────────────

    @staticmethod
    def _is_datetime(value):
        """Return True for Python datetime objects (produced by bson.decode)."""
        import datetime
        return isinstance(value, datetime.datetime)

    def _redact_hostinfo_value(self, value):
        """
        Recursively replace scalar values with '#'.

        Preservation rules:
          - datetime.datetime values → kept as-is (timestamps are not PII here)
          - dict/list → recurse
          - everything else (str, int, float, bool, None) → '#'
        """
        if self._is_datetime(value):
            return value
        if isinstance(value, dict):
            return {k: self._redact_hostinfo_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._redact_hostinfo_value(v) for v in value]
        return '#'

    def _redact_hostinfo(self, doc, member_id):
        """
        Mutate the decoded type-0 BSON doc in place:
          - Walk hostInfo recursively and replace all scalar values with '#'.
          - Restore preserved fields:
              * Any datetime value in the walk is kept (handled by _redact_hostinfo_value).
              * 'ok' field at any level is set back to its original value.
          - Replace hostInfo.system.hostname with
            "redacted_hostname_<member_id>:redacted_port_number".
        """
        hi = doc.get('doc', {}).get('hostInfo')
        if not isinstance(hi, dict):
            return  # nothing to do

        # Save 'ok' value before redaction (float like 1.0)
        ok_value = hi.get('ok')

        # Deep-redact all values
        redacted_hi = self._redact_hostinfo_value(hi)

        # Restore 'ok'
        if ok_value is not None:
            redacted_hi['ok'] = ok_value

        # Set the redacted hostname with the RS member _id embedded
        if isinstance(redacted_hi.get('system'), dict):
            redacted_hi['system']['hostname'] = (
                f'redacted_hostname_{member_id}:redacted_port_number'
            )

        doc['doc']['hostInfo'] = redacted_hi

    # ── Per-file processing ───────────────────────────────────────────────────

    def _process_file(self, src_path, dst_path):
        """Read src_path, redact, write to dst_path."""
        docs = self._read_bson_docs(src_path)

        # Derive the RS member _id from the first type-1 chunk's reference doc
        member_id = self._derive_member_id(docs)

        out_chunks = []
        redacted_count = 0
        for raw, decoded in docs:
            if decoded.get('type') == 0:
                # Metadata chunk — redact hostInfo
                self._redact_hostinfo(decoded, member_id)
                out_chunks.append(self._encode_doc(decoded))
                redacted_count += 1
            else:
                # type-1 metric delta chunk — pass through unchanged
                out_chunks.append(raw)

        with open(dst_path, 'wb') as fh:
            for chunk in out_chunks:
                fh.write(chunk)

        return len(docs), redacted_count

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self):
        os.makedirs(self.output_dir, exist_ok=True)

        # Find all metrics.* files in input_dir (non-recursive by design;
        # diagnostic.data is a flat directory)
        pattern = os.path.join(self.input_dir, 'metrics.*')
        files = sorted(_glob.glob(pattern))

        if not files:
            sys.stderr.write(
                f'WARNING: no metrics.* files found in {self.input_dir!r}\n')
            return

        total_files = len(files)
        sys.stderr.write(
            f'[ftdc_redact] Found {total_files} metrics.* file(s) in {self.input_dir!r}\n')

        for i, src_path in enumerate(files, 1):
            filename = os.path.basename(src_path)
            dst_path = os.path.join(self.output_dir, filename)
            try:
                n_docs, n_redacted = self._process_file(src_path, dst_path)
                sys.stderr.write(
                    f'  [{i}/{total_files}] {filename}: '
                    f'{n_docs} docs, {n_redacted} metadata chunk(s) redacted '
                    f'→ {dst_path}\n'
                )
            except Exception as exc:
                sys.stderr.write(
                    f'  [{i}/{total_files}] {filename}: ERROR — {exc}\n')
                traceback.print_exc(file=sys.stderr)

        sys.stderr.write('[ftdc_redact] Done.\n')


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=(
            'ofuscator.py — MongoDB log and FTDC obfuscation tool.\n'
            'Based on fruitsalad (https://github.com/rueckstiess/fruitsalad).\n\n'
            'Select one of the two operating modes with a required flag:\n'
            '  --log_redact <logfile>   Obfuscate a MongoDB log file.\n'
            '  --ftdc_redact            Redact hostInfo from FTDC metrics files.\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Mode selection ────────────────────────────────────────────────────────
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        '--log_redact', metavar='LOGFILE',
        help=(
            'Path to the MongoDB log file to obfuscate. '
            'Supports JSON structured logs (MongoDB 4.4+) and legacy text logs.'
        ),
    )
    mode_group.add_argument(
        '--ftdc_redact', action='store_true', default=False,
        help=(
            'Redact hostInfo fields from FTDC diagnostic.data metrics.* files. '
            'Requires --input_dir and --output_dir.'
        ),
    )

    # ── Log-redact options ────────────────────────────────────────────────────
    log_group = parser.add_argument_group(
        'log_redact options',
        'These options apply only when --log_redact is used.',
    )
    log_group.add_argument(
        '--seed', '-s', metavar='S', default=None,
        help='Seed the random number generator with S (any string). '
             'Same seed on the same log always produces the same output.')
    log_group.add_argument(
        '--pii', action='store_true', default=False,
        help='Enable deep PII obfuscation: walks into attr.command values '
             '(emails, URLs, user data, nested objects/arrays) instead of '
             'hashing the whole command blob.')
    log_group.add_argument(
        '--strict', action='store_true', default=False,
        help='Implies --pii.  Redact EVERY literal value inside query / update '
             '/ pipeline / document subtrees, not only values of known PII '
             'field names.  Field names and operators are preserved.')
    log_group.add_argument(
        '--loadSchemaFile', metavar='FILE', default=None,
        help='JSON file listing extra fields to obfuscate: {"fields": [names at any depth], '
             '"paths": ["customer.vipCode"], "schema": {"customer": {"vipCode": true}}} '
             '(a top-level array is shorthand for "fields").  Rule: default rules + the '
             'schema + --addFields (union).  Uses the fruit words, or x-pattern with '
             '--char_replacement.')
    log_group.add_argument(
        '--server_redaction', '--redactClientLogData', dest='server_redaction',
        action='store_true', default=False,
        help='Emulate the server\'s security.redactClientLogData=true on client-data '
             'attributes: BSON redaction level "all" (every scalar of any type -> "###", '
             'keys and structure kept) and Status / exception text -> "CodeName: ###". '
             'Implies --pii.  The mask is always "###" (ignores --char_replacement for '
             'those values).  BinData Encrypt/Sensitive masking is always on.')
    log_group.add_argument(
        '--single_pass', action='store_true', default=False,
        help='Skip the name-learning pre-pass (about 2x faster).  Names are '
             'then only replaced in free text AFTER the line that first '
             'reveals them.')
    log_group.add_argument(
        '--addFields', metavar='FIELDS', default=None,
        help="Comma-separated list of extra command-level field names to "
             "obfuscate when --pii is active (e.g. '$comment,_tid').")
    log_group.add_argument(
        '--redactNamespaces', action='store_true', default=False,
        help='Replace every database name and collection name with a stable '
             'opaque token (REDACTED_<hash>). Well-known system namespaces '
             '(local, admin, config, $cmd) are preserved.')
    log_group.add_argument(
        '--char_replacement', action='store_true', default=False,
        help='Use x-pattern placeholders instead of fruit/colour names. '
             'Alone: all obfuscated values become x-pattern. '
             'With --seed and --char_fields: only the listed fields get x-pattern.')
    log_group.add_argument(
        '--char_fields', metavar='FIELDS', default=None,
        help="Comma-separated field names that get x-pattern output when "
             "--char_replacement and --seed are both active. "
             "Has no effect without --char_replacement.")

    # ── FTDC-redact options ───────────────────────────────────────────────────
    ftdc_group = parser.add_argument_group(
        'ftdc_redact options',
        'These options apply only when --ftdc_redact is used.',
    )
    ftdc_group.add_argument(
        '--input_dir', metavar='DIR', default=None,
        help='Directory containing metrics.* FTDC files (required with --ftdc_redact).')
    ftdc_group.add_argument(
        '--output_dir', metavar='DIR', default=None,
        help='Directory where redacted metrics.* files will be written '
             '(required with --ftdc_redact). Created if it does not exist.')

    args = parser.parse_args()

    # ── Dispatch ──────────────────────────────────────────────────────────────

    if args.log_redact:
        # Validate that FTDC-only options were not passed
        if args.input_dir or args.output_dir:
            parser.error('--input_dir / --output_dir are only valid with --ftdc_redact')

        add_fields = None
        if args.addFields:
            add_fields = [f.strip() for f in args.addFields.split(',') if f.strip()]

        char_fields = None
        if args.char_fields:
            char_fields = [f.strip() for f in args.char_fields.split(',') if f.strip()]

        try:
            tool = Obfuscator(
                arg_logfile=args.log_redact,
                arg_seed=args.seed,
                arg_pii=args.pii,
                arg_add_fields=add_fields,
                arg_char_replacement=args.char_replacement,
                arg_char_fields=char_fields,
                arg_redact_namespaces=args.redactNamespaces,
                arg_strict=args.strict,
                arg_single_pass=args.single_pass,
                arg_server_redaction=args.server_redaction,
                arg_schema_file=args.loadSchemaFile,
            )
        except SchemaFileError as exc:
            parser.error(f'--loadSchemaFile: {exc}')
        tool.run()

    elif args.ftdc_redact:
        # Validate that log-only options were not passed
        log_only_opts = {
            '--seed': args.seed,
            '--pii': args.pii,
            '--strict': args.strict,
            '--single_pass': args.single_pass,
            '--server_redaction': args.server_redaction,
            '--addFields': args.addFields,
            '--loadSchemaFile': args.loadSchemaFile,
            '--redactNamespaces': args.redactNamespaces,
            '--char_replacement': args.char_replacement,
            '--char_fields': args.char_fields,
        }
        for flag, val in log_only_opts.items():
            if val:
                parser.error(f'{flag} is only valid with --log_redact')

        if not args.input_dir:
            parser.error('--ftdc_redact requires --input_dir')
        if not args.output_dir:
            parser.error('--ftdc_redact requires --output_dir')
        if not os.path.isdir(args.input_dir):
            parser.error(f'--input_dir {args.input_dir!r} is not a directory or does not exist')

        redactor = FtdcRedactor(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
        )
        redactor.run()

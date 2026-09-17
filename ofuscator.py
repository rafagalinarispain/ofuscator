#!/usr/bin/env python3
"""
ofuscator.py - Enhanced MongoDB log obfuscation tool.

Based on fruitsalad (https://github.com/rueckstiess/fruitsalad) by Thomas Rueckstiess.

Enhancements:
  --pii            Deep PII obfuscation: walks into attr.command values (emails,
                   URLs, strings, nested objects/arrays) instead of hashing the
                   whole command blob.
  --addFields      Comma-separated list of additional top-level command fields to
                   obfuscate (e.g. '$comment', '_tid').
  --redactNamespaces
                   Replace every database name and collection name with a stable
                   opaque token (REDACTED_<8-char-hash>) so that the real
                   namespace is never visible in the output.  Well-known system
                   namespaces (local, admin, config, $cmd) are preserved.
                   Covers: attr.ns, attr.command.$db, attr.command.find/update/
                   insert/delete/aggregate/collection, and all other paths that
                   go through namespace obfuscation.  In text-mode logs every
                   dotted hostname/namespace segment is also replaced.
  --char_replacement
                   Used alone: replaces ALL obfuscated values with an x-pattern
                   placeholder (e.g. "lemon@antiquewhite.com" → "xxxxx@xxxxxxxxxxx.xxx").
                   No fruit/colour names are used at all.
                   Used together with --seed and --char_fields: the main obfuscation
                   uses fruit/colour names (seeded), but the fields listed in
                   --char_fields are replaced with x-pattern instead, making those
                   specific fields immediately identifiable as processed.
  --char_fields    Comma-separated field names that should receive x-pattern output
                   when --char_replacement and --seed are both active.
                   Has no effect without --char_replacement.
  --seed           Seed the random number generator (same seed → same mapping).
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
                 arg_char_fields=None, arg_redact_namespaces=False):
        self.logfile = arg_logfile
        self.seed = str(arg_seed) if arg_seed is not None else None
        self.pii = arg_pii
        self.add_fields = [f.strip() for f in (arg_add_fields or [])]
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
        return self.replacements.setdefault(
            key, hashlib.md5(key.encode('utf-8')).hexdigest())

    def _obfuscate_scalar(self, value, key=None):
        """Obfuscate a scalar value according to the chosen strategy.

        key is the field name that owns this value; used to decide whether
        x-pattern or fruit/colour substitution applies when char_fields is set.
        """
        if value is None:
            return value
        if isinstance(value, bool):
            return value
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

    def _obfuscate_value(self, value, key=None):
        """
        Recursively obfuscate a value.
        For dicts, only recurse into non-operator keys.
        For lists, recurse into each element.
        key is propagated so _obfuscate_scalar can decide x-pattern vs fruit/colour.
        """
        if isinstance(value, dict):
            result = {}
            for k, v in value.items():
                if k in _SKIP_KEYS and k != key:
                    result[k] = v  # keep structural/operator keys as-is
                elif k.startswith('$') and k not in (self.add_fields or []):
                    result[k] = v
                else:
                    result[k] = self._obfuscate_value(v, key=k)
            return result
        elif isinstance(value, list):
            # list elements inherit the parent key for x-pattern decisions
            return [self._obfuscate_value(item, key=key) for item in value]
        else:
            return self._obfuscate_scalar(value, key=key)

    # ── PII: deep obfuscation of command internals ────────────────────────────

    def _obfuscate_command_pii(self, data, path):
        """
        Deep-walk the object at `path` and obfuscate values of PII keys,
        plus any keys listed in self.add_fields.
        """
        obj = self._get_by_path(data, path)
        if obj is None or obj == {}:
            return
        if isinstance(obj, str):
            # Already a string (perhaps from prior hashing) — skip
            return
        self._walk_pii(obj)
        self._set_by_path(data, path, obj)

    def _walk_pii(self, obj):
        """Mutate `obj` in place: obfuscate PII fields recursively.

        Handles both nested dict keys ('ssn') and MongoDB dot-notation flat
        keys ('identity.ssn') that appear in filter/query documents.
        """
        if isinstance(obj, dict):
            for k in list(obj.keys()):
                # Match the bare key OR the last segment of a dotted key
                # e.g. "identity.ssn" → bare segment "ssn"
                bare = k.split('.')[-1]
                is_pii_key = (k in _PII_VALUE_KEYS or
                              k.lower() in _PII_VALUE_KEYS or
                              bare in _PII_VALUE_KEYS or
                              bare.lower() in _PII_VALUE_KEYS or
                              k in self.add_fields or
                              bare in self.add_fields)
                if is_pii_key:
                    obj[k] = self._obfuscate_value(obj[k], key=k)
                elif isinstance(obj[k], (dict, list)):
                    self._walk_pii(obj[k])
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._walk_pii(item)

    # ── Original fruitsalad obfuscation methods ───────────────────────────────

    def _obfuscate_user(self, data, path):
        user = self._get_by_path(data, path)
        if user is None or user in ['__system']:
            return
        if self._use_char_replace_for_key('principalName'):
            self._set_by_path(data, path, _char_replace(user))
        else:
            self._set_by_path(data, path,
                               self.replacements.setdefault(user, choice(fruits)))

    def _redact_ns_part(self, part):
        """Return a stable opaque token for a namespace segment.

        Uses an 8-character truncated MD5 so the same input always produces
        the same token within a run (and across runs with the same seed, since
        the token is hash-based, not random).  Format: REDACTED_<8hex>.
        """
        token = 'REDACTED_' + hashlib.md5(part.encode()).hexdigest()[:8]
        # Store in replacements so other code can look it up if needed
        self.replacements.setdefault(part, token)
        return token

    def _obfuscate_namespace(self, data, path):
        ns = self._get_by_path(data, path)
        if ns is None:
            return
        if ns in ['local.oplog.rs', 'oplog.rs']:
            return
        parts = ns.split('.')
        replaced = []
        for i, part in enumerate(parts):
            if (i == 0 and part in ['system', 'local', 'admin', 'config']
                    or part in ['$cmd']):
                replaced.append(part)
                continue
            if self.redact_namespaces:
                part_out = self._redact_ns_part(part)
            elif self._use_char_replace_for_key():
                part_out = _char_replace(part)
            elif i == len(parts) - 1:
                part_out = self.replacements.setdefault(part, choice(fruits))
            elif i == len(parts) - 2:
                part_out = self.replacements.setdefault(part, choice(colors))
            else:
                part_out = self.replacements.setdefault(part, choice(adjectives))
            replaced.append(part_out)
        self._set_by_path(data, path, '.'.join(replaced))

    def _obfuscate_command(self, data, path):
        """Hash the whole command object (original fruitsalad behaviour)."""
        obj = self._get_by_path(data, path)
        if obj is None or obj == {}:
            return
        use_x = self._use_char_replace_for_key()
        if isinstance(obj, str):
            if use_x:
                self._set_by_path(data, path, _char_replace(obj))
            else:
                self._set_by_path(data, path, self._hash_for(obj))
            return
        command = json.dumps(obj, sort_keys=True)
        if use_x:
            self._set_by_path(data, path, _char_replace(command))
        else:
            self._set_by_path(data, path,
                               self.replacements.setdefault(
                                   command, hashlib.md5(command.encode()).hexdigest()))

    def _obfuscate_keys(self, data, path):
        obj = self._get_by_path(data, path)
        if obj is None:
            return
        doc = {}
        for key in obj:
            if self._use_char_replace_for_key():
                doc[_char_replace(key)] = obj[key]
            else:
                doc[self.replacements.setdefault(key, choice(fruits))] = obj[key]
        self._set_by_path(data, path, doc)

    def _obfuscate_planSummary(self, data):
        planSummary = self._get_by_path(data, "attr.planSummary")
        if planSummary is None:
            return
        plan = json.dumps(planSummary).strip('"')

        def _obfuscate_plan(match):
            ns = re.sub(
                r'([^\s]+):',
                lambda x: ((_char_replace(x[1]) if self._use_char_replace_for_key()
                             else self.replacements.setdefault(x[1], choice(fruits))) + ':'),
                match[2])
            return match[1] + ' ' + ns

        obfuscated_plan = re.sub(r'(\w+) ({[^}]+},?)', _obfuscate_plan, plan)
        self._set_by_path(data, "attr.planSummary", obfuscated_plan)

    def _obfuscate_truncation(self, data):
        obj = self._get_by_path(data, "truncated")
        if obj is None:
            return
        for key in obj.keys():
            for subkey in obj.get(key, {}):
                if self.pii:
                    self._obfuscate_command_pii(data, "truncated." + key + '.' + subkey)
                else:
                    self._obfuscate_command(data, "truncated." + key + '.' + subkey)

    def _obfuscate_stats(self, data):
        path = "attr.stats.inputStage.inputStages"
        obj = self._get_by_path(data, path)
        if obj is None:
            return
        for stage in obj:
            if stage == {}:
                continue
            for val in ["filter", "keyPattern", "indexName", "multiKeyPaths", "indexBounds"]:
                if val not in stage:
                    continue
                raw = json.dumps(stage[val])
                if self._use_char_replace_for_key():
                    stage[val] = _char_replace(raw)
                else:
                    stage[val] = self.replacements.setdefault(
                        raw, hashlib.md5(raw.encode()).hexdigest())
        self._set_by_path(data, path, obj)

    # ── IP / hostname helpers (TEXT mode) ─────────────────────────────────────

    def _replace_ip(self, match):
        ip = match.group(2)
        if ip == '127.0.0.1':
            return match.group(1) + ip + match.group(3)
        if ip in self.replacements:
            return match.group(1) + self.replacements[ip] + match.group(3)
        if self._use_char_replace_for_key():
            fake = 'xxx.xxx.xxx.xxx'
        else:
            n1, n2 = randrange(0, 255), randrange(0, 255)
            fake = '192.168.%i.%i' % (n1, n2)
        return match.group(1) + self.replacements.setdefault(ip, fake) + match.group(3)

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
        return '"' + hashlib.md5(str(match.group(0)).encode('utf-8')).hexdigest() + '"'

    # ── Command-level field obfuscation (--addFields) ─────────────────────────

    def _obfuscate_add_fields(self, command_obj):
        """
        Walk the command object and obfuscate the values of fields listed
        in self.add_fields (e.g. '$comment', '_tid').
        """
        if not self.add_fields or not isinstance(command_obj, dict):
            return

        def _walk(obj):
            if isinstance(obj, dict):
                for k in list(obj.keys()):
                    if k in self.add_fields:
                        obj[k] = self._obfuscate_value(obj[k], key=k)
                    else:
                        _walk(obj[k])
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item)

        _walk(command_obj)

    # ── JSON log processing ───────────────────────────────────────────────────

    def _process_json_line(self, loaded_line):
        if "attr" not in loaded_line:
            return loaded_line

        if "truncated" in loaded_line:
            self._obfuscate_truncation(loaded_line)

        # Reason / indexName
        self._obfuscate_command(loaded_line, "attr.reason")
        self._obfuscate_command(loaded_line, "attr.indexName")

        # Auth namespaces / users
        self._obfuscate_namespace(loaded_line, "attr.authenticationDatabase")
        self._obfuscate_user(loaded_line, "attr.principalName")

        # Namespaces
        for ns_path in [
            "attr.namespace", "attr.sourceNamespace", "attr.targetNamespace",
            "attr.ns", "attr.fromName", "attr.toName", "attr.command.$db",
        ]:
            self._obfuscate_namespace(loaded_line, ns_path)

        # Collection-level namespaces
        for coll_path in [
            "attr.command.aggregate", "attr.command.find",
            "attr.command.update", "attr.command.insert",
            "attr.command.delete", "attr.command.killCursors",
            "attr.command.collection",
            "attr.command.drop", "attr.command.dropIndexes",
            "attr.command.create", "attr.command.createIndexes",
            "attr.command.renameCollection", "attr.command.listIndexes",
            "attr.command.validate", "attr.command.compact",
        ]:
            self._obfuscate_namespace(loaded_line, coll_path)

        # Command bodies
        if self.pii:
            # Deep PII walk instead of hashing the whole blob
            for cmd_path in [
                "attr.command.q", "attr.command.u",
                "attr.command.pipeline", "attr.command.filter",
                "attr.command.query",
            ]:
                self._obfuscate_command_pii(loaded_line, cmd_path)

            # Also walk 'updates' array (each element has q/u)
            updates = self._get_by_path(loaded_line, "attr.command.updates")
            if isinstance(updates, list):
                for upd in updates:
                    if isinstance(upd, dict):
                        for sub in ['q', 'u']:
                            if sub in upd:
                                self._walk_pii(upd[sub])
                        # addFields inside each update
                        self._obfuscate_add_fields(upd)
        else:
            for cmd_path in [
                "attr.command.q", "attr.command.u",
                "attr.command.pipeline", "attr.command.filter",
                "attr.command.query",
            ]:
                self._obfuscate_command(loaded_line, cmd_path)

        self._obfuscate_command(loaded_line, "attr.error.errmsg")

        # Redact free-text error/status fields that may embed namespace strings
        if self.redact_namespaces:
            for err_path in ["attr.errMsg", "attr.errmsg"]:
                raw = self._get_by_path(loaded_line, err_path)
                if isinstance(raw, str) and raw:
                    # Replace any dotted namespace tokens inside the error string
                    redacted = re.sub(
                        r'\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_\$][A-Za-z0-9_\.]*)\b',
                        lambda m: self._redact_ns_part(m.group(1)) + '.' + self._redact_ns_part(m.group(2)),
                        raw
                    )
                    self._set_by_path(loaded_line, err_path, redacted)

        # --addFields: obfuscate specified fields anywhere in attr.command
        cmd = self._get_by_path(loaded_line, "attr.command")
        if cmd and self.add_fields:
            self._obfuscate_add_fields(cmd)

        # Sort keys
        self._obfuscate_keys(loaded_line, "attr.command.sort")

        # Plan summary
        self._obfuscate_planSummary(loaded_line)

        # CRUD
        self._obfuscate_namespace(loaded_line, "attr.CRUD.ns")
        self._obfuscate_command(loaded_line, "attr.CRUD.o")

        # Originating command
        if self._get_by_path(loaded_line, 'attr.originatingCommand') is not None:
            self._obfuscate_namespace(loaded_line, "attr.originatingCommand.find")
            self._obfuscate_command(loaded_line, "attr.originatingCommand.aggregate")
            self._obfuscate_namespace(loaded_line, "attr.originatingCommand.$db")
            self._obfuscate_command(loaded_line, "attr.originatingCommand.filter")
            self._obfuscate_command(loaded_line, "attr.originatingCommand.projection")

        if self._get_by_path(loaded_line, 'attr.stats') is not None:
            self._obfuscate_stats(loaded_line)

        return loaded_line

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self):
        if self.seed is not None:
            rseed(self.seed)

        line_counter = 0
        with open(self.logfile, 'r', encoding='utf-8', errors='replace') as fh:
            for logevent in fh:
                line = logevent

                # Replace IPs in both modes
                line = re.sub(
                    r'([^\w])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^\w])',
                    self._replace_ip, line)

                if self.logtype == LogType.TEXT:
                    line = re.sub(r'".+?"', self._replace_string, line)
                    line = re.sub(
                        r'[a-zA-Z$][^ \t\n\r\f\v:\'"]+(\.[a-zA-Z$][^ \t\n\r\f\v:\'"]+)+',
                        self._replace_dottedname, line)
                    sys.stdout.write(line.rstrip() + '\n')

                elif self.logtype == LogType.JSON:
                    line_counter += 1
                    try:
                        loaded_line = json.loads(line)
                    except json.decoder.JSONDecodeError:
                        if re.match(r'^\s*$', line):
                            continue
                        sys.stderr.write(
                            f'Error reading line {line_counter} from {self.logfile}\n\n')
                        traceback.print_exc()
                        sys.stderr.write('\nRaw JSON:\n' + line + '\n')
                        sys.exit(1)

                    try:
                        loaded_line = self._process_json_line(loaded_line)
                    except Exception:
                        sys.stderr.write(
                            f'Error processing line {line_counter} from {self.logfile}\n\n')
                        traceback.print_exc()
                        sys.stderr.write('\nRaw JSON:\n' + line + '\n')
                        sys.exit(1)

                    print(json.dumps(loaded_line))

    def _get_logtype(self):
        with open(self.logfile, 'r', encoding='utf-8', errors='replace') as f:
            line = f.readline().lstrip()
        return LogType.JSON if line.startswith('{') else LogType.TEXT


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=(
            'ofuscator.py — Enhanced MongoDB log obfuscation tool.\n'
            'Based on fruitsalad (https://github.com/rueckstiess/fruitsalad).'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        'logfile', type=str,
        help='Path to the MongoDB log file to obfuscate.')
    parser.add_argument(
        '--seed', '-s', metavar='S', default=None,
        help='Seed the random number generator with S (any string). '
             'Using the same seed on the same log produces the same output.')
    parser.add_argument(
        '--pii', action='store_true', default=False,
        help='Enable deep PII obfuscation: walks into attr.command values '
             '(emails, URLs, user data, nested objects/arrays) instead of '
             'hashing the whole command blob.')
    parser.add_argument(
        '--addFields', metavar='FIELDS', default=None,
        help='Comma-separated list of extra command-level field names to '
             'obfuscate when --pii is active (e.g. \'$comment,_tid\').')
    parser.add_argument(
        '--redactNamespaces', action='store_true', default=False,
        help='Replace every database name and collection name with a stable '
             'opaque token (REDACTED_<hash>) so that the real namespace is '
             'never visible in the output. Well-known system namespaces '
             '(local, admin, config, $cmd) are preserved. '
             'Covers attr.ns, attr.command.$db, and all command collection '
             'fields (find, update, insert, delete, aggregate, etc.).')
    parser.add_argument(
        '--char_replacement', action='store_true', default=False,
        help='Obfuscate using x-pattern placeholders instead of fruit/colour names. '
             'Used alone: ALL obfuscated values become x-pattern '
             '(e.g. "lemon@antiquewhite.com" → "xxxxx@xxxxxxxxxxx.xxx"). '
             'Used together with --seed and --char_fields: the main obfuscation '
             'uses fruit/colour names, but the fields listed in --char_fields '
             'receive x-pattern output, making them clearly identifiable as processed.')
    parser.add_argument(
        '--char_fields', metavar='FIELDS', default=None,
        help='Comma-separated field names that get x-pattern output when '
             '--char_replacement and --seed are both active '
             '(e.g. \'emails,externalShares,$comment\'). '
             'All other fields continue to use fruit/colour obfuscation. '
             'Has no effect without --char_replacement.')

    args = parser.parse_args()

    add_fields = None
    if args.addFields:
        add_fields = [f.strip() for f in args.addFields.split(',') if f.strip()]

    char_fields = None
    if args.char_fields:
        char_fields = [f.strip() for f in args.char_fields.split(',') if f.strip()]

    tool = Obfuscator(
        arg_logfile=args.logfile,
        arg_seed=args.seed,
        arg_pii=args.pii,
        arg_add_fields=add_fields,
        arg_char_replacement=args.char_replacement,
        arg_char_fields=char_fields,
        arg_redact_namespaces=args.redactNamespaces,
    )
    tool.run()

# peercast/webauthn.py
"""
WebAuthn endpoints for PeerCast.

Goals:
- Robust across python-fido2 library shape differences (dict vs object results).
- Defensive handling of stored public keys (COSE bytes vs JSON map).
- Detailed debug logging to help diagnose mismatched shapes.
"""
import os
import json
import time
import base64
import pickle
import logging
from datetime import datetime, timezone
from types import SimpleNamespace

from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login as django_login, authenticate as django_authenticate
from core.models import UserProfile

import boto3
from boto3.dynamodb.conditions import Key

# fido2 imports
from fido2.server import Fido2Server
from fido2.utils import websafe_encode, websafe_decode

# safe imports (entities, client helpers)
try:
    from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
except Exception:
    from fido2.webauthn import PublicKeyCredentialRpEntity
    PublicKeyCredentialUserEntity = None

try:
    from fido2.client import CollectedClientData
except Exception:
    CollectedClientData = None

# COSEKey helper (optional; used to convert dict COSE -> bytes or create object)
COSEKey = None
try:
    from fido2.cose import COSEKey as _COSEKey
    COSEKey = _COSEKey
    logging.getLogger(__name__).info("COSEKey imported successfully from fido2.cose")
except ImportError:
    try:
        from fido2.cose import CoseKey as _COSEKey
        COSEKey = _COSEKey
        logging.getLogger(__name__).info("CoseKey imported successfully from fido2.cose (aliased to COSEKey)")
    except ImportError:
        logging.getLogger(__name__).warning("COSEKey/CoseKey could not be imported from fido2.cose")
except Exception as e:
    logging.getLogger(__name__).warning("COSEKey import warning: %s", e)
    COSEKey = None

# CBOR helper — prefer cbor2 for robust encoding/decoding
cbor = None
try:
    import cbor2
    cbor = cbor2
except Exception:
    try:
        from fido2 import cbor as fido_cbor
        cbor = fido_cbor
    except Exception:
        cbor = None

# AttestationObject / AuthenticatorData may be in different modules
AttestationObject = None
AuthenticatorData = None
for mod in ("fido2.ctap2", "fido2.attestation", "fido2.webauthn"):
    try:
        m = __import__(mod, fromlist=['AttestationObject', 'AuthenticatorData'])
        if AttestationObject is None:
            AttestationObject = getattr(m, 'AttestationObject', None)
        if AuthenticatorData is None:
            AuthenticatorData = getattr(m, 'AuthenticatorData', None)
    except Exception:
        continue

logger = logging.getLogger(__name__)

# ---------- config ----------
RP_ID = os.environ.get("RP_ID", "localhost")
RP_NAME = os.environ.get("RP_NAME", "PeerCast")
ORIGIN = os.environ.get("ORIGIN", f"http://{RP_ID}")

DYNAMO_TABLE_CREDS = os.environ.get("WEBAUTHN_CREDS_TABLE", "webauthn_credentials")
DYNAMO_TABLE_CHALLENGES = os.environ.get("WEBAUTHN_CHALLENGES_TABLE", "webauthn_challenges")

AWS_REGION = os.environ.get("REGION_AWS")
AWS_ACCESS_KEY = os.environ.get("ACCESS_KEY_AWS")
AWS_SECRET_KEY = os.environ.get("SECRET_KEY_AWS")

# ---------- boto3 init ----------
boto_kwargs = {}
if AWS_REGION:
    boto_kwargs['region_name'] = AWS_REGION
if AWS_ACCESS_KEY and AWS_SECRET_KEY:
    boto_kwargs['aws_access_key_id'] = AWS_ACCESS_KEY
    boto_kwargs['aws_secret_access_key'] = AWS_SECRET_KEY

dynamodb = boto3.resource('dynamodb', **boto_kwargs)
creds_table = dynamodb.Table(DYNAMO_TABLE_CREDS)
ch_table = dynamodb.Table(DYNAMO_TABLE_CHALLENGES)

# ---------- FIDO2 server ----------
rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(rp)

# ---------- helpers ----------
def b64u(b: bytes) -> str:
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("b64u expects bytes")
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def b64u_to_bytes(s: str) -> bytes:
    if s is None:
        return b''
    if isinstance(s, str):
        s_bytes = s.encode('ascii')
    elif isinstance(s, (bytes, bytearray)):
        s_bytes = bytes(s)
    else:
        raise TypeError("b64u_to_bytes expects str or bytes")
    padding = b'=' * (-len(s_bytes) % 4)
    return base64.urlsafe_b64decode(s_bytes + padding)

def convert_to_json_safe(obj):
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return b64u(bytes(obj))
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, dict):
        return {k: convert_to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [convert_to_json_safe(i) for i in obj]
    if hasattr(obj, '__dict__'):
        return convert_to_json_safe(obj.__dict__)
    return str(obj)

def safe_get(obj, *names):
    """
    Try to retrieve first existing value from 'names' from obj.
    If obj is a dict use dict lookup; otherwise use getattr.
    Returns None if none found.
    """
    if obj is None:
        return None
    for n in names:
        if isinstance(obj, dict):
            if n in obj:
                return obj[n]
        else:
            if hasattr(obj, n):
                return getattr(obj, n)
    return None

def get_member(obj, name):
    """
    Return obj[name] if obj is a dict; otherwise getattr(obj, name, None).
    """
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)

# ---------- storage helpers ----------
def store_challenge(user_id: str, challenge_b64u: str, ttl_seconds=120):
    expiry = int(time.time()) + ttl_seconds
    ch_table.put_item(Item={
        'user_id': user_id,
        'challenge': challenge_b64u,
        'expires_at': expiry
    })
    logger.debug("WEBAUTHN DEBUG: store_challenge user_id=%s expires_at=%d", user_id, expiry)

def get_and_delete_challenge(user_id: str):
    r = ch_table.get_item(Key={'user_id': user_id})
    item = r.get('Item')
    logger.debug("WEBAUTHN DEBUG: get_and_delete_challenge user_id=%s item=%s", user_id, bool(item))
    if not item:
        return None
    ch_table.delete_item(Key={'user_id': user_id})
    if item.get('expires_at', 0) < int(time.time()):
        logger.debug("WEBAUTHN DEBUG: challenge expired for user_id=%s", user_id)
        return None
    return item.get('challenge')

def store_state(user_id: str, state_obj, ttl_seconds=120):
    expiry = int(time.time()) + ttl_seconds
    try:
        pickled = pickle.dumps(state_obj)
        encoded = base64.b64encode(pickled).decode('ascii')
    except Exception:
        encoded = base64.b64encode(json.dumps(convert_to_json_safe(state_obj)).encode('utf-8')).decode('ascii')
    ch_table.put_item(Item={
        'user_id': user_id,
        'state': encoded,
        'expires_at': expiry
    })
    logger.debug("WEBAUTHN DEBUG: store_state user_id=%s encoded_len=%d", user_id, len(encoded))

def get_and_delete_state(user_id: str):
    r = ch_table.get_item(Key={'user_id': user_id})
    item = r.get('Item')
    logger.debug("WEBAUTHN DEBUG: get_and_delete_state user_id=%s item=%s", user_id, bool(item))
    if not item:
        return None
    ch_table.delete_item(Key={'user_id': user_id})
    if item.get('expires_at', 0) < int(time.time()):
        logger.debug("WEBAUTHN DEBUG: state expired for user_id=%s", user_id)
        return None
    enc = item.get('state')
    if not enc:
        return None
    try:
        pickled = base64.b64decode(enc)
        return pickle.loads(pickled)
    except Exception:
        try:
            return json.loads(base64.b64decode(enc).decode('utf-8'))
        except Exception:
            return None

# ---------- credential storage ----------
def _serialize_public_key_for_storage(public_key):
    """
    Accept bytes/dict/str; return base64-encoded string suitable for storing in Dynamo.
    If dict and COSEKey available we attempt conversion to bytes first.
    """
    try:
        if isinstance(public_key, (bytes, bytearray)):
            return base64.b64encode(bytes(public_key)).decode('ascii')
        if isinstance(public_key, dict):
            if COSEKey:
                try:
                    cose = COSEKey.from_dict(public_key)
                    if hasattr(cose, 'encode'):
                        pkb = cose.encode()
                    elif hasattr(cose, 'to_bytes'):
                        pkb = cose.to_bytes()
                    else:
                        pkb = None
                    if pkb:
                        return base64.b64encode(pkb).decode('ascii')
                except Exception:
                    pass
            # fallback to storing JSON bytes
            return base64.b64encode(json.dumps(convert_to_json_safe(public_key)).encode('utf-8')).decode('ascii')
        if isinstance(public_key, str):
            # assume already a base64 string OR JSON string; attempt to base64 decode (if works, keep)
            try:
                base64.b64decode(public_key)
                return public_key
            except Exception:
                return base64.b64encode(public_key.encode('utf-8')).decode('ascii')
        # fallback
        return base64.b64encode(str(public_key).encode('utf-8')).decode('ascii')
    except Exception:
        logger.exception("WEBAUTHN DEBUG: _serialize_public_key_for_storage failed")
        return ''

def store_credential(user_id: str, credential_id: str, public_key_cose: bytes, sign_count: int, extra=None):
    stored_pk = _serialize_public_key_for_storage(public_key_cose)
    item = {
        'user_id': user_id,
        'credential_id': credential_id,
        'public_key_cose': stored_pk,
        'sign_count': int(sign_count),
        'status': 'active',
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    if extra and isinstance(extra, dict):
        item.update(extra)
    creds_table.put_item(Item=item)
    logger.debug("WEBAUTHN DEBUG: store_credential user_id=%s credential_id=%s pk_len=%d", user_id, credential_id, len(stored_pk))

def get_credentials_for_user(user_id: str):
    try:
        logger.debug("WEBAUTHN DEBUG: Querying creds table for user_id=%s", user_id)
        resp = creds_table.query(KeyConditionExpression=Key('user_id').eq(user_id))
        items = resp.get('Items', [])
        logger.debug("WEBAUTHN DEBUG: Dynamo returned %d items for user_id=%s", len(items), user_id)
        return items
    except Exception:
        logger.exception("WEBAUTHN DEBUG: Error querying DynDB")
        return []

def has_webauthn_credentials(user_id: str) -> bool:
    try:
        items = get_credentials_for_user(user_id)
        for it in items:
            if it.get('status', 'active') == 'active':
                return True
        return False
    except Exception:
        logger.exception("WEBAUTHN DEBUG: Error in has_webauthn_credentials")
        return True  # conservative

# ---------- endpoints ----------
@csrf_exempt
def has_credentials(request):
    logger.debug("/has_credentials hit")
    if request.method != "POST":
        return HttpResponseBadRequest("POST only")
    try:
        body = json.loads(request.body or "{}")
    except Exception:
        return JsonResponse({"error": "invalid json"}, status=400)
    user_id = body.get("user_id") or body.get("email") or body.get("username")
    if not user_id:
        return JsonResponse({"error": "user_id required"}, status=400)
    exists = has_webauthn_credentials(user_id)
    return JsonResponse({"has_credentials": bool(exists)})

@csrf_exempt
def password_login_view(request):
    if request.method != "POST":
        return HttpResponseBadRequest("POST only")
    try:
        body = json.loads(request.body or "{}")
    except Exception:
        return JsonResponse({"error": "invalid json"}, status=400)
    username = body.get("username")
    password = body.get("password")
    if not username or not password:
        return JsonResponse({"ok": False, "error": "missing username/password"}, status=400)
    if has_webauthn_credentials(username):
        return JsonResponse({"ok": False, "error": "passkey_required"}, status=403)
    try:
        user = django_authenticate(username=username, password=password)
        if user is None:
            return JsonResponse({"ok": False, "error": "invalid_credentials"}, status=401)
        django_login(request, user)
        return JsonResponse({"ok": True, "username": username})
    except Exception:
        logger.exception("password_login_view: internal error")
        return JsonResponse({"ok": False, "error": "internal_error"}, status=500)

@csrf_exempt
def register_options(request):
    logger.debug("/register/options hit")
    if request.method != "POST":
        return HttpResponseBadRequest("POST only")
    try:
        body = json.loads(request.body or "{}")
    except Exception:
        return JsonResponse({"error": "invalid json"}, status=400)
    user_id = body.get("user_id") or body.get("email") or body.get("username")
    display_name = body.get("displayName") or user_id
    if not user_id:
        return JsonResponse({"error": "user_id required"}, status=400)
    user_bytes = user_id.encode('utf-8')
    if PublicKeyCredentialUserEntity:
        user = PublicKeyCredentialUserEntity(id=user_bytes, name=user_id, display_name=display_name)
    else:
        user = {'id': user_bytes, 'name': user_id, 'displayName': display_name}
    existing = get_credentials_for_user(user_id)
    exclude_list = []
    for it in existing:
        try:
            cred_b = base64.b64decode(it['credential_id'])
            exclude_list.append({'type': 'public-key', 'id': cred_b})
        except Exception:
            continue
    try:
        registration_data, state = server.register_begin(user, credentials=exclude_list)
    except Exception as e:
        logger.exception("register_begin failed")
        return JsonResponse({"error": f"register_begin failed: {e}"}, status=500)
    # challenge -> bytes
    challenge = state.get("challenge")
    if isinstance(challenge, str):
        try:
            challenge_bytes = websafe_decode(challenge)
        except Exception:
            challenge_bytes = challenge.encode('utf-8')
    elif isinstance(challenge, (bytes, bytearray, memoryview)):
        challenge_bytes = bytes(challenge)
    else:
        challenge_bytes = str(challenge).encode('utf-8')
    challenge_b64u = b64u(challenge_bytes)
    expiry = int(time.time()) + 120
    try:
        try:
            pickled = pickle.dumps(state)
            state_enc = base64.b64encode(pickled).decode('ascii')
            item_state = {'state': state_enc}
        except Exception:
            item_state = {'state': base64.b64encode(json.dumps(convert_to_json_safe(state)).encode('utf-8')).decode('ascii')}
        item = {'user_id': user_id, 'challenge': challenge_b64u, 'expires_at': expiry}
        item.update(item_state)
        ch_table.put_item(Item=item)
    except Exception:
        logger.exception("Failed to store challenge+state")
    reg_json = convert_to_json_safe(registration_data)
    out = reg_json.get('publicKey') if isinstance(reg_json, dict) and 'publicKey' in reg_json else reg_json or {}
    out['challenge'] = b64u(challenge_bytes)
    out.setdefault('user', {'id': b64u(user_bytes), 'name': user_id, 'displayName': display_name})
    out.setdefault('pubKeyCredParams', [{'type': 'public-key', 'alg': -7}, {'type': 'public-key', 'alg': -257}])
    out.setdefault('rp', {'name': RP_NAME, 'id': RP_ID})
    out.setdefault('attestation', 'none')
    return JsonResponse(out)

@csrf_exempt
def register_verify(request):
    logger.debug("/register/verify hit")
    if request.method != "POST":
        return HttpResponseBadRequest("POST only")
    try:
        body = json.loads(request.body or "{}")
    except Exception:
        return JsonResponse({"ok": False, "error": "invalid json"}, status=400)

    user_id = body.get("user_id") or body.get("email") or body.get("username")
    if not user_id:
        return JsonResponse({"ok": False, "error": "missing user_id"}, status=400)

    raw_id_b64 = body.get("rawId")
    attestation_b64 = body.get("response", {}).get("attestationObject")
    clientdata_b64 = body.get("response", {}).get("clientDataJSON")
    if not raw_id_b64 or not attestation_b64 or not clientdata_b64:
        return JsonResponse({"ok": False, "error": "missing fields"}, status=400)

    try:
        attestation_bytes = b64u_to_bytes(attestation_b64)
        clientdata_bytes = b64u_to_bytes(clientdata_b64)
    except Exception as e:
        logger.exception("register_verify: bad base64")
        return JsonResponse({"ok": False, "error": f"bad base64 payload: {e}"}, status=400)

    state_obj = get_and_delete_state(user_id)
    if not state_obj:
        challenge_b64u = get_and_delete_challenge(user_id)
        if not challenge_b64u:
            return JsonResponse({"ok": False, "error": "challenge missing or expired"}, status=400)
        state_obj = {'challenge': b64u_to_bytes(challenge_b64u)}

    # Build client_data_obj (shim if necessary)
    client_data_obj = None
    if CollectedClientData:
        try:
            client_data_obj = CollectedClientData(clientdata_bytes)
        except Exception:
            try:
                client_data_obj = CollectedClientData(clientdata_bytes.decode('utf-8'))
            except Exception:
                client_data_obj = None
    if client_data_obj is None:
        try:
            cd = json.loads(clientdata_bytes.decode('utf-8'))
            class _ShimClientData:
                def __init__(self, d):
                    self.type = d.get('type')
                    self.challenge = d.get('challenge')
                    self.origin = d.get('origin')
                    self.tokenBinding = d.get('tokenBinding', None)
            client_data_obj = _ShimClientData(cd)
        except Exception as e:
            logger.exception("register_verify: failed to parse clientDataJSON")
            return JsonResponse({"ok": False, "error": f"failed to parse clientDataJSON: {e}"}, status=400)

    # Attestation object handling
    att_obj_for_server = None
    if AttestationObject:
        try:
            att_obj_for_server = AttestationObject(attestation_bytes)
        except Exception:
            att_obj_for_server = None
    if att_obj_for_server is None:
        att_obj_for_server = attestation_bytes

    # Call server.register_complete defensively
    try:
        auth_data = server.register_complete(state=state_obj, client_data=client_data_obj, attestation_object=att_obj_for_server)
    except Exception as e:
        logger.exception("register_complete failed")
        diag = {'state_type': str(type(state_obj)), 'client_data_type': str(type(client_data_obj)), 'attestation_type': str(type(att_obj_for_server))}
        return JsonResponse({"ok": False, "error": str(e), "diag": diag}, status=400)

    # extract credential information robustly with defensive access and debug logs
    try:
        logger.debug("WEBAUTHN DEBUG: register_verify: auth_data type=%s", type(auth_data))
        try:
            logger.debug("WEBAUTHN DEBUG: register_verify: auth_data repr=%s", repr(auth_data)[:1000])
        except Exception:
            logger.debug("WEBAUTHN DEBUG: register_verify: auth_data repr unrepresentable")

        # cred may be nested in many possible fields
        cred = safe_get(auth_data, 'credential_data', 'credential') or safe_get(auth_data, 'attested_credential_data') or auth_data

        # Try many names for credential id and public key
        credential_id_bytes = safe_get(cred, 'credential_id', 'id', 'rawId', 'credentialId')
        public_key_cose = safe_get(cred, 'public_key', 'credential_public_key', 'publicKey', 'public_key_cose')

        # sign count could be on auth_data or nested
        sign_count = safe_get(auth_data, 'sign_count', 'counter') or safe_get(get_member(auth_data, 'auth_data'), 'sign_count', 'counter') or safe_get(cred, 'sign_count') or 0

        # normalize credential id -> base64url
        credential_id_b64u = None
        if isinstance(credential_id_bytes, (bytes, bytearray)):
            credential_id_b64u = b64u(bytes(credential_id_bytes))
        elif isinstance(credential_id_bytes, str):
            try:
                tmp = b64u_to_bytes(credential_id_bytes)
                credential_id_b64u = b64u(tmp)
            except Exception:
                credential_id_b64u = b64u(credential_id_bytes.encode('utf-8'))

        # normalize public key into bytes where possible
        pk_bytes = None
        if isinstance(public_key_cose, (bytes, bytearray)):
            pk_bytes = bytes(public_key_cose)
        elif isinstance(public_key_cose, dict):
            if COSEKey:
                try:
                    cose = COSEKey.from_dict(public_key_cose)
                    if hasattr(cose, 'encode'):
                        pk_bytes = cose.encode()
                    elif hasattr(cose, 'to_bytes'):
                        pk_bytes = cose.to_bytes()
                except Exception:
                    pk_bytes = None
            if pk_bytes is None and cbor:
                try:
                    pk_bytes = cbor.dumps(public_key_cose)
                except Exception:
                    pk_bytes = None
            if pk_bytes is None:
                pk_bytes = json.dumps(convert_to_json_safe(public_key_cose)).encode('utf-8')
        elif isinstance(public_key_cose, str):
            try:
                pk_bytes = base64.b64decode(public_key_cose)
            except Exception:
                pk_bytes = public_key_cose.encode('utf-8')
        else:
            try:
                pk_bytes = bytes(public_key_cose)
            except Exception:
                pk_bytes = None

        if not credential_id_b64u or pk_bytes is None:
            raise ValueError("could not extract credential_id or public_key")
    except Exception as e:
        logger.exception("Failed to extract credential info during register_verify")
        try:
            auth_repr = repr(auth_data)[:1000]
        except Exception:
            auth_repr = '<unrepresentable>'
        diag = {'error': str(e), 'auth_data_type': str(type(auth_data)), 'auth_data_repr': auth_repr}
        return JsonResponse({"ok": False, "error": f"failed to extract credential: {e}", "diag": diag}, status=500)

    # store credential
    try:
        store_credential(user_id, credential_id_b64u, pk_bytes, int(sign_count or 0), extra={
            'attestation_format': safe_get(auth_data, 'fmt') or 'unknown',
            'attestation_object_b64': base64.b64encode(attestation_bytes).decode('ascii'),
            'client_data_b64': base64.b64encode(clientdata_bytes).decode('ascii')
        })
    except Exception as e:
        logger.exception("Failed to store credential")
        return JsonResponse({"ok": False, "error": f"Failed to store credential: {e}"}, status=500)

    return JsonResponse({"ok": True, "credential_id": credential_id_b64u})

@csrf_exempt
def authenticate_options(request):
    logger.debug("/authenticate/options hit")
    if request.method != 'POST':
        return HttpResponseBadRequest('POST only')
    try:
        body = json.loads(request.body or '{}')
    except Exception:
        return JsonResponse({'error': 'invalid json'}, status=400)
    user_id = body.get('user_id') or body.get('email') or body.get('username')
    if not user_id:
        return JsonResponse({'error': 'user_id required'}, status=400)
    creds = get_credentials_for_user(user_id)
    allow = []
    for c in creds:
        try:
            cid = base64.b64decode(c['credential_id'])
            allow.append({'type': 'public-key', 'id': cid})
        except Exception:
            continue
    try:
        options, state = server.authenticate_begin(allow)
    except Exception as e:
        logger.exception("authenticate_begin failed")
        return JsonResponse({'error': f'authenticate_begin failed: {e}'}, status=500)
    try:
        store_state(user_id, state, ttl_seconds=120)
    except Exception:
        logger.exception("store_state failed for authenticate")
    opts_json = convert_to_json_safe(options)
    out = opts_json.get('publicKey') if isinstance(opts_json, dict) and 'publicKey' in opts_json else opts_json or {}
    if 'challenge' in out and isinstance(out['challenge'], (bytes, bytearray)):
        out['challenge'] = b64u(bytes(out['challenge']))
    if 'allowCredentials' in out and isinstance(out['allowCredentials'], list):
        new_allow = []
        for ac in out['allowCredentials']:
            ac_copy = dict(ac)
            if isinstance(ac_copy.get('id'), (bytes, bytearray)):
                ac_copy['id'] = b64u(bytes(ac_copy['id']))
            new_allow.append(ac_copy)
        out['allowCredentials'] = new_allow
    return JsonResponse(out)

@csrf_exempt
def authenticate_verify(request):
    """
    POST { user_id, id, rawId, type, response: { clientDataJSON, authenticatorData, signature } }
    """
    logger.debug("/authenticate/verify hit")
    if request.method != 'POST':
        return HttpResponseBadRequest('POST only')
    try:
        body = json.loads(request.body or '{}')
    except Exception:
        logger.exception("authenticate_verify: invalid json")
        return JsonResponse({'ok': False, 'error': 'invalid json'}, status=400)

    user_id = body.get('user_id') or body.get('username')
    if not user_id:
        return JsonResponse({'ok': False, 'error': 'missing user_id'}, status=400)

    raw_id_b64 = body.get('rawId')
    clientdata_b64 = body.get('response', {}).get('clientDataJSON')
    authdata_b64 = body.get('response', {}).get('authenticatorData')
    signature_b64 = body.get('response', {}).get('signature')
    if not raw_id_b64 or not clientdata_b64 or not authdata_b64 or not signature_b64:
        return JsonResponse({'ok': False, 'error': 'missing fields'}, status=400)

    try:
        clientdata_bytes = b64u_to_bytes(clientdata_b64)
        authdata_bytes = b64u_to_bytes(authdata_b64)
        signature_bytes = b64u_to_bytes(signature_b64)
        cred_id_bytes = b64u_to_bytes(raw_id_b64)
    except Exception as e:
        logger.exception("authenticate_verify: bad base64 payload")
        return JsonResponse({'ok': False, 'error': f'bad base64 payload: {e}'}, status=400)

    state_obj = get_and_delete_state(user_id)
    if not state_obj:
        return JsonResponse({'ok': False, 'error': 'challenge missing or expired'}, status=400)

    # parse clientDataJSON (shim if necessary)
    client_data_obj = None
    if CollectedClientData:
        try:
            client_data_obj = CollectedClientData(clientdata_bytes)
        except Exception:
            client_data_obj = None
    if client_data_obj is None:
        try:
            cd = json.loads(clientdata_bytes.decode('utf-8'))
            class _ShimClientData:
                def __init__(self, d):
                    self.type = d.get('type')
                    self.challenge = d.get('challenge')
                    self.origin = d.get('origin')
                    self.tokenBinding = d.get('tokenBinding', None)
            client_data_obj = _ShimClientData(cd)
        except Exception:
            return JsonResponse({'ok': False, 'error': 'failed to parse clientDataJSON'}, status=400)

    # Build AuthenticatorData for server if possible
    authdata_for_server = None
    if AuthenticatorData:
        try:
            authdata_for_server = AuthenticatorData(authdata_bytes)
        except Exception:
            authdata_for_server = None
    if authdata_for_server is None:
        authdata_for_server = authdata_bytes

    # ---------------------------------------------------------
    # REPLACED: robust public key reconstruction (your provided block)
    # ---------------------------------------------------------
    try:
        stored = get_credentials_for_user(user_id)
        logger.debug("authenticate_verify: found %d stored credentials for user %s", len(stored), user_id)
        creds_for_server = []
        skipped_credentials = []
        
        for row in stored:
            logger.debug("authenticate_verify: processing row with cred_id=%s, has pk=%s", 
                        row.get('credential_id'), bool(row.get('public_key_cose') or row.get('public_key')))
            
            # 1) Decode stored credential id
            cid = None
            try:
                cid = b64u_to_bytes(row.get('credential_id'))
            except Exception:
                try:
                    cid = base64.b64decode(row.get('credential_id'))
                except Exception:
                    logger.warning("Skipping stored credential with bad id: %s", row.get('credential_id'))
                    skipped_credentials.append({'reason': 'bad_id', 'row': row})
                    continue

            # 2) Reconstruct public key from stored base64
            pk = None
            stored_pk_b64 = row.get('public_key_cose') or row.get('public_key')
            
            if not stored_pk_b64:
                logger.warning("Skipping credential: no stored public key for user=%s cred=%s", 
                              user_id, row.get('credential_id'))
                skipped_credentials.append({'reason': 'no_pk_b64', 'cred_id': row.get('credential_id')})
                continue
            
            logger.debug("authenticate_verify: stored_pk_b64 type=%s, len=%d", 
                        type(stored_pk_b64).__name__, len(str(stored_pk_b64)))
            
            # THE KEY FIX: Always base64 decode first
            try:
                pk_bytes = base64.b64decode(stored_pk_b64)
                logger.debug("authenticate_verify: base64 decoded to %d bytes", len(pk_bytes))
            except Exception as e:
                logger.warning("Failed to base64 decode stored_pk_b64: %s", e)
                # Fallback: maybe it's raw bytes already (shouldn't happen with b64 storage)
                try:
                    pk_bytes = stored_pk_b64.encode('utf-8') if isinstance(stored_pk_b64, str) else stored_pk_b64
                except Exception:
                    logger.warning("Skipping credential: cannot decode public key for user=%s cred=%s", 
                                  user_id, row.get('credential_id'))
                    skipped_credentials.append({'reason': 'pk_decode_failed', 'cred_id': row.get('credential_id')})
                    continue
            
            # Check if decoded bytes are JSON (starts with { or [)
            usable_public = None
            if pk_bytes and len(pk_bytes) > 0 and pk_bytes[0] in (0x7b, 0x5b):  # '{' or '['
                logger.debug("authenticate_verify: decoded bytes look like JSON, attempting to parse")
                try:
                    cose_dict = json.loads(pk_bytes.decode('utf-8'))
                    logger.debug("authenticate_verify: parsed JSON COSE dict with keys: %s", list(cose_dict.keys()))
                    
                    # Try to convert dict back to COSE bytes
                    if COSEKey:
                        try:
                            cose_obj = COSEKey.from_dict(cose_dict)
                            if hasattr(cose_obj, 'encode'):
                                usable_public = cose_obj.encode()
                            elif hasattr(cose_obj, 'to_bytes'):
                                usable_public = cose_obj.to_bytes()
                            logger.debug("authenticate_verify: COSEKey converted dict to %d bytes", len(usable_public))
                        except Exception as e:
                            logger.warning("COSEKey.from_dict failed: %s", e)
                            usable_public = None
                    
                    # Fallback: CBOR encode the dict
                    if usable_public is None and cbor:
                        try:
                            usable_public = cbor.dumps(cose_dict)
                            logger.debug("authenticate_verify: cbor re-encoded dict to %d bytes", len(usable_public))
                        except Exception as e:
                            logger.warning("CBOR re-encoding failed: %s", e)
                            usable_public = None
                    
                    # Last resort: keep as JSON bytes (may not work)
                    if usable_public is None:
                        logger.warning("Could not convert JSON COSE dict to bytes; will attempt with JSON bytes")
                        usable_public = pk_bytes
                except Exception as e:
                    logger.warning("Failed to parse JSON from decoded bytes: %s", e)
                    # Not JSON; treat as raw COSE bytes
                    usable_public = pk_bytes
            else:
                # Raw COSE/CBOR bytes
                logger.debug("authenticate_verify: decoded bytes appear to be raw COSE/CBOR")
                usable_public = pk_bytes
            
            # Verify we have usable public key
            if not usable_public:
                logger.warning("Skipping credential: no usable public key for user=%s cred=%s", 
                              user_id, row.get('credential_id'))
                skipped_credentials.append({'reason': 'no_usable_pk', 'cred_id': row.get('credential_id')})
                continue
            
            logger.debug("authenticate_verify: credential public_key type=%s, len=%d", 
                        type(usable_public).__name__, 
                        len(usable_public) if isinstance(usable_public, (bytes, bytearray)) else 'N/A')
            
            # CRITICAL: fido2.server.authenticate_complete() will deserialize COSE bytes itself
            # Do NOT pass COSEKey objects or cryptography key objects — pass raw COSE bytes
            # fido2 library will call cbor.loads() on the bytes and use the resulting dict
            if not isinstance(usable_public, (bytes, bytearray)):
                logger.error("usable_public is not bytes (type=%s); cannot use for fido2", type(usable_public).__name__)
                skipped_credentials.append({'reason': 'not_bytes', 'cred_id': row.get('credential_id')})
                continue
            
            # Create credential object for fido2 with COSEKey object
            # fido2.server.authenticate_complete expects an object with a .verify() method (like COSEKey)
            try:
                if COSEKey:
                    # COSEKey.parse expects a dictionary (decoded CBOR), not bytes
                    if isinstance(usable_public, (bytes, bytearray)):
                        if cbor:
                            try:
                                key_dict = cbor.loads(usable_public)
                                public_key_obj = COSEKey.parse(key_dict)
                            except Exception as e:
                                logger.warning("Failed to decode CBOR bytes for COSEKey: %s", e)
                                # Try parsing bytes directly if library supports it (unlikely for standard fido2)
                                try:
                                    public_key_obj = COSEKey.parse(usable_public)
                                except Exception:
                                    raise e
                        else:
                            logger.error("CBOR library not available to decode public key bytes")
                            skipped_credentials.append({'reason': 'cbor_missing', 'cred_id': row.get('credential_id')})
                            continue
                    else:
                        # Already a dict?
                        public_key_obj = COSEKey.parse(usable_public)
                else:
                    # Should not happen if fido2 is installed correctly
                    logger.error("COSEKey class not available")
                    skipped_credentials.append({'reason': 'COSEKey_missing', 'cred_id': row.get('credential_id')})
                    continue
            except Exception as e:
                logger.warning("Failed to parse public key into COSEKey: %s", e)
                skipped_credentials.append({'reason': 'pk_parse_failed', 'cred_id': row.get('credential_id')})
                continue

            cred_obj = SimpleNamespace(
                credential_id=cid,
                id=cid,
                public_key=public_key_obj,
                sign_count=int(row.get('sign_count', 0) or 0)
            )
            creds_for_server.append(cred_obj)
            logger.debug("authenticate_verify: added credential with COSEKey object to server list")
        
        # If no usable credentials
        if not creds_for_server:
            logger.warning("No usable stored credentials for user %s; skipped=%d", user_id, len(skipped_credentials))
            diag = {
                'skipped_count': len(skipped_credentials), 
                'skipped_reasons': [s['reason'] for s in skipped_credentials][:10]
            }
            return JsonResponse({
                'ok': False, 
                'error': 'no usable stored public key for authentication; re-register authenticator', 
                'diag': diag
            }, status=400)
        
        # Call authenticate_complete
        logger.debug("authenticate_verify: calling authenticate_complete with %d credentials", len(creds_for_server))
        auth_data = server.authenticate_complete(state_obj, creds_for_server, cred_id_bytes, 
                                                client_data_obj, authdata_for_server, signature_bytes)

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        logger.error("authenticate_complete exception: %s\n%s", e, tb)
        msg = str(e)
        if 'Signature verification' in msg or 'could not be converted' in msg or 'verify' in msg:
            return JsonResponse({
                'ok': False, 
                'error': 'Signature verification failed / no usable public key; re-register this authenticator.'
            }, status=400)
        return JsonResponse({
            'ok': False, 
            'error': str(e), 
            'diag': {'traceback': tb[:3000]}
        }, status=400)

    # extract credential id & sign_count (robust)
    try:
        logger.debug("WEBAUTHN DEBUG: authenticate_verify: auth_data type=%s", type(auth_data))
        try:
            logger.debug("WEBAUTHN DEBUG: authenticate_verify: auth_data repr=%s", repr(auth_data)[:1000])
        except Exception:
            logger.debug("WEBAUTHN DEBUG: authenticate_verify: auth_data repr unrepresentable")

        cred = safe_get(auth_data, 'credential', 'credential_data', 'auth_data') or auth_data

        sign_count = safe_get(auth_data, 'sign_count', 'counter') or safe_get(get_member(auth_data, 'auth_data'), 'sign_count', 'counter') or safe_get(cred, 'sign_count') or 0

        credential_id_bytes = safe_get(cred, 'credential_id', 'id', 'rawId', 'credentialId')
        if isinstance(credential_id_bytes, (bytes, bytearray)):
            credential_id_b = bytes(credential_id_bytes)
        elif isinstance(credential_id_bytes, str):
            try:
                credential_id_b = b64u_to_bytes(credential_id_bytes)
            except Exception:
                credential_id_b = credential_id_bytes.encode('utf-8')
        else:
            credential_id_b = None

        public_key_cose = safe_get(cred, 'public_key', 'credential_public_key', 'publicKey', 'public_key_cose')

        pk_bytes = None
        if isinstance(public_key_cose, (bytes, bytearray)):
            pk_bytes = bytes(public_key_cose)
        elif isinstance(public_key_cose, dict) and COSEKey:
            try:
                cose = COSEKey.from_dict(public_key_cose)
                if hasattr(cose, 'encode'):
                    pk_bytes = cose.encode()
                elif hasattr(cose, 'to_bytes'):
                    pk_bytes = cose.to_bytes()
            except Exception:
                pk_bytes = None
        elif isinstance(public_key_cose, str):
            try:
                pk_bytes = base64.b64decode(public_key_cose)
            except Exception:
                pk_bytes = public_key_cose.encode('utf-8')
        else:
            try:
                pk_bytes = bytes(public_key_cose)
            except Exception:
                pk_bytes = None

        if credential_id_b is None:
            raise ValueError("could not determine credential id from auth_data")

        cred_id_b64u = b64u(credential_id_b)
        sign_count = int(sign_count or 0)
    except Exception as e:
        logger.exception("failed to extract credential from auth_data")
        return JsonResponse({'ok': False, 'error': f'failed to extract credential: {e}'}, status=500)

    # ensure this credential belongs to user
    stored_items = get_credentials_for_user(user_id)
    matched = None
    for it in stored_items:
        if it.get('credential_id') == cred_id_b64u:
            matched = it
            break
    if not matched:
        return JsonResponse({'ok': False, 'error': 'credential not registered for this user'}, status=403)

    # verify stored public key present (basic)
    stored_pk_b64 = matched.get('public_key_cose') or matched.get('public_key')
    try:
        stored_pk_bytes = base64.b64decode(stored_pk_b64) if stored_pk_b64 else None
    except Exception:
        stored_pk_bytes = None
    if not stored_pk_bytes:
        return JsonResponse({'ok': False, 'error': 'no usable public key for this credential; re-register'}, status=500)

    # update sign_count
    try:
        for it in stored_items:
            if it.get('credential_id') == cred_id_b64u:
                creds_table.update_item(Key={'user_id': user_id, 'credential_id': it['credential_id']},
                                       UpdateExpression='SET sign_count = :sc',
                                       ExpressionAttributeValues={':sc': int(sign_count)})
                break
    except Exception:
        logger.exception("Failed to update sign_count")

    # login user
    try:
        # user_id from client is typically email; look up by email first, then username
        user = UserProfile.objects.filter(email=user_id).first()
        if not user:
            user = UserProfile.objects.filter(username=user_id).first()
        if user:
            django_login(request, user)
            logger.debug("WEBAUTHN DEBUG: User logged in after authenticate: %s", user_id)
        else:
            logger.error("WEBAUTHN DEBUG: No user found for authenticate after verify (email or username): %s", user_id)
    except Exception:
        logger.exception("Failed to login user after WebAuthn authenticate")

    return JsonResponse({'ok': True, 'credential_id': cred_id_b64u})

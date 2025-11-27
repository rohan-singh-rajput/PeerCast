# peercast/webauthn.py
"""
WebAuthn registration endpoints (server side) for PeerCast.
Supports register_options and register_verify with robust handling
for differences across python-fido2 versions.
"""
import os
import json
import time
import base64
import pickle
import logging
from datetime import datetime, timezone

from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login as django_login, authenticate as django_authenticate
from core.models import UserProfile

import boto3
from boto3.dynamodb.conditions import Key

# fido2 imports
from fido2.server import Fido2Server
from fido2.utils import websafe_encode, websafe_decode
# try safe imports for entities
try:
    from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
except Exception:
    # older/newer package layouts - try alternate import
    from fido2.webauthn import PublicKeyCredentialRpEntity
    # create a lightweight user entity fallback if missing
    PublicKeyCredentialUserEntity = None

# CollectedClientData used later
try:
    from fido2.client import CollectedClientData
except Exception:
    CollectedClientData = None

# AttestationObject class may be in different modules
AttestationObject = None
for mod in ("fido2.ctap2", "fido2.attestation", "fido2.webauthn"):
    try:
        m = __import__(mod, fromlist=['AttestationObject'])
        AttestationObject = getattr(m, 'AttestationObject', None)
        if AttestationObject:
            break
    except Exception:
        continue

logger = logging.getLogger(__name__)

# ---------- config from environment ----------
RP_ID = os.environ.get("RP_ID", "localhost")
RP_NAME = os.environ.get("RP_NAME", "PeerCast")
ORIGIN = os.environ.get("ORIGIN", f"http://{RP_ID}")  # http for local dev

DYNAMO_TABLE_CREDS = os.environ.get("WEBAUTHN_CREDS_TABLE", "webauthn_credentials")
DYNAMO_TABLE_CHALLENGES = os.environ.get("WEBAUTHN_CHALLENGES_TABLE", "webauthn_challenges")

AWS_REGION = os.environ.get("REGION_AWS")
AWS_ACCESS_KEY = os.environ.get("ACCESS_KEY_AWS")
AWS_SECRET_KEY = os.environ.get("SECRET_KEY_AWS")

# ---------- initialize AWS resources ----------
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
    # convert bytes -> base64url; fallback to str()
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return b64u(bytes(obj))
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, dict):
        return {k: convert_to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [convert_to_json_safe(i) for i in obj]
    # dataclass / object fallback
    if hasattr(obj, '__dict__'):
        return convert_to_json_safe(obj.__dict__)
    return str(obj)

# ---------- challenge & state storage ----------
def store_challenge(user_id: str, challenge_b64u: str, ttl_seconds=120):
    expiry = int(time.time()) + ttl_seconds
    ch_table.put_item(Item={
        'user_id': user_id,
        'challenge': challenge_b64u,
        'expires_at': expiry
    })

def get_and_delete_challenge(user_id: str):
    r = ch_table.get_item(Key={'user_id': user_id})
    item = r.get('Item')
    if not item:
        return None
    ch_table.delete_item(Key={'user_id': user_id})
    # validate TTL (optional)
    if item.get('expires_at', 0) < int(time.time()):
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

def get_and_delete_state(user_id: str):
    r = ch_table.get_item(Key={'user_id': user_id})
    item = r.get('Item')
    if not item:
        return None
    ch_table.delete_item(Key={'user_id': user_id})
    if item.get('expires_at', 0) < int(time.time()):
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
def store_credential(user_id: str, credential_id: str, public_key_cose: bytes, sign_count: int, extra=None):
    item = {
        'user_id': user_id,
        'credential_id': credential_id,
        'public_key_cose': base64.b64encode(public_key_cose).decode('ascii'),
        'sign_count': int(sign_count),
        'status': 'active',
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    if extra and isinstance(extra, dict):
        item.update(extra)
    creds_table.put_item(Item=item)

def get_credentials_for_user(user_id: str):
    try:
        resp = creds_table.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
        )
        return resp.get('Items', [])
    except Exception:
        return []

# ---------- passkey-check helper + endpoints ----------
def has_webauthn_credentials(user_id: str) -> bool:
    """
    Return True if the user has at least one active WebAuthn credential.
    Conservative fallback: on Dynamo errors return True to avoid weakening security.
    """
    try:
        items = get_credentials_for_user(user_id)
        for it in items:
            if it.get('status', 'active') == 'active':
                return True
        return False
    except Exception as e:
        logger.exception("DynamoDB error when checking credentials for %s: %s", user_id, e)
        # Conservative: treat as having credentials (avoids bypassing passkey protection)
        return True

@csrf_exempt
def has_credentials(request):
    """
    POST { user_id } -> { has_credentials: true/false }
    Used by the frontend to decide whether to show password box or prompt for passkey.
    """
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
    """
    POST { username, password }
    Enforces strict policy: if user has any registered WebAuthn credentials, deny password login.
    Otherwise authenticate via Django's authenticate() and create session.
    """
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

    # Deny password login for passkey-enabled accounts
    if has_webauthn_credentials(username):
        logger.info("Password login blocked for passkey-enabled account %s", username)
        return JsonResponse({"ok": False, "error": "passkey_required"}, status=403)

    # Otherwise proceed with Django authentication (replace if you use custom auth)
    try:
        user = django_authenticate(username=username, password=password)
        if user is None:
            return JsonResponse({"ok": False, "error": "invalid_credentials"}, status=401)
        # log the user in and create session
        django_login(request, user)
        return JsonResponse({"ok": True, "username": username})
    except Exception as e:
        logger.exception("Error during password login for user %s: %s", username, e)
        return JsonResponse({"ok": False, "error": "internal_error"}, status=500)

# ========== endpoints ==========
@csrf_exempt
def register_options(request):
    """
    POST { user_id, username, displayName (optional) }
    returns the publicKey creation options (JSON-safe)
    """
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

    # create user entity - use fido2's class if available, otherwise pass minimal data
    user_bytes = user_id.encode('utf-8')
    if PublicKeyCredentialUserEntity:
        user = PublicKeyCredentialUserEntity(id=user_bytes, name=user_id, display_name=display_name)
    else:
        user = {'id': user_bytes, 'name': user_id, 'displayName': display_name}

    # prepare excludeCredentials from existing creds
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

    # challenge handling
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

    # Persist both the full state and the challenge in a single item write so one
    # does not overwrite the other (DynamoDB put_item replaces the whole item).
    expiry = int(time.time()) + 120
    try:
        # try to pickle the state for full fidelity
        try:
            pickled = pickle.dumps(state)
            state_enc = base64.b64encode(pickled).decode('ascii')
            item_state = {'state': state_enc}
        except Exception:
            # fallback to JSON-safe encoding
            item_state = {'state': base64.b64encode(json.dumps(convert_to_json_safe(state)).encode('utf-8')).decode('ascii')}

        item = {
            'user_id': user_id,
            'challenge': challenge_b64u,
            'expires_at': expiry
        }
        item.update(item_state)
        ch_table.put_item(Item=item)
    except Exception:
        logger.exception("Failed to store challenge+state in one item")

    # convert registration_data (may be dict/object) into JSON-safe dict
    reg_json = convert_to_json_safe(registration_data)
    # registration_data generally contains 'publicKey'
    if isinstance(reg_json, dict) and 'publicKey' in reg_json:
        out = reg_json['publicKey']
    else:
        out = reg_json or {}

    # ensure challenge and user.id are present as base64url strings
    out['challenge'] = b64u(challenge_bytes)
    if 'user' not in out or not isinstance(out['user'], dict):
        out['user'] = {'id': b64u(user_bytes), 'name': user_id, 'displayName': display_name}

    # defaults for required fields
    out.setdefault('pubKeyCredParams', [
        {'type': 'public-key', 'alg': -7},
        {'type': 'public-key', 'alg': -257}
    ])
    out.setdefault('rp', {'name': RP_NAME, 'id': RP_ID})
    out.setdefault('attestation', 'none')

    return JsonResponse(out)


@csrf_exempt
def register_verify(request):
    """
    POST { user_id, id, rawId, type, response: { clientDataJSON, attestationObject } }
    verifies attestation and stores credential
    """
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

    # decode
    try:
        attestation_bytes = b64u_to_bytes(attestation_b64)
        clientdata_bytes = b64u_to_bytes(clientdata_b64)
    except Exception as e:
        return JsonResponse({"ok": False, "error": f"bad base64 payload: {e}"}, status=400)

    # reconstruct saved state (prefer full state)
    state_obj = get_and_delete_state(user_id)
    if not state_obj:
        challenge_b64u = get_and_delete_challenge(user_id)
        if not challenge_b64u:
            return JsonResponse({"ok": False, "error": "challenge missing or expired"}, status=400)
        state_obj = {'challenge': b64u_to_bytes(challenge_b64u)}

    # build CollectedClientData if available (fido2 expects this type)
    client_data_obj = None
    if CollectedClientData:
        try:
            client_data_obj = CollectedClientData(clientdata_bytes)
        except Exception:
            # try decode as utf-8 string then parse
            try:
                client_data_obj = CollectedClientData(clientdata_bytes.decode('utf-8'))
            except Exception:
                client_data_obj = None

    # if CollectedClientData not available or failed, create a minimal shim
    if not client_data_obj:
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
            return JsonResponse({"ok": False, "error": f"failed to parse clientDataJSON: {e}"}, status=400)

    # build attestation object if library provides the class, else pass raw bytes
    att_obj_for_server = None
    if AttestationObject:
        try:
            att_obj_for_server = AttestationObject(attestation_bytes)
        except Exception:
            att_obj_for_server = None
    if att_obj_for_server is None:
        # server.register_complete may accept raw bytes in some versions; we'll pass raw bytes if needed.
        att_obj_for_server = attestation_bytes

    # perform register_complete
    try:
        auth_data = server.register_complete(
            state=state_obj,
            client_data=client_data_obj,
            attestation_object=att_obj_for_server
        )
    except Exception as e:
        logger.exception("register_complete failed")
        # include diagnostic types but not raw bytes
        diag = {
            'state_type': str(type(state_obj)),
            'client_data_type': str(type(client_data_obj)),
            'attestation_type': str(type(att_obj_for_server))
        }
        return JsonResponse({"ok": False, "error": str(e), "diag": diag}, status=400)

    # extract credential info - robust to possible return shapes
    try:
        # credential_data often at auth_data.credential_data
        if hasattr(auth_data, 'credential_data'):
            cred = auth_data.credential_data
        elif isinstance(auth_data, dict) and 'credential' in auth_data:
            cred = auth_data['credential']
        else:
            # fallback: try attribute access on first element
            cred = getattr(auth_data, 'credential', None) or auth_data

        credential_id_bytes = getattr(cred, 'credential_id', None) or getattr(cred, 'id', None)
        public_key_cose = getattr(cred, 'public_key', None) or getattr(cred, 'credential_public_key', None)
        # sign count may be on auth_data or on auth_data.auth_data
        sign_count = None
        if hasattr(auth_data, 'sign_count'):
            sign_count = getattr(auth_data, 'sign_count')
        elif hasattr(auth_data, 'auth_data') and hasattr(auth_data.auth_data, 'sign_count'):
            sign_count = getattr(auth_data.auth_data, 'sign_count')
        elif hasattr(auth_data, 'auth_data') and hasattr(auth_data.auth_data, 'counter'):
            sign_count = getattr(auth_data.auth_data, 'counter')
        # final fallback find in cred
        if sign_count is None:
            sign_count = getattr(cred, 'sign_count', 0)
        # normalize credential id -> base64url string
        credential_id_b64u = None
        if isinstance(credential_id_bytes, (bytes, bytearray)):
            credential_id_b64u = b64u(bytes(credential_id_bytes))
        elif isinstance(credential_id_bytes, str):
            # could be base64url or raw str; try to decode then re-encode as b64url
            try:
                tmp = b64u_to_bytes(credential_id_bytes)
                credential_id_b64u = b64u(tmp)
            except Exception:
                # fallback: utf-8 bytes
                try:
                    credential_id_b64u = b64u(credential_id_bytes.encode('utf-8'))
                except Exception:
                    credential_id_b64u = None

        # normalize public key: many python-fido2 versions return a dict (COSE map) here
        pk_bytes = None
        if isinstance(public_key_cose, (bytes, bytearray)):
            pk_bytes = bytes(public_key_cose)
        elif isinstance(public_key_cose, dict):
            # store a JSON-safe representation of the COSE map (safe for storage)
            try:
                pk_bytes = json.dumps(convert_to_json_safe(public_key_cose)).encode('utf-8')
            except Exception:
                pk_bytes = None
        elif isinstance(public_key_cose, str):
            # maybe base64 encoded
            try:
                pk_bytes = base64.b64decode(public_key_cose)
            except Exception:
                pk_bytes = public_key_cose.encode('utf-8')
        else:
            # try best-effort coercion
            try:
                pk_bytes = bytes(public_key_cose)
            except Exception:
                pk_bytes = None

        if not credential_id_b64u or pk_bytes is None:
            raise ValueError("could not extract credential_id or public_key")
    except Exception as e:
        logger.exception("Failed to extract credential info")
        # Provide developer-friendly diagnostics (truncated) to help debug shapes
        try:
            auth_repr = repr(auth_data)
            if len(auth_repr) > 1000:
                auth_repr = auth_repr[:1000] + '...TRUNC'
        except Exception:
            auth_repr = '<unrepresentable>'
        try:
            auth_dir = [d for d in dir(auth_data) if not d.startswith('_')]
        except Exception:
            auth_dir = None
        diag = {
            'error': str(e),
            'auth_data_type': str(type(auth_data)),
            'auth_data_repr': auth_repr,
            'auth_data_dir_sample': auth_dir[:50] if isinstance(auth_dir, list) else auth_dir,
        }
        return JsonResponse({"ok": False, "error": f"failed to extract credential: {e}", 'diag': diag}, status=500)

    # finally store credential
    try:
        store_credential(user_id, credential_id_b64u, pk_bytes, int(sign_count or 0), extra={
            'attestation_format': getattr(auth_data, 'fmt', 'unknown') if hasattr(auth_data, 'fmt') else 'unknown',
            'attestation_object_b64': base64.b64encode(attestation_bytes).decode('ascii'),
            'client_data_b64': base64.b64encode(clientdata_bytes).decode('ascii')
        })
    except Exception as e:
        logger.exception("Failed to store credential in DB")
        return JsonResponse({"ok": False, "error": f"Failed to store credential: {e}"}, status=500)

    return JsonResponse({"ok": True, "credential_id": credential_id_b64u})


@csrf_exempt
def authenticate_options(request):
    """
    POST { user_id }
    returns PublicKeyCredentialRequestOptions (JSON-safe)
    """
    if request.method != 'POST':
        return HttpResponseBadRequest('POST only')
    try:
        body = json.loads(request.body or '{}')
    except Exception:
        return JsonResponse({'error': 'invalid json'}, status=400)

    user_id = body.get("user_id") or body.get("email") or body.get("username")

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
        logger.exception('authenticate_begin failed')
        return JsonResponse({'error': f'authenticate_begin failed: {e}'}, status=500)

    # store state for later verification
    try:
        store_state(user_id, state, ttl_seconds=120)
    except Exception:
        logger.exception('store_state failed for authenticate')

    opts_json = convert_to_json_safe(options)
    # options may be structured as {'publicKey': ...} or directly
    out = opts_json.get('publicKey') if isinstance(opts_json, dict) and 'publicKey' in opts_json else opts_json
    out = out or {}
    # ensure challenge and allowCredentials ids are base64url strings
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
    if request.method != 'POST':
        return HttpResponseBadRequest('POST only')
    try:
        body = json.loads(request.body or '{}')
    except Exception:
        return JsonResponse({'ok': False, 'error': 'invalid json'}, status=400)

    user_id = body.get("user_id") or body.get("email") or body.get("username")

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
        return JsonResponse({'ok': False, 'error': f'bad base64 payload: {e}'}, status=400)

    state_obj = get_and_delete_state(user_id)
    if not state_obj:
        return JsonResponse({'ok': False, 'error': 'challenge missing or expired'}, status=400)

    # Build credentials list from stored DynamoDB rows and pass to python-fido2 for verification.
    try:
        stored = get_credentials_for_user(user_id)
        creds_for_server = []
        for row in stored:
            try:
                # credential_id in table is stored as base64url string
                cid = b64u_to_bytes(row.get('credential_id'))
            except Exception:
                # try regular base64 fallback
                try:
                    cid = base64.b64decode(row.get('credential_id'))
                except Exception:
                    continue
            # public_key_cose stored as base64 (standard) in table
            pk = None
            try:
                if row.get('public_key_cose'):
                    pk = base64.b64decode(row.get('public_key_cose'))
            except Exception:
                pk = None
            creds_for_server.append({
                'credential_id': cid,
                'id': cid,
                'public_key': pk,
                'sign_count': int(row.get('sign_count', 0) or 0)
            })

        auth_data = server.authenticate_complete(
            state_obj,
            creds_for_server,
            cred_id_bytes,
            clientdata_bytes,
            authdata_bytes,
            signature_bytes
        )
    except Exception as e:
        logger.exception('authenticate_complete failed')
        return JsonResponse({'ok': False, 'error': str(e)}, status=400)

    # server.authenticate_complete returns auth info including credential_id and sign_count
    try:
        cred_id = getattr(auth_data, 'credential_id', None) or getattr(auth_data, 'credential', None) or None
        sign_count = getattr(auth_data, 'sign_count', None) or 0
        # normalize credential id
        if isinstance(cred_id, (bytes, bytearray)):
            cred_id_b64u = b64u(bytes(cred_id))
        elif isinstance(cred_id, str):
            cred_id_b64u = b64u(b64u_to_bytes(cred_id))
        else:
            cred_id_b64u = None
    except Exception:
        cred_id_b64u = None
        sign_count = 0

    if not cred_id_b64u:
        return JsonResponse({'ok': False, 'error': 'could not determine credential id'}, status=500)

    # Ensure the credential belongs to this user and that we have a stored public key to verify against.
    stored_items = get_credentials_for_user(user_id)
    matched = None
    for it in stored_items:
        if it.get('credential_id') == cred_id_b64u:
            matched = it
            break
    if not matched:
        # The authenticator returned a credential id that isn't registered for this username.
        logger.warning('authenticate_verify: credential id not found for user %s: %s', user_id, cred_id_b64u)
        return JsonResponse({'ok': False, 'error': 'credential not registered for this user'}, status=403)

    # validate stored public key exists and appears to be binary COSE bytes (not JSON dump)
    stored_pk_b64 = matched.get('public_key_cose') or matched.get('public_key')
    pk_bytes = None
    if stored_pk_b64:
        try:
            pk_bytes = base64.b64decode(stored_pk_b64)
            # quick sanity: if pk_bytes starts with '{' or '[' treat as JSON (migrated COSE map) and refuse
            if len(pk_bytes) and pk_bytes[0] in (0x7b, 0x5b):
                logger.warning('authenticate_verify: stored public key for user %s appears to be JSON, not COSE bytes', user_id)
                return JsonResponse({'ok': False, 'error': 'stored public key format not supported; re-register required'}, status=500)
        except Exception:
            pk_bytes = None
    if not pk_bytes:
        logger.warning('authenticate_verify: no usable public key for user %s credential %s', user_id, cred_id_b64u)
        return JsonResponse({'ok': False, 'error': 'no usable public key for this credential'}, status=500)

    # update stored sign count
    try:
        # fetch existing item
        items = get_credentials_for_user(user_id)
        for it in items:
            if it.get('credential_id') == cred_id_b64u:
                # update sign_count attribute
                creds_table.update_item(Key={'user_id': user_id, 'credential_id': it['credential_id']},
                                       UpdateExpression='SET sign_count = :sc',
                                       ExpressionAttributeValues={':sc': int(sign_count)})
                break
    except Exception:
        logger.exception('Failed to update sign_count')

    # success -> log the user in (create Django session)
    try:
        user = UserProfile.objects.filter(username=user_id).first()
        if user:
            django_login(request, user)
    except Exception:
        logger.exception('Failed to login user after WebAuthn authenticate')

    return JsonResponse({'ok': True, 'credential_id': cred_id_b64u})

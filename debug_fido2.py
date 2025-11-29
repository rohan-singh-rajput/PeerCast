import os
import django
from django.conf import settings

# Configure Django settings
if not settings.configured:
    settings.configure(
        INSTALLED_APPS=[
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'core',
        ],
        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
        SECRET_KEY='debug',
    )
    django.setup()

from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.utils import websafe_encode
import base64

def b64u(b: bytes) -> str:
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("b64u expects bytes")
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

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

rp = PublicKeyCredentialRpEntity(id="localhost", name="PeerCast")
server = Fido2Server(rp)

user = PublicKeyCredentialUserEntity(id=b"user_id", name="user", display_name="User")

options, state = server.register_begin(user)

print("Options type:", type(options))
print("Options dict keys:", options.__dict__.keys() if hasattr(options, '__dict__') else "No __dict__")
json_safe = convert_to_json_safe(options)
print("JSON Safe keys:", json_safe.keys() if isinstance(json_safe, dict) else "Not a dict")
print("JSON Safe:", json_safe)

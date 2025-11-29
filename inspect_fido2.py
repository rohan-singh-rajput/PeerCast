import inspect
from fido2.server import Fido2Server
from fido2.webauthn import AuthenticatorAttestationResponse

print("Fido2Server.register_complete signature:")
print(inspect.signature(Fido2Server.register_complete))

print("\nAuthenticatorAttestationResponse signature:")
print(inspect.signature(AuthenticatorAttestationResponse.__init__))

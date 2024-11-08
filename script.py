import secrets
# generates django secret key
print(secrets.token_urlsafe(50))

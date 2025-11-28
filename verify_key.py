import base64
import cbor2
import sys

# Try imports
try:
    from fido2.cose import COSEKey
except ImportError:
    try:
        from fido2.cose import CoseKey as COSEKey
    except ImportError:
        print("Could not import COSEKey or CoseKey")
        sys.exit(1)

key_b64 = "pQECAyYgASFYIOI0j8yILcqTSRTGXHHB74GyVPVVqicaK3tQ4ko7DftOIlgg9vXwACLTCMky09dwGXyx84SLZVzeLRlTSWO0vomGlAU="

try:
    key_bytes = base64.b64decode(key_b64)
    print(f"Decoded {len(key_bytes)} bytes")
    
    # Try decoding as CBOR first
    try:
        cose_dict = cbor2.loads(key_bytes)
        print("Successfully decoded CBOR:", cose_dict)
        
        # Try parsing with COSEKey
        try:
            key = COSEKey.parse(cose_dict)
            print("Successfully parsed COSEKey:", key)
            print("Has verify method:", hasattr(key, 'verify'))
        except Exception as e:
            print("Failed to parse COSEKey from dict:", e)
            
    except Exception as e:
        print("Failed to decode CBOR:", e)
        
except Exception as e:
    print("Failed to decode base64:", e)

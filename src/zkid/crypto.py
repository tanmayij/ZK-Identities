#import blake2b
from hashlib import blake2b

def derive_salt(id, attribute_name):
    """Deterministic salt derivation from user ID and attribute name.
    
    NOTE: For production, use cryptographically random salts (secrets.token_bytes(32))
    and store them in the user bundle. This deterministic version is for dev/testing.
    """
    hasher = blake2b(digest_size=32)
    hasher.update(f"{id}-{attribute_name}".encode('utf-8'))
    return hasher.digest() #returns bytes

#commit_attr(value_int_or_bytes, salt) -> Commitment
def commit_attr(value, salt):
    """Simple hash-based commitment: H(value || salt).
    
    NOTE: This is binding but NOT cryptographically hiding (brute-forceable for small value spaces).
    TODO: Upgrade to Pedersen commitments for production ZK-friendliness.
    """
    hasher = blake2b(digest_size=32)
    if isinstance(value, int):
        value_bytes = value.to_bytes(8, byteorder='big', signed=False)
    elif isinstance(value, str):
        value_bytes = value.encode('utf-8')
    else:
        value_bytes = value  #assume bytes
    hasher.update(value_bytes)
    hasher.update(salt)
    return hasher.digest()  #returns bytes

#H(x: bytes) -> bytes for Merkle leaves
def hash_leaf(data: bytes):
    """Hash a Merkle tree leaf with domain separation prefix."""
    hasher = blake2b(digest_size=32)
    hasher.update(b'\x00')  #leaf prefix
    hasher.update(data)
    return hasher.digest()

def hash_internal(left: bytes, right: bytes):
    """Hash two Merkle tree nodes to create parent node.
    
    Uses domain separation prefix (0x01) to prevent leaf/internal collision attacks.
    """
    hasher = blake2b(digest_size=32)
    hasher.update(b'\x01')  # internal node prefix
    hasher.update(left)
    hasher.update(right)
    return hasher.digest()



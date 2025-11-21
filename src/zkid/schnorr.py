"""
Schnorr signature implementation with blind signing support.

This is a simplified educational implementation for the encrypted database system.
Uses elliptic curve cryptography (secp256k1) for Schnorr signatures.

WARNING: This is prototype code for research/demonstration purposes.
For production, use a battle-tested library like libsecp256k1 or similar.
"""

import secrets
import hashlib
from dataclasses import dataclass
from typing import Tuple, Optional


# Secp256k1 curve parameters (Bitcoin/Ethereum curve)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


@dataclass
class Point:
    """Elliptic curve point on secp256k1."""
    x: int
    y: int
    
    def __eq__(self, other):
        if isinstance(other, Point):
            return self.x == other.x and self.y == other.y
        return False
    
    def is_infinity(self):
        return self.x == 0 and self.y == 0


# Point at infinity
INFINITY = Point(0, 0)
# Generator point
G = Point(Gx, Gy)


def mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm."""
    return pow(a, -1, m)


def point_add(p1: Point, p2: Point) -> Point:
    """Add two points on the elliptic curve."""
    if p1.is_infinity():
        return p2
    if p2.is_infinity():
        return p1
    
    if p1.x == p2.x:
        if p1.y == p2.y:
            # Point doubling
            s = (3 * p1.x * p1.x * mod_inverse(2 * p1.y, P)) % P
        else:
            # Points are inverses
            return INFINITY
    else:
        # Point addition
        s = ((p2.y - p1.y) * mod_inverse(p2.x - p1.x, P)) % P
    
    x3 = (s * s - p1.x - p2.x) % P
    y3 = (s * (p1.x - x3) - p1.y) % P
    
    return Point(x3, y3)


def point_multiply(k: int, point: Point) -> Point:
    """Multiply a point by a scalar using double-and-add."""
    if k == 0:
        return INFINITY
    if k < 0:
        raise ValueError("Scalar must be non-negative")
    
    result = INFINITY
    addend = point
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    
    return result


def hash_to_scalar(*messages: bytes) -> int:
    """Hash messages to a scalar in the field."""
    h = hashlib.sha256()
    for msg in messages:
        h.update(msg)
    return int.from_bytes(h.digest(), 'big') % N


@dataclass
class SchnorrKeypair:
    """Schnorr keypair."""
    sk: int  # Secret key (scalar)
    pk: Point  # Public key (point)


@dataclass
class SchnorrSignature:
    """Schnorr signature (R, s)."""
    R: Point  # Commitment point
    s: int  # Response scalar


def generate_keypair() -> SchnorrKeypair:
    """Generate a new Schnorr keypair."""
    sk = secrets.randbelow(N - 1) + 1  # Avoid 0
    pk = point_multiply(sk, G)
    return SchnorrKeypair(sk=sk, pk=pk)


def sign(keypair: SchnorrKeypair, message: bytes) -> SchnorrSignature:
    """
    Sign a message with Schnorr signature.
    
    Args:
        keypair: Schnorr keypair
        message: Message to sign
    
    Returns:
        Schnorr signature (R, s)
    """
    # Generate random nonce
    k = secrets.randbelow(N - 1) + 1
    R = point_multiply(k, G)
    
    # Compute challenge: e = H(R || pk || m)
    e = hash_to_scalar(
        R.x.to_bytes(32, 'big'),
        keypair.pk.x.to_bytes(32, 'big'),
        keypair.pk.y.to_bytes(32, 'big'),
        message
    )
    
    # Compute response: s = k + e * sk
    s = (k + e * keypair.sk) % N
    
    return SchnorrSignature(R=R, s=s)


def verify(pk: Point, message: bytes, signature: SchnorrSignature) -> bool:
    """
    Verify a Schnorr signature.
    
    Args:
        pk: Public key
        message: Message that was signed
        signature: Schnorr signature to verify
    
    Returns:
        True if signature is valid, False otherwise
    """
    # Compute challenge: e = H(R || pk || m)
    e = hash_to_scalar(
        signature.R.x.to_bytes(32, 'big'),
        pk.x.to_bytes(32, 'big'),
        pk.y.to_bytes(32, 'big'),
        message
    )
    
    # Check: s*G = R + e*pk
    left = point_multiply(signature.s, G)
    right = point_add(signature.R, point_multiply(e, pk))
    
    return left == right


# ============================================================================
# Blind Schnorr Signature Protocol (Placeholder/Simplified)
# ============================================================================

@dataclass
class BlindingState:
    """Client-side state for blind signature protocol."""
    alpha: int  # Blinding factor for challenge
    beta: int  # Blinding factor for commitment
    R_prime: Point  # Blinded commitment
    message: bytes  # Original message


@dataclass
class BlindSignatureRequest:
    """Request from client to server for blind signature."""
    R_prime: Point  # Blinded commitment point
    

@dataclass
class BlindSignatureResponse:
    """Response from server with blind signature."""
    s_prime: int  # Blinded response scalar


def blind_prepare(pk: Point, message: bytes) -> Tuple[BlindingState, BlindSignatureRequest]:
    """
    Client: Prepare a blinded message for signing.
    
    This is a simplified blind Schnorr protocol. In production,
    use a formally verified implementation.
    
    Args:
        pk: Server's public key
        message: Message to be blindly signed
    
    Returns:
        (blinding_state, blind_request)
    """
    # Client generates blinding factors
    alpha = secrets.randbelow(N - 1) + 1  # Challenge blinding
    beta = secrets.randbelow(N - 1) + 1   # Commitment blinding
    
    # Client generates own commitment and blinds it
    # Instead of asking server for R, we simulate by having client
    # generate R' = beta*G (server will sign this blinded commitment)
    R_prime = point_multiply(beta, G)
    
    state = BlindingState(
        alpha=alpha,
        beta=beta,
        R_prime=R_prime,
        message=message
    )
    
    request = BlindSignatureRequest(R_prime=R_prime)
    
    return state, request


def blind_sign(keypair: SchnorrKeypair, request: BlindSignatureRequest, 
               server_nonce: Optional[int] = None) -> BlindSignatureResponse:
    """
    Server: Sign a blinded commitment.
    
    Server doesn't know what message this commitment corresponds to.
    
    Args:
        keypair: Server's Schnorr keypair
        request: Blind signature request from client
        server_nonce: Optional nonce (if None, generates random)
    
    Returns:
        Blind signature response
    """
    # Server generates nonce if not provided
    if server_nonce is None:
        k = secrets.randbelow(N - 1) + 1
    else:
        k = server_nonce
    
    # Server computes R = k*G
    R = point_multiply(k, G)
    
    # Server computes challenge on blinded commitment
    # e' = H(R' || pk || R)
    e_prime = hash_to_scalar(
        request.R_prime.x.to_bytes(32, 'big'),
        keypair.pk.x.to_bytes(32, 'big'),
        keypair.pk.y.to_bytes(32, 'big'),
        R.x.to_bytes(32, 'big')
    )
    
    # Server computes blinded response: s' = k + e' * sk
    s_prime = (k + e_prime * keypair.sk) % N
    
    return BlindSignatureResponse(s_prime=s_prime)


def unblind(state: BlindingState, response: BlindSignatureResponse) -> SchnorrSignature:
    """
    Client: Unblind the signature from server.
    
    Args:
        state: Client's blinding state
        response: Blind signature from server
    
    Returns:
        Unblinded Schnorr signature
    """
    # Unblind the response
    # s = s' + alpha (simplified; in full protocol this is more complex)
    s = (response.s_prime + state.alpha) % N
    
    # The commitment R is derived from R_prime
    # In simplified version, R = R_prime / beta
    # But point division isn't straightforward, so we use R_prime directly
    # NOTE: This is simplified and not cryptographically rigorous!
    # A proper implementation would handle this correctly.
    
    return SchnorrSignature(R=state.R_prime, s=s)


# ============================================================================
# High-level API for encrypted database system
# ============================================================================

class SchnorrIssuer:
    """Server-side Schnorr signature issuer for encrypted database."""
    
    def __init__(self, keypair: Optional[SchnorrKeypair] = None):
        """Initialize with a keypair (generates new if not provided)."""
        self.keypair = keypair if keypair else generate_keypair()
    
    def get_public_key(self) -> Point:
        """Get public key for distribution to clients."""
        return self.keypair.pk
    
    def sign_message(self, message: bytes) -> SchnorrSignature:
        """Sign a message directly (non-blind)."""
        return sign(self.keypair, message)
    
    def blind_sign_request(self, request: BlindSignatureRequest) -> BlindSignatureResponse:
        """Sign a blinded request from a client."""
        return blind_sign(self.keypair, request)
    
    def verify_signature(self, message: bytes, signature: SchnorrSignature) -> bool:
        """Verify a signature (useful for testing)."""
        return verify(self.keypair.pk, message, signature)


# ============================================================================
# Utility functions
# ============================================================================

def point_to_bytes(point: Point) -> bytes:
    """Serialize a point to bytes (compressed format)."""
    # Simple serialization: x-coordinate + y parity bit
    prefix = b'\x02' if point.y % 2 == 0 else b'\x03'
    return prefix + point.x.to_bytes(32, 'big')


def bytes_to_point(data: bytes) -> Point:
    """Deserialize a point from bytes (compressed format)."""
    if len(data) != 33:
        raise ValueError("Invalid point data length")
    
    prefix = data[0]
    x = int.from_bytes(data[1:], 'big')
    
    # Compute y from x (solving curve equation)
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    
    # Choose correct y based on parity
    if (prefix == 0x02 and y % 2 != 0) or (prefix == 0x03 and y % 2 == 0):
        y = P - y
    
    return Point(x, y)


def signature_to_bytes(sig: SchnorrSignature) -> bytes:
    """Serialize a signature to bytes."""
    return point_to_bytes(sig.R) + sig.s.to_bytes(32, 'big')


def bytes_to_signature(data: bytes) -> SchnorrSignature:
    """Deserialize a signature from bytes."""
    if len(data) != 65:
        raise ValueError("Invalid signature data length")
    
    R = bytes_to_point(data[:33])
    s = int.from_bytes(data[33:], 'big')
    
    return SchnorrSignature(R=R, s=s)

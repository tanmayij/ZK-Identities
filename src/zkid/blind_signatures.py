"""
blind signature implementation using rsa blind signatures

after successful proof verification, the verifier can issue a blind signature
that the user unblinds to obtain an unlinkable attestation token.

this prevents the verifier from linking multiple verification sessions to the same user.
"""

import secrets
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class BlindSignatureIssuer:
    """verifier-side blind signature operations"""
    
    def __init__(self, key_size=2048):
        """initialize with rsa keypair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def get_public_key_pem(self):
        """export public key as pem"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def sign_blinded_message(self, blinded_message_int):
        """
        sign a blinded message (verifier operation)
        
        note: this is simplified rsa blind signature
        in production, use proper blind signature library
        """
        n = self.public_key.public_numbers().n
        e = self.public_key.public_numbers().e
        d = self.private_key.private_numbers().d
        
        # sign: s' = (m')^d mod n
        blinded_signature = pow(blinded_message_int, d, n)
        
        return blinded_signature
    
    def save_keys(self, private_path, public_path):
        """save keypair to files"""
        # save private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_path, 'wb') as f:
            f.write(private_pem)
        
        # save public key
        public_pem = self.get_public_key_pem()
        with open(public_path, 'wb') as f:
            f.write(public_pem)


class BlindSignatureUser:
    """user-side blind signature operations"""
    
    def __init__(self, verifier_public_key_pem):
        """initialize with verifier's public key"""
        self.public_key = serialization.load_pem_public_key(
            verifier_public_key_pem,
            backend=default_backend()
        )
        self.n = self.public_key.public_numbers().n
        self.e = self.public_key.public_numbers().e
    
    def prepare_message(self, predicate_set, nonce):
        """
        prepare message to be blindly signed
        
        message = hash(predicate_set || nonce)
        this binds the token to specific predicates and prevents replay
        """
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(json.dumps(predicate_set, sort_keys=True).encode('utf-8'))
        hasher.update(str(nonce).encode('utf-8'))
        message_hash = hasher.finalize()
        
        # convert to integer
        message_int = int.from_bytes(message_hash, 'big')
        
        return message_int, message_hash
    
    def blind_message(self, message_int):
        """
        blind the message before sending to verifier
        
        m' = m * r^e mod n
        where r is random blinding factor
        """
        # generate random blinding factor
        r = secrets.randbelow(self.n)
        while r <= 1 or pow(r, self.e, self.n) <= 1:
            r = secrets.randbelow(self.n)
        
        # blind: m' = m * r^e mod n
        r_e = pow(r, self.e, self.n)
        blinded_message = (message_int * r_e) % self.n
        
        return blinded_message, r
    
    def unblind_signature(self, blinded_signature, r):
        """
        unblind the signature from verifier
        
        s = s' * r^(-1) mod n
        """
        # compute r inverse
        r_inv = pow(r, -1, self.n)
        
        # unblind: s = s' / r mod n
        signature = (blinded_signature * r_inv) % self.n
        
        return signature
    
    def verify_signature(self, message_int, signature):
        """
        verify unblinded signature
        
        check: m == s^e mod n
        """
        recovered = pow(signature, self.e, self.n)
        return recovered == message_int


def generate_verifier_blind_keys(
    private_path="artifacts/verifier_blind_key.pem",
    public_path="artifacts/verifier_blind_public.pem"
):
    """generate and save verifier blind signature keys"""
    issuer = BlindSignatureIssuer()
    issuer.save_keys(private_path, public_path)
    print(f"verifier blind signature keys saved")
    print(f"  private: {private_path}")
    print(f"  public: {public_path}")
    return issuer


def create_blind_signature_token(
    predicate_set,
    nonce,
    verifier_public_key_path="artifacts/verifier_blind_public.pem"
):
    """
    user-side: create blinded message for attestation token
    
    args:
        predicate_set: list of predicates that were proven
        nonce: unique nonce (e.g., timestamp + random)
    
    returns:
        dict with blinded_message and user's blinding state
    """
    # load verifier public key
    with open(verifier_public_key_path, 'rb') as f:
        verifier_public_key = f.read()
    
    user = BlindSignatureUser(verifier_public_key)
    
    # prepare message
    message_int, message_hash = user.prepare_message(predicate_set, nonce)
    
    # blind the message
    blinded_message, r = user.blind_message(message_int)
    
    return {
        "blinded_message": blinded_message,
        "message_int": message_int,
        "message_hash": message_hash.hex(),
        "blinding_factor": r,
        "predicate_set": predicate_set,
        "nonce": nonce,
        "verifier_public_key": verifier_public_key.decode('utf-8')
    }


def issue_blind_signature(
    blinded_message,
    verifier_private_key_path="artifacts/verifier_blind_key.pem"
):
    """
    verifier-side: sign the blinded message after successful proof verification
    
    args:
        blinded_message: int, the blinded message from user
    
    returns:
        blinded_signature: int
    """
    # load verifier private key
    with open(verifier_private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    n = private_key.public_key().public_numbers().n
    d = private_key.private_numbers().d
    
    # sign blinded message
    blinded_signature = pow(blinded_message, d, n)
    
    return blinded_signature


def unblind_and_verify_token(
    blinded_signature,
    blind_state,
    verifier_public_key_path="artifacts/verifier_blind_public.pem"
):
    """
    user-side: unblind signature and verify token
    
    args:
        blinded_signature: int from verifier
        blind_state: dict from create_blind_signature_token
    
    returns:
        dict with unblinded token and verification status
    """
    # load verifier public key
    with open(verifier_public_key_path, 'rb') as f:
        verifier_public_key = f.read()
    
    user = BlindSignatureUser(verifier_public_key)
    
    # unblind signature
    signature = user.unblind_signature(
        blinded_signature,
        blind_state['blinding_factor']
    )
    
    # verify signature
    valid = user.verify_signature(
        blind_state['message_int'],
        signature
    )
    
    token = {
        "predicate_set": blind_state['predicate_set'],
        "nonce": blind_state['nonce'],
        "message_hash": blind_state['message_hash'],
        "signature": signature,
        "signature_hex": hex(signature),
        "valid": valid
    }
    
    return token


def verify_token_later(
    token,
    verifier_public_key_path="artifacts/verifier_blind_public.pem"
):
    """
    anyone can verify token later using verifier's public key
    
    this proves user successfully verified predicates without revealing
    which verification session produced this token (unlinkability)
    """
    # load verifier public key
    with open(verifier_public_key_path, 'rb') as f:
        verifier_public_key = f.read()
    
    user = BlindSignatureUser(verifier_public_key)
    
    # reconstruct message from token
    message_int, _ = user.prepare_message(
        token['predicate_set'],
        token['nonce']
    )
    
    # verify signature
    valid = user.verify_signature(message_int, token['signature'])
    
    return valid


if __name__ == "__main__":
    import time
    
    print("blind signature demonstration")
    print("=" * 60)
    
    # step 1: verifier generates blind signature keys
    print("\n1. generating verifier blind signature keys...")
    issuer = generate_verifier_blind_keys()
    
    # step 2: user creates blind token request
    print("\n2. user prepares blind signature request...")
    predicate_set = [
        {"type": "range", "attribute": "age", "threshold": 18},
        {"type": "equality", "attribute": "citizenship", "value": "germany"}
    ]
    nonce = int(time.time() * 1000)  # timestamp-based nonce
    
    blind_state = create_blind_signature_token(predicate_set, nonce)
    print(f"   blinded message: {str(blind_state['blinded_message'])[:32]}...")
    print(f"   nonce: {nonce}")
    
    # step 3: verifier signs blinded message (after proof verification)
    print("\n3. verifier signs blinded message...")
    blinded_sig = issue_blind_signature(blind_state['blinded_message'])
    print(f"   blinded signature: {str(blinded_sig)[:32]}...")
    
    # step 4: user unblinds signature
    print("\n4. user unblinds signature...")
    token = unblind_and_verify_token(blinded_sig, blind_state)
    print(f"   unblinded signature: {token['signature_hex'][:32]}...")
    print(f"   token valid: {token['valid']}")
    
    # step 5: later verification (by anyone with verifier's public key)
    print("\n5. third party verifies token...")
    is_valid = verify_token_later(token)
    print(f"   token verification: {is_valid}")
    
    # save example token
    token_path = "artifacts/proofs/example_blind_token.json"
    Path(token_path).parent.mkdir(parents=True, exist_ok=True)
    with open(token_path, 'w') as f:
        json.dump(token, f, indent=2)
    print(f"\n   example token saved to {token_path}")
    
    print("\n" + "=" * 60)
    print("demonstration complete")
    print("\nkey properties demonstrated:")
    print("- unlinkability: verifier cannot link token back to original request")
    print("- unforgeability: only verifier can create valid signatures")
    print("- binding: token is bound to specific predicates and nonce")

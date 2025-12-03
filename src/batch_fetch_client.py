"""
Client-side batch fetch logic for Read-Verify-Rotate architecture.

Implements k-anonymity fetching where the client requests k+1 encrypted blobs
(1 real target + k decoys) to hide which record they're actually accessing.
"""

import secrets
import random
import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
from poseidon_hash import PoseidonHash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class EncryptedBlob:
    """Encrypted user data blob from server."""
    index: int                          # Position in outer tree
    encrypted_data: bytes               # Encrypted attributes
    outer_path: List[Tuple[bytes, int]] # Merkle path (sibling, direction)
    inner_root: bytes                   # Inner tree root (acts as outer leaf)


@dataclass
class DecryptedUserData:
    """Decrypted user attributes."""
    attributes: List[int]               # Attribute values (e.g., [25, 1, ...] for age, citizenship, etc.)
    salts: List[bytes]                  # Current salts for each attribute
    inner_root: bytes                   # Inner Merkle root
    outer_index: int                    # Current position in outer tree


class BatchFetchClient:
    """
    Client for privacy-preserving batch fetching with rotation.
    
    Key Features:
    - k-anonymity: Fetches k decoys + 1 real target
    - Rotation: Moves user to new outer tree position after each access
    - Zero-knowledge: Server doesn't know which blob is the real target
    """
    
    def __init__(
        self,
        user_id: str,
        encryption_key: bytes,
        num_attributes: int = 8,
        verbose: bool = True,
    ):
        """
        Initialize batch fetch client.
        
        Args:
            user_id: User identifier (kept private)
            encryption_key: Symmetric key for decrypting blobs
            num_attributes: Number of attributes (must be 2^inner_depth)
        """
        self.user_id = user_id
        self.encryption_key = encryption_key
        self.num_attributes = num_attributes
        self.verbose = verbose
        
        # Track used nullifiers to prevent double-rotation
        self.used_nullifiers: set = set()
    
    def _generate_decoy_indices(self, target_index: int, k: int, total_users: int) -> List[int]:
        """
        Generate k random decoy indices different from target.
        
        Args:
            target_index: Real user's index
            k: Number of decoys
            total_users: Total number of users in outer tree
        
        Returns:
            List of k decoy indices
        """
        available = list(range(total_users))
        available.remove(target_index)
        return random.sample(available, k)
    
    def _decrypt_blob(self, blob: EncryptedBlob) -> Optional[DecryptedUserData]:
        """
        Attempt to decrypt a blob (succeeds only if it's the real target).

        Args:
            blob: Encrypted blob from server

        Returns:
            Decrypted data if decryption succeeds, None otherwise
        """
        try:
            # Decrypt with AES-GCM (authenticated encryption)
            nonce = blob.encrypted_data[:12]  # First 12 bytes is nonce
            ciphertext = blob.encrypted_data[12:]

            aesgcm = AESGCM(self.encryption_key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)

            # Parse JSON payload
            data = json.loads(decrypted_bytes.decode("utf-8"))

            return DecryptedUserData(
                attributes=data["attributes"],
                salts=[bytes.fromhex(s) for s in data["salts"]],
                inner_root=bytes.fromhex(data["inner_root"]),
                outer_index=blob.index,
            )
        except Exception:  # pragma: no cover - expected for decoys
            return None

    def _encrypt_blob(self, attributes: List[int], salts: List[bytes], inner_root: bytes) -> bytes:
        """Encrypt updated user data with fresh salts for server storage."""

        payload = json.dumps(
            {
                "attributes": attributes,
                "salts": [s.hex() for s in salts],
                "inner_root": inner_root.hex(),
            }
        ).encode()

        aesgcm = AESGCM(self.encryption_key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, payload, None)
        return nonce + ciphertext
    
    def _compute_inner_root(self, attributes: List[int], salts: List[bytes]) -> bytes:
        """
        Compute inner Merkle root from attributes and salts (matches Circom logic).
        
        Args:
            attributes: List of attribute values
            salts: List of salts (one per attribute)
        
        Returns:
            Inner Merkle root (32 bytes)
        """
        # Use Poseidon hash (ZK-friendly, matches circuits)
        return PoseidonHash.compute_inner_root(attributes, salts)
    
    def _generate_new_salts(self) -> List[bytes]:
        """Generate fresh random salts for re-randomization."""
        return [secrets.token_bytes(32) for _ in range(self.num_attributes)]
    
    def _compute_nullifier(self, old_inner_root: bytes, old_salt: bytes) -> bytes:
        """
        Compute nullifier to prevent double-use of old position.
        
        Args:
            old_inner_root: Previous inner root
            old_salt: First salt from old salts array
        
        Returns:
            Nullifier (32 bytes)
        """
        # Use Poseidon hash (matches circuit nullifier computation)
        return PoseidonHash.compute_nullifier(old_inner_root, old_salt)
    
    def _compute_inner_merkle_path(
        self,
        attributes: List[int],
        salts: List[bytes],
        attribute_index: int
    ) -> Tuple[bytes, List[bytes], List[int]]:
        """Compute inner tree authentication path for a specific attribute."""
        if attribute_index < 0 or attribute_index >= self.num_attributes:
            raise ValueError("attribute index out of range for predicate proof")

        leaves: List[bytes] = []
        for attr, salt in zip(attributes, salts):
            salt_int = int.from_bytes(salt, byteorder='big')
            leaf = PoseidonHash.hash(attr, salt_int)
            leaves.append(leaf)

        root, path_elements, path_indices = PoseidonHash.get_merkle_path(attribute_index, leaves)
        return root, path_elements, path_indices

    def _to_field_element(self, value: bytes) -> str:
        """convert bytes to decimal string for circom inputs."""
        return str(int.from_bytes(value, byteorder='big'))

    def _to_hex_signal(self, value: Any) -> str:
        """convert decimal string or int to a 64-digit hex signal with a hex prefix."""
        if isinstance(value, str):
            stripped = value.strip().lower()
            if stripped.startswith('0x'):
                stripped = stripped[2:]
            else:
                stripped = format(int(stripped), 'x')
        elif isinstance(value, int):
            stripped = format(value, 'x')
        else:
            raise TypeError("public signal must be int or str")

        return "0x" + stripped.zfill(64)

    def _generate_groth16_proof(
        self,
        circuit_inputs: Dict[str, Any],
        circuit_dir: Path,
        wasm_filename: str,
        zkey_filename: str
    ) -> Tuple[Path, Path]:
        """Generate witness and Groth16 proof artifacts for a circuit."""
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as input_file:
            json.dump(circuit_inputs, input_file)
            input_path = Path(input_file.name)

        with tempfile.NamedTemporaryFile(suffix='.wtns', delete=False) as witness_file:
            witness_path = Path(witness_file.name)

        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as proof_file:
            proof_path = Path(proof_file.name)

        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as public_file:
            public_path = Path(public_file.name)

        try:
            wasm_path = circuit_dir / wasm_filename
            generator = circuit_dir / 'generate_witness.js'

            calc_result = subprocess.run(
                ['node', str(generator), str(wasm_path), str(input_path), str(witness_path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            if calc_result.returncode != 0:
                raise RuntimeError(f'witness generation failed: {calc_result.stderr.strip()}')

            prove_result = subprocess.run(
                [
                    'snarkjs', 'groth16', 'prove',
                    str(circuit_dir.parent / zkey_filename),
                    str(witness_path),
                    str(proof_path),
                    str(public_path)
                ],
                capture_output=True,
                text=True,
                timeout=120
            )
            if prove_result.returncode != 0:
                raise RuntimeError(f'proof generation failed: {prove_result.stderr.strip()}')

            return proof_path, public_path
        finally:
            if input_path.exists():
                input_path.unlink(missing_ok=True)
            if witness_path.exists():
                witness_path.unlink(missing_ok=True)

    def fetch_and_rotate(
        self,
        target_index: int,
        k_decoys: int,
        server_fetch_fn,
        server_update_fn,
        outer_root: bytes,
        total_users: int,
        predicate_request: Optional[Dict[str, Any]] = None
    ) -> Tuple[Optional[DecryptedUserData], Dict[str, Any]]:
        """
        Fetch user data with k-anonymity and rotate to new position.
        
        This is the main privacy-preserving operation:
        1. Generate k decoy indices
        2. Request k+1 blobs from server (server doesn't know which is real)
        3. Decrypt only the target blob
        4. Generate rotation proof (Circuit A)
        5. Send update to server with new commitment
        
        Args:
            target_index: User's current position in outer tree
            k_decoys: Number of decoy requests (k-anonymity parameter)
            server_fetch_fn: Function to fetch blobs from server
                             Signature: (indices: List[int]) -> List[EncryptedBlob]
            server_update_fn: Function to send rotation update to server
                          Signature: (proof, public_signals, new_commitment, new_encrypted_blob, nullifier_hex) -> bool
            outer_root: Current outer tree root
            total_users: Total number of users in database
            predicate_request: Optional predicate description for external verifier
        
        Returns:
            Tuple of (decrypted_data, proof_bundle)
        """
        total_start = time.perf_counter()

        if self.verbose:
            print(f"[fetch_and_rotate] starting k-anonymity fetch (k={k_decoys})")
        
        # Step 1: Generate decoy indices
        decoy_indices = self._generate_decoy_indices(target_index, k_decoys, total_users)
        all_indices = [target_index] + decoy_indices
        random.shuffle(all_indices)  # Shuffle so server can't identify target by position
        
        if self.verbose:
            print(f"  requesting indices: {all_indices} (target is hidden)")

        if isinstance(outer_root, str):
            trimmed = outer_root.lower().strip()
            if trimmed.startswith('0x'):
                trimmed = trimmed[2:]
            outer_root_bytes = bytes.fromhex(trimmed)
        else:
            outer_root_bytes = outer_root
        
        # Step 2: Fetch k+1 encrypted blobs from server
        blobs = server_fetch_fn(all_indices)
        
        if len(blobs) != k_decoys + 1:
            raise ValueError(f"expected {k_decoys + 1} blobs, got {len(blobs)}")
        
        # Step 3: Decrypt blobs (only target will succeed)
        decrypted_data = None
        target_blob = None
        
        for blob in blobs:
            result = self._decrypt_blob(blob)
            if result is not None:
                decrypted_data = result
                target_blob = blob
                break
        
        if decrypted_data is None:
            raise ValueError("failed to decrypt target blob - wrong key or missing data")
        
        if self.verbose:
            print(f" decrypted target at index {decrypted_data.outer_index}")
        
        # Step 4: Verify inner root matches
        computed_inner_root = self._compute_inner_root(
            decrypted_data.attributes,
            decrypted_data.salts
        )
        
        if computed_inner_root != decrypted_data.inner_root:
            raise ValueError("inner root mismatch - data corruption detected")
        
        predicate_bundle: Optional[Dict[str, Any]] = None

        timings: Dict[str, float] = {}

        if predicate_request is not None:
            attribute_index = predicate_request.get('attribute_index')
            threshold = predicate_request.get('threshold')

            if attribute_index is None or threshold is None:
                raise ValueError("predicate_request must include attribute_index and threshold")

            inner_root_check, inner_path_elements, inner_path_indices = self._compute_inner_merkle_path(
                decrypted_data.attributes,
                decrypted_data.salts,
                int(attribute_index)
            )

            if inner_root_check != decrypted_data.inner_root:
                raise ValueError("computed inner root does not match stored root for predicate proof")

            predicate_inputs = {
                "attributes": [str(attr) for attr in decrypted_data.attributes],
                "salts": [self._to_field_element(s) for s in decrypted_data.salts],
                "inner_path_elements": [self._to_field_element(elem) for elem in inner_path_elements],
                "inner_path_indices": [int(idx) for idx in inner_path_indices],
                "outer_path_elements": [
                    self._to_field_element(elem)
                    for elem, _ in target_blob.outer_path
                ],
                "outer_path_indices": [direction for _, direction in target_blob.outer_path],
                "outer_root": self._to_field_element(outer_root_bytes),
                "attribute_index": str(int(attribute_index)),
                "threshold": str(int(threshold))
            }

            build_dir = Path(__file__).parent.parent / 'build'
            predicate_dir = build_dir / 'predicate_js'
            predicate_start = time.perf_counter()

            predicate_proof_path, predicate_public_path = self._generate_groth16_proof(
                predicate_inputs,
                predicate_dir,
                'predicate.wasm',
                'predicate_final.zkey'
            )

            with predicate_proof_path.open('r') as pp:
                predicate_proof = json.load(pp)
            with predicate_public_path.open('r') as sp:
                predicate_public_signals = json.load(sp)

            predicate_proof_path.unlink(missing_ok=True)
            predicate_public_path.unlink(missing_ok=True)

            predicate_public_signals_hex = [
                self._to_hex_signal(signal) for signal in predicate_public_signals
            ]

            predicate_bundle = {
                "inputs": predicate_inputs,
                "proof": predicate_proof,
                "public_signals": predicate_public_signals_hex
            }

            timings["predicate_proof_ms"] = (time.perf_counter() - predicate_start) * 1000.0

            if self.verbose:
                print("  generated predicate proof for external verifier")

        # Step 5: Generate new salts for re-randomization
        new_salts = self._generate_new_salts()
        new_inner_root = self._compute_inner_root(decrypted_data.attributes, new_salts)
        new_encrypted_blob = self._encrypt_blob(
            decrypted_data.attributes,
            new_salts,
            new_inner_root,
        )
        
        if self.verbose:
            print("  generated new commitment (inner root)")
        
        # Step 6: Compute nullifier
        nullifier = self._compute_nullifier(
            decrypted_data.inner_root,
            decrypted_data.salts[0]
        )
        
        if nullifier in self.used_nullifiers:
            raise ValueError("nullifier already used - attempted double-rotation")
        
        self.used_nullifiers.add(nullifier)
        
        # Step 7: Prepare rotation proof inputs (for Circuit A)
        rotation_proof_inputs = {
            "attributes": [str(attr) for attr in decrypted_data.attributes],
            "old_salts": [self._to_field_element(s) for s in decrypted_data.salts],
            "new_salts": [self._to_field_element(s) for s in new_salts],
            "outer_path_elements": [
                self._to_field_element(elem) for elem, _ in target_blob.outer_path
            ],
            "outer_path_indices": [direction for _, direction in target_blob.outer_path],
            "old_outer_root": self._to_field_element(outer_root_bytes),
            "new_outer_leaf": self._to_field_element(new_inner_root),
            "nullifier": self._to_field_element(nullifier)
        }

        if self.verbose:
            print("  prepared rotation proof inputs")

        build_dir = Path(__file__).parent.parent / 'build'
        circuit_dir = build_dir / 'rotation_js'
        rotation_start = time.perf_counter()

        proof_path, public_path = self._generate_groth16_proof(
            rotation_proof_inputs,
            circuit_dir,
            'rotation.wasm',
            'rotation_final.zkey'
        )

        with proof_path.open('r') as pf:
            proof = json.load(pf)
        with public_path.open('r') as sf:
            public_signals = json.load(sf)

        proof_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)

        if self.verbose:
            print("  generated rotation proof")

        public_signals_hex = [self._to_hex_signal(signal) for signal in public_signals]

        nullifier_hex = "0x" + nullifier.hex()

        success = server_update_fn(
            proof,
            public_signals_hex,
            new_inner_root,
            new_encrypted_blob,
            nullifier_hex,
        )
        
        if not success:
            raise ValueError("server rejected rotation proof")
        
        if self.verbose:
            print("  rotation complete - user moved to new position")
        
        rotation_bundle = {
            "inputs": rotation_proof_inputs,
            "proof": proof,
            "public_signals": public_signals_hex,
        }
        
        proof_bundle = {
            "rotation": rotation_bundle,
            "predicate": predicate_bundle,
            "timings": timings
        }

        timings["rotation_proof_ms"] = (time.perf_counter() - rotation_start) * 1000.0
        timings["total_fetch_and_rotate_ms"] = (time.perf_counter() - total_start) * 1000.0

        return decrypted_data, proof_bundle


class MockServer:
    """Mock server with encrypted user database for testing."""
    
    def __init__(self):
        # Database of users with their encryption keys
        self.users = {}
        
    def register_user(self, user_index: int, encryption_key: bytes, 
                     attributes: List[int], salts: List[bytes]):
        """Register a user in the mock database."""
        inner_root = PoseidonHash.compute_inner_root(attributes, salts)

        # Create encrypted blob with AES-GCM
        data_to_encrypt = json.dumps({
            "attributes": attributes,
            "salts": [s.hex() for s in salts],
            "inner_root": inner_root.hex()
        }).encode()
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(encryption_key)
        nonce = secrets.token_bytes(12)
        encrypted_data = nonce + aesgcm.encrypt(nonce, data_to_encrypt, None)
        
        self.users[user_index] = {
            "encrypted_data": encrypted_data,
            "inner_root": inner_root
        }

        outer_path_elements, outer_path_indices = self._compute_outer_path(user_index)
        self.users[user_index]["outer_path"] = list(zip(outer_path_elements, outer_path_indices))
    
    def fetch(self, indices: List[int]) -> List[EncryptedBlob]:
        """Fetch encrypted blobs for requested indices."""
        blobs = []
        for idx in indices:
            if idx in self.users:
                user = self.users[idx]
                blob = EncryptedBlob(
                    index=idx,
                    encrypted_data=user["encrypted_data"],
                    outer_path=user["outer_path"],
                    inner_root=user["inner_root"]
                )
            else:
                # Generate dummy blob for non-existent users
                blob = EncryptedBlob(
                    index=idx,
                    encrypted_data=secrets.token_bytes(256),
                    outer_path=[(secrets.token_bytes(32), random.randint(0, 1)) for _ in range(10)],
                    inner_root=secrets.token_bytes(32)
                )
            blobs.append(blob)
        
        return blobs

    def _compute_outer_path(self, user_index: int) -> Tuple[List[bytes], List[int]]:
        """compute outer merkle path for a registered user."""
        if not self.users:
            raise ValueError("no users registered")

        max_index = max(self.users.keys())
        size = 1
        while size <= max(user_index, max_index):
            size <<= 1
        size = max(size, 1)

        leaves = [bytes(32) for _ in range(size)]
        for idx, info in self.users.items():
            if idx < size:
                leaves[idx] = info["inner_root"]

        _, path_elements, path_indices = PoseidonHash.get_merkle_path(user_index, leaves)
        return path_elements, path_indices

    def get_outer_root(self) -> bytes:
        """return current outer merkle root for registered users."""
        if not self.users:
            return bytes(32)

        max_index = max(self.users.keys())
        size = 1
        while size <= max_index:
            size <<= 1
        size = max(size, 1)

        leaves = [bytes(32) for _ in range(size)]
        for idx, info in self.users.items():
            if idx < size:
                leaves[idx] = info["inner_root"]

        return PoseidonHash.compute_merkle_root(leaves)


def mock_server_update(proof: Dict, public_signals: List[str], new_commitment: bytes, nullifier_hex: str) -> bool:
    """mock server update hook for the standalone demo."""
    print("[server] received rotation request")
    print(f"  public signals: {public_signals}")
    print(f"  nullifier: {nullifier_hex[2:18]}...")
    print(f"  new commitment: {new_commitment.hex()[:16]}...")
    print(f"  proof keys: {list(proof.keys())}")
    return True


# Example usage
if __name__ == "__main__":
    print("=== batch fetch and rotate demo ===\n")
    
    # Setup mock server
    server = MockServer()
    
    # User's encryption key
    user_key = secrets.token_bytes(32)
    
    # Register test user at index 42
    test_attributes = [25, 1, 42, 100, 5, 999, 12345, 7]
    test_salts = [secrets.token_bytes(32) for _ in range(8)]
    
    server.register_user(42, user_key, test_attributes, test_salts)
    print(f"[setup] registered user at index 42")
    
    # Add some other users as decoys (with different keys)
    for idx in [17, 89, 90, 49, 78, 100, 200]:
        server.register_user(
            idx,
            secrets.token_bytes(32),  # Different key
            [random.randint(18, 80) for _ in range(8)],
            [secrets.token_bytes(32) for _ in range(8)]
        )
    
    print(f"[setup] registered {len(server.users)} total users\n")
    
    # Setup client with matching key
    client = BatchFetchClient(
        user_id="alice",
        encryption_key=user_key,
        num_attributes=8
    )
    
    # Simulate fetch and rotate
    try:
        outer_root = server.get_outer_root()
        user_data, proof_bundle = client.fetch_and_rotate(
            target_index=42,
            k_decoys=3,
            server_fetch_fn=server.fetch,
            server_update_fn=mock_server_update,
            outer_root=outer_root,
            total_users=100
        )
        
        print("\n=== rotation successful ===")
        print(f"attributes: {user_data.attributes}")
        print(f"user now at new position (unlinkable to old position)")
        
    except Exception as e:
        print(f"\n[error] {e}")
        import traceback
        traceback.print_exc()

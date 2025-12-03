"""
PostgreSQL-backed encrypted identity database server.

This server stores encrypted identity attributes with Merkle commitments
and supports the Read-Verify-Rotate protocol with k-anonymity.
"""

import json
import secrets
import random
import subprocess
import tempfile
from typing import List, Dict, Optional, Tuple, Sequence
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import create_engine, Column, Integer, LargeBinary, String, JSON, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from faker import Faker

from poseidon_hash import PoseidonHash

Base = declarative_base()


class OuterTreeState(Base):
    """Global state for outer Merkle tree."""
    __tablename__ = "outer_tree_state"
    
    id = Column(Integer, primary_key=True, default=1)
    outer_root = Column(LargeBinary, nullable=False)  # Current outer tree root
    total_users = Column(Integer, nullable=False, default=0)
    last_updated = Column(String, nullable=True)


class EncryptedUser(Base):
    """Database model for encrypted user records."""
    __tablename__ = 'encrypted_users'
    
    user_index = Column(Integer, primary_key=True)
    encrypted_data = Column(LargeBinary, nullable=False)  # Encrypted attributes + salts
    inner_root = Column(LargeBinary, nullable=False)      # Merkle root of attributes
    outer_path_elements = Column(JSON, nullable=False)    # Path to outer tree root
    outer_path_indices = Column(JSON, nullable=False)     # Path directions
    nullifier = Column(String(66), nullable=True, index=True)  # Used nullifiers for rotation
    
    __table_args__ = (
        Index('idx_user_index', 'user_index'),
        Index('idx_nullifier', 'nullifier'),
    )


class EncryptedIdentityDatabase:
    """
    PostgreSQL-backed encrypted identity database with Merkle trees.
    
    Stores encrypted identity attributes (name, age, citizenship, etc.)
    with cryptographic commitments for privacy-preserving queries.
    """
    
    def __init__(self, db_url: str = "postgresql://localhost/identity_db"):
        """
        Initialize database connection.
        
        Args:
            db_url: PostgreSQL connection string
                   Format: postgresql://user:password@host:port/database
                   Example: postgresql://postgres:password@localhost:5432/identity_db
                   
        For local testing without password:
            postgresql://localhost/identity_db
        """
        self.engine = create_engine(db_url, echo=False)
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.used_nullifiers = set()
        
        # Initialize outer tree state if not exists
        session = self.SessionLocal()
        try:
            if not session.query(OuterTreeState).first():
                initial_state = OuterTreeState(
                    outer_root=secrets.token_bytes(32),  # Placeholder until first user
                    total_users=0
                )
                session.add(initial_state)
                session.commit()
        finally:
            session.close()
    
    def _compute_inner_root(self, attributes: List[int], salts: List[bytes]) -> bytes:
        """Compute Merkle root from attributes (matches client logic)."""
        # Use Poseidon hash (ZK-friendly, matches circuits)
        return PoseidonHash.compute_inner_root(attributes, salts)
    
    def _collect_outer_tree(self, session: Session) -> Tuple[List[EncryptedUser], List[bytes]]:
        """collect ordered users and padded leaf list for the outer tree."""
        users = session.query(EncryptedUser).order_by(EncryptedUser.user_index).all()
        if not users:
            return [], []

        max_index = max(user.user_index for user in users)
        target_size = 1
        while target_size <= max(max_index, len(users) - 1):
            target_size <<= 1
        baseline = 1 << 10
        target_size = max(target_size, baseline)

        leaves = [bytes(32) for _ in range(target_size)]
        for user in users:
            if user.user_index >= target_size:
                raise ValueError("user index exceeds outer tree capacity")
            leaves[user.user_index] = user.inner_root

        return users, leaves

    def _refresh_all_paths(
        self,
        users: Sequence[EncryptedUser],
        all_path_elements: Sequence[Sequence[bytes]],
        all_path_indices: Sequence[Sequence[int]],
    ) -> None:
        """Persist outer paths supplied for each user index."""
        if not users:
            return

        total_paths = len(all_path_elements)

        for user in users:
            if user.user_index >= total_paths:
                raise ValueError("user index exceeds outer tree capacity")

            elements = all_path_elements[user.user_index]
            indices = all_path_indices[user.user_index]
            user.outer_path_elements = [elem.hex() for elem in elements]
            user.outer_path_indices = list(indices)

    def _update_outer_state(self, session: Session) -> None:
        """Recompute outer tree root and refresh stored paths."""
        users, leaves = self._collect_outer_tree(session)
        tree_state = session.query(OuterTreeState).first()

        if not leaves:
            if not tree_state:
                tree_state = OuterTreeState(outer_root=secrets.token_bytes(32), total_users=0)
                session.add(tree_state)
                session.flush()
            tree_state.total_users = 0
            tree_state.last_updated = None
            return

        updated_root, all_path_elements, all_path_indices = PoseidonHash.compute_all_paths(leaves)

        if not tree_state:
            tree_state = OuterTreeState(outer_root=updated_root, total_users=0)
            session.add(tree_state)
            session.flush()

        tree_state.outer_root = updated_root
        tree_state.total_users = len(users)
        tree_state.last_updated = None
        self._refresh_all_paths(users, all_path_elements, all_path_indices)

    def recompute_outer_tree(self) -> Optional[bytes]:
        """trigger a full outer tree rebuild and return the new root."""
        session: Session = self.SessionLocal()
        try:
            self._update_outer_state(session)
            session.commit()
            state = session.query(OuterTreeState).first()
            return state.outer_root if state else None
        finally:
            session.close()
    
    @staticmethod
    def _normalize_hex(value: str) -> str:
        """return lowercase hex string with 0x prefix."""
        if isinstance(value, bytes):
            stripped = value.hex()
        else:
            stripped = value.lower().strip()
            if stripped.startswith("0x"):
                stripped = stripped[2:]
        return "0x" + stripped.zfill(64)

    def _verify_groth16_proof(self, proof: Dict, public_signals: List[str],
                              circuit_name: str = "rotation") -> bool:
        """
        Verify a Groth16 proof using snarkjs.
        
        Args:
            proof: Proof object from client
            public_signals: Public inputs to the circuit
            circuit_name: Name of circuit (rotation or predicate)
            
        Returns:
            True if proof is valid
        """
        project_root = Path(__file__).parent.parent
        vkey_path = project_root / f"build/{circuit_name}_vkey.json"
        
        if not vkey_path.exists():
            print(f"Warning: Verification key not found at {vkey_path}")
            return False
        
        try:
            # Write proof and public signals to temp files
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as pf:
                json.dump(proof, pf)
                proof_file = pf.name
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as sf:
                json.dump(public_signals, sf)
                signals_file = sf.name
            
            # Call snarkjs verify
            result = subprocess.run(
                ['snarkjs', 'groth16', 'verify', str(vkey_path), signals_file, proof_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Clean up temp files
            Path(proof_file).unlink(missing_ok=True)
            Path(signals_file).unlink(missing_ok=True)
            
            # Check result
            return result.returncode == 0 and 'OK' in result.stdout
            
        except subprocess.TimeoutExpired:
            print("Proof verification timeout")
            return False
        except Exception as e:
            print(f"Proof verification error: {e}")
            return False
    
    def register_user(self, user_index: int, encryption_key: bytes,
                     attributes: List[int], salts: List[bytes],
                     outer_path_elements: List[bytes], 
                     outer_path_indices: List[int]) -> bool:
        """
        Register a new user with encrypted identity data.
        
        Args:
            user_index: Unique user identifier (position in outer tree)
            encryption_key: User's encryption key (32 bytes)
            attributes: List of 8 identity attributes (age, citizenship, etc.)
            salts: List of 8 random salts (32 bytes each)
            outer_path_elements: Merkle path siblings in outer tree
            outer_path_indices: Merkle path directions (0=left, 1=right)
            
        Returns:
            True if registration successful
        """
        # Compute inner root
        inner_root = self._compute_inner_root(attributes, salts)
        
        # Serialize data for encryption
        data_to_encrypt = json.dumps({
            "attributes": attributes,
            "salts": [s.hex() for s in salts],
            "inner_root": inner_root.hex()
        }).encode()
        
        # Encrypt with AES-GCM (authenticated encryption)
        aesgcm = AESGCM(encryption_key)
        nonce = secrets.token_bytes(12)  # 96-bit nonce
        encrypted_data = nonce + aesgcm.encrypt(nonce, data_to_encrypt, None)
        
        # Store in database
        session: Session = self.SessionLocal()
        try:
            user = EncryptedUser(
                user_index=user_index,
                encrypted_data=encrypted_data,
                inner_root=inner_root,
                outer_path_elements=[e.hex() for e in outer_path_elements],
                outer_path_indices=outer_path_indices,
                nullifier=None
            )
            session.add(user)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error registering user: {e}")
            return False
        finally:
            session.close()
    
    def register_user_auto_path(self, user_index: int, encryption_key: bytes,
                                attributes: List[int], salts: List[bytes],
                                refresh_paths: bool = True) -> bool:
        """
        Register a new user with auto-computed outer Merkle path.
        
        Args:
            user_index: Unique user identifier
            encryption_key: User's encryption key (32 bytes)
            attributes: List of 8 identity attributes
            salts: List of 8 random salts (32 bytes each)
            
        Returns:
            True if registration successful
        """
        session: Session = self.SessionLocal()
        try:
            # First register with placeholder paths
            inner_root = self._compute_inner_root(attributes, salts)
            
            data_to_encrypt = json.dumps({
                "attributes": attributes,
                "salts": [s.hex() for s in salts],
                "inner_root": inner_root.hex()
            }).encode()
            
            aesgcm = AESGCM(encryption_key)
            nonce = secrets.token_bytes(12)
            encrypted_data = nonce + aesgcm.encrypt(nonce, data_to_encrypt, None)
            
            # Create user with placeholder paths
            user = EncryptedUser(
                user_index=user_index,
                encrypted_data=encrypted_data,
                inner_root=inner_root,
                outer_path_elements=[],  # Will compute after
                outer_path_indices=[],
                nullifier=None
            )
            session.add(user)
            session.flush()
            
            # # Compute real outer path now that user is in database
            # path_elements, path_indices = self._compute_outer_path(user_index, session)
            # user.outer_path_elements = [e.hex() for e in path_elements]
            # user.outer_path_indices = path_indices
            
            # # Update outer tree root
            # outer_root = self._rebuild_outer_tree(session)
            # tree_state = session.query(OuterTreeState).first()
            # tree_state.outer_root = outer_root
            # tree_state.total_users = session.query(EncryptedUser).count()
            
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error registering user: {e}")
            return False
        finally:
            session.close()
    
    def get_outer_root(self) -> Optional[bytes]:
        """Get current outer Merkle tree root."""
        session = self.SessionLocal()
        try:
            state = session.query(OuterTreeState).first()
            return state.outer_root if state else None
        finally:
            session.close()
    
    def fetch_users(self, user_indices: List[int]) -> List[Dict]:
        """
        Fetch encrypted blobs for requested user indices (k-anonymity batch fetch).
        
        Args:
            user_indices: List of user indices to fetch (target + decoys)
            
        Returns:
            List of encrypted user blobs
        """
        session: Session = self.SessionLocal()
        try:
            users = session.query(EncryptedUser).filter(
                EncryptedUser.user_index.in_(user_indices)
            ).all()
            
            result = []
            for user in users:
                result.append({
                    "index": user.user_index,
                    "encrypted_data": user.encrypted_data,
                    "outer_path": list(zip(
                        [bytes.fromhex(e) for e in user.outer_path_elements],
                        user.outer_path_indices
                    )),
                    "inner_root": user.inner_root
                })
            
            return result
        finally:
            session.close()
    
    def verify_rotation_proof(
        self,
        user_index: int,
        proof: Dict,
        new_inner_root: bytes,
        nullifier: str,
        new_encrypted_data: bytes,
        public_signals: Optional[List[str]] = None,
        batch_merkle_rebuild: bool = False,
    ) -> bool:
        """
        Verify rotation proof and update user's position.
        
        Args:
            user_index: User's current index
            proof: Groth16 proof object
            new_inner_root: New commitment after re-randomization
            nullifier: Hash to prevent double-rotation
            batch_merkle_rebuild: If True, defer merkle rebuild (for batching)
            
        Returns:
            True if proof valid and rotation successful
        """
        session: Session = self.SessionLocal()
        try:
            # Check nullifier hasn't been used
            normalized_nullifier = self._normalize_hex(nullifier)

            existing = session.query(EncryptedUser).filter(
                EncryptedUser.nullifier == normalized_nullifier
            ).first()
            
            if existing:
                print(f"Nullifier {normalized_nullifier[:18]}... already used")
                return False
            
            # Verify Groth16 proof (if proof provided)
            if proof is not None:
                tree_state = session.query(OuterTreeState).first()
                if not tree_state:
                    print("Missing outer tree state")
                    return False

                current_outer_root = tree_state.outer_root

                expected_signals = [
                    self._normalize_hex(current_outer_root),
                    self._normalize_hex(new_inner_root),
                    normalized_nullifier
                ]

                if public_signals is None:
                    public_signals = expected_signals

                resolved_signals = [self._normalize_hex(sig) for sig in public_signals]

                if resolved_signals != expected_signals:
                    print("Public signals mismatch")
                    return False

                if not self._verify_groth16_proof(proof, resolved_signals, "rotation"):
                    print("Invalid Groth16 proof")
                    return False
                
                print("Groth16 proof verified")
            else:
                print("warning: no proof provided (development mode)")
            
            # Update user's nullifier
            user = session.query(EncryptedUser).filter(
                EncryptedUser.user_index == user_index
            ).first()
            
            if user:
                user.nullifier = normalized_nullifier
                user.inner_root = new_inner_root
                user.encrypted_data = new_encrypted_data
                session.flush()

                if not batch_merkle_rebuild:
                    self._update_outer_state(session)

                session.commit()
                return True
            
            return False
        except Exception as e:
            session.rollback()
            print(f"Error verifying rotation: {e}")
            return False
        finally:
            session.close()
    
    def get_user_count(self) -> int:
        """Get total number of registered users."""
        session: Session = self.SessionLocal()
        try:
            return session.query(EncryptedUser).count()
        finally:
            session.close()
    
    def clear_database(self):
        """Clear all users (for testing)."""
        session: Session = self.SessionLocal()
        try:
            session.query(EncryptedUser).delete()
            state = session.query(OuterTreeState).first()
            if state:
                state.outer_root = secrets.token_bytes(32)
                state.total_users = 0
                state.last_updated = None
            session.commit()
        finally:
            session.close()


def populate_test_database(db: EncryptedIdentityDatabase, num_users: int = 100):
    """
    Populate database with synthetic identity data.
    
    Args:
        db: Database instance
        num_users: Number of test users to create
    """
    from faker import Faker
    import random
    
    fake = Faker()
    print(f"Populating database with {num_users} test users...")
    
    for i in range(num_users):
        # Generate synthetic identity attributes
        age = random.randint(18, 80)
        citizenship = random.choice([1, 2, 3, 4, 5])  # Country codes
        income = random.randint(20000, 200000)
        credit_score = random.randint(300, 850)
        license_class = random.choice([1, 2, 3, 4])
        status = random.choice([0, 1])  # 0=inactive, 1=active
        years_employed = random.randint(0, 40)
        num_dependents = random.randint(0, 5)
        
        attributes = [
            age, citizenship, income, credit_score,
            license_class, status, years_employed, num_dependents
        ]
        
        # Generate random encryption key and salts
        encryption_key = secrets.token_bytes(32)
        salts = [secrets.token_bytes(32) for _ in range(8)]
        
        # Register user with auto-computed outer path
        db.register_user_auto_path(
            user_index=i,
            encryption_key=encryption_key,
            attributes=attributes,
            salts=salts,
            refresh_paths=False
        )
        
        if (i + 1) % 20 == 0:
            print(f"  registered {i + 1}/{num_users} users")
    
    db.recompute_outer_tree()
    print(f" Database populated with {num_users} users")


if __name__ == "__main__":
    # Example usage
    print("=== PostgreSQL Encrypted Identity Database ===\n")
    
    # Initialize database (use SQLite for local testing without PostgreSQL)
    # db = EncryptedIdentityDatabase("postgresql://localhost/identity_db")
    db = EncryptedIdentityDatabase("sqlite:///identity_db.sqlite")
    
    print(f"Database initialized")
    print(f"Current users: {db.get_user_count()}\n")
    
    # Clear and populate with test data
    if db.get_user_count() == 0:
        populate_test_database(db, num_users=100)
    
    print(f"\n=== Testing k-anonymity fetch ===")
    # Simulate k-anonymity fetch (3 decoys + 1 target)
    target_index = 42
    decoy_indices = [10, 25, 67]
    all_indices = [target_index] + decoy_indices
    random.shuffle(all_indices)
    
    print(f"Fetching indices: {all_indices} (target hidden)")
    blobs = db.fetch_users(all_indices)
    print(f"Retrieved {len(blobs)} encrypted blobs")
    
    for blob in blobs:
        print(f"  User {blob['index']}: {len(blob['encrypted_data'])} bytes encrypted")
    
    print(f"\n Database ready for Read-Verify-Rotate protocol")

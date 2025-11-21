"""
encrypted database system with merkle trees and blind signatures.

implements design from docs/design_encrypted_db.tex with deterministic encryption,
per-user inner merkle trees, global outer tree, and leaf shuffling.
includes performance instrumentation for benchmarking.
"""

import time
import secrets
import random
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set, Any
from hashlib import blake2b
from collections import defaultdict
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from zkid.crypto import hash_leaf, hash_internal
from zkid.blind_signatures import BlindSignatureIssuer
from zkid.schnorr import (
    SchnorrIssuer, SchnorrKeypair, SchnorrSignature,
    BlindingState, BlindSignatureRequest, BlindSignatureResponse,
    blind_prepare, unblind
)


def derive_leaf_randomizer(uid: str, attr_index: int, seed: Optional[bytes] = None) -> bytes:
    """
    Derive deterministic per-leaf randomizer from uid and attribute index.
    
    This ensures consistency (same uid + index always gives same randomizer)
    while hiding the attribute semantic meaning from the server.
    
    Args:
        uid: User identifier
        attr_index: Attribute position (0, 1, 2, ...)
        seed: Optional global seed for the system (if None, uses default)
    
    Returns:
        32-byte randomizer
    """
    if seed is None:
        seed = b"encrypted_db_leaf_randomizer_v1"
    
    hasher = blake2b(digest_size=32)
    hasher.update(seed)
    hasher.update(uid.encode('utf-8'))
    hasher.update(attr_index.to_bytes(4, 'big'))
    return hasher.digest()


@dataclass
class DeterministicCiphertext:
    """ciphertext from deterministic encryption."""
    ciphertext: bytes
    tag: bytes


def compute_leaf_message_for_signing(ciphertext: DeterministicCiphertext,
                                      query_nonce: bytes,
                                      leaf_randomizer: bytes) -> bytes:
    """
    Compute the message to be signed for a leaf (attribute-agnostic).
    
    This message does NOT include uid or attribute name/index, only:
    - The encrypted value (ciphertext + tag)
    - Query-specific nonce (prevents replay across queries)
    - Per-leaf randomizer (ensures uniqueness)
    
    Args:
        ciphertext: Encrypted attribute value
        query_nonce: Fresh randomness for this query
        leaf_randomizer: Per-leaf randomness
    
    Returns:
        32-byte message suitable for Schnorr signing
    """
    hasher = blake2b(digest_size=32)
    hasher.update(b"leaf_message_v1")
    hasher.update(ciphertext.ciphertext)
    hasher.update(ciphertext.tag)
    hasher.update(query_nonce)
    hasher.update(leaf_randomizer)
    return hasher.digest()


class DeterministicEncryptionAES:
    """
    deterministic encryption using aes-128-ecb (cryptdb-style).
    
    uses per-column keys derived from master key and attribute name.
    aes-ecb mode ensures deterministic encryption: same plaintext always
    produces same ciphertext for a given key.
    
    note: ecb mode is only secure for deterministic encryption use case
    where determinism is required. not for general encryption.
    """
    
    def __init__(self, master_key: bytes):
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes")
        self.master_key = master_key
        self.column_keys: Dict[str, bytes] = {}
    
    def _derive_column_key(self, column_name: str) -> bytes:
        """derive per-column key from master key and column name."""
        if column_name in self.column_keys:
            return self.column_keys[column_name]
        
        hasher = blake2b(digest_size=16, key=self.master_key)
        hasher.update(b"column_key")
        hasher.update(column_name.encode('utf-8'))
        column_key = hasher.digest()
        
        self.column_keys[column_name] = column_key
        return column_key
    
    def encrypt(self, plaintext: bytes, column_name: str) -> DeterministicCiphertext:
        """
        encrypt plaintext deterministically using aes-128-ecb.
        
        args:
            plaintext: data to encrypt
            column_name: attribute name (for per-column key derivation)
        
        returns:
            deterministic ciphertext with tag for equality checking
        """
        column_key = self._derive_column_key(column_name)
        
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        
        cipher = Cipher(
            algorithms.AES(column_key),
            modes.ECB(),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        tag_hasher = blake2b(digest_size=32, key=column_key)
        tag_hasher.update(b"tag")
        tag_hasher.update(plaintext)
        tag = tag_hasher.digest()
        
        return DeterministicCiphertext(ciphertext=ciphertext, tag=tag)
    
    def decrypt(self, ct: DeterministicCiphertext, column_name: str) -> bytes:
        """
        decrypt ciphertext.
        
        args:
            ct: deterministic ciphertext
            column_name: attribute name (for per-column key derivation)
        
        returns:
            plaintext bytes
        """
        column_key = self._derive_column_key(column_name)
        
        cipher = Cipher(
            algorithms.AES(column_key),
            modes.ECB(),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ct.ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext


class DeterministicEncryption:
    """legacy hash-based deterministic encryption (kept for compatibility)."""
    
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        self.key = key
    
    def encrypt(self, plaintext: bytes) -> DeterministicCiphertext:
        hasher = blake2b(digest_size=len(plaintext), key=self.key)
        hasher.update(plaintext)
        keystream = hasher.digest()
        
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        
        tag_hasher = blake2b(digest_size=32, key=self.key)
        tag_hasher.update(b"tag")
        tag_hasher.update(plaintext)
        tag = tag_hasher.digest()
        
        return DeterministicCiphertext(ciphertext=ciphertext, tag=tag)
    
    def decrypt(self, ct: DeterministicCiphertext, plaintext_len: int) -> bytes:
        raise NotImplementedError("Decryption requires additional metadata")
    
    def decrypt_with_plaintext_check(self, ct: DeterministicCiphertext, 
                                     candidate_plaintext: bytes) -> bool:
        test_ct = self.encrypt(candidate_plaintext)
        return test_ct.ciphertext == ct.ciphertext and test_ct.tag == ct.tag


@dataclass
class MerkleNode:
    hash: bytes
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None
    is_leaf: bool = False
    leaf_data: Optional[bytes] = None


@dataclass
class MerklePath:
    leaf_index: int
    leaf_hash: bytes
    sibling_hashes: List[Tuple[bytes, bool]]
    root: bytes


class MerkleTree:
    """binary merkle tree with domain-separated hashing."""
    
    def __init__(self, leaves: List[bytes]):
        if not leaves:
            raise ValueError("Cannot build Merkle tree with no leaves")
        
        self.leaves = leaves.copy()
        self.leaf_map: Dict[bytes, int] = {lf: i for i, lf in enumerate(leaves)}
        self.root_node = self._build_tree(leaves)
        self.root = self.root_node.hash
    
    def _build_tree(self, hashes: List[bytes]) -> MerkleNode:
        if len(hashes) == 1:
            return MerkleNode(hash=hashes[0], is_leaf=True, leaf_data=hashes[0])
        
        next_level = []
        nodes = []
        
        for i in range(0, len(hashes), 2):
            left_hash = hashes[i]
            right_hash = hashes[i + 1] if i + 1 < len(hashes) else hashes[i]
            
            parent_hash = hash_internal(left_hash, right_hash)
            next_level.append(parent_hash)
        
        if len(next_level) == 1:
            return MerkleNode(hash=next_level[0])
        
        return self._build_tree(next_level)
    
    def get_auth_path(self, leaf: bytes) -> MerklePath:
        if leaf not in self.leaf_map:
            raise ValueError("Leaf not in tree")
        
        leaf_index = self.leaf_map[leaf]
        return self._compute_path(leaf_index)
    
    def _compute_path(self, leaf_index: int) -> MerklePath:
        path_siblings = []
        current_hashes = self.leaves.copy()
        current_index = leaf_index
        
        while len(current_hashes) > 1:
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                if sibling_index < len(current_hashes):
                    sibling = current_hashes[sibling_index]
                    is_right = True
                else:
                    sibling = current_hashes[current_index]
                    is_right = True
            else:
                sibling_index = current_index - 1
                sibling = current_hashes[sibling_index]
                is_right = False
            
            path_siblings.append((sibling, is_right))
            
            next_level = []
            for i in range(0, len(current_hashes), 2):
                left = current_hashes[i]
                right = current_hashes[i + 1] if i + 1 < len(current_hashes) else current_hashes[i]
                parent = hash_internal(left, right)
                next_level.append(parent)
            
            current_hashes = next_level
            current_index = current_index // 2
        
        return MerklePath(
            leaf_index=leaf_index,
            leaf_hash=self.leaves[leaf_index],
            sibling_hashes=path_siblings,
            root=self.root
        )
    
    def shuffle_and_rebuild(self) -> 'MerkleTree':
        shuffled = self.leaves.copy()
        random.shuffle(shuffled)
        return MerkleTree(shuffled)


@dataclass
class AttributeLeaf:
    """
    Attribute leaf in inner tree (attribute-agnostic design).
    
    Leaf hash does NOT include attr_name to prevent server from learning
    which attribute type is being accessed. Uses attr_index (position) instead.
    
    leaf_hash = H_leaf(uid || pk_user || ciphertext || randomizer)
    
    The randomizer is derived deterministically from uid + index to ensure
    consistency while hiding attribute semantics from the server.
    """
    uid: str
    pk_user: bytes
    attr_index: int  # Position in attribute vector (not semantically meaningful name)
    ciphertext: DeterministicCiphertext
    randomizer: bytes  # Per-leaf randomness derived from uid + index
    
    # For internal/client use only (not hashed, not revealed to server crypto):
    attr_name: Optional[str] = None  
    
    def compute_leaf_hash(self) -> bytes:
        """
        Compute leaf hash WITHOUT including attribute name or index.
        Only includes: uid, pk_user, ciphertext, and per-leaf randomizer.
        """
        hasher = blake2b(digest_size=32)
        hasher.update(b"leaf")
        hasher.update(self.uid.encode('utf-8'))
        hasher.update(self.pk_user)
        hasher.update(self.ciphertext.ciphertext)
        hasher.update(self.ciphertext.tag)
        hasher.update(self.randomizer)
        return hash_leaf(hasher.digest())


@dataclass
class OuterLeaf:
    """outer tree leaf: L_outer,uid = H_outer_leaf(uid || R_inner(uid))"""
    uid: str
    inner_root: bytes
    
    def compute_hash(self) -> bytes:
        hasher = blake2b(digest_size=32)
        hasher.update(b"outer_leaf")
        hasher.update(self.uid.encode('utf-8'))
        hasher.update(self.inner_root)
        return hasher.digest()


@dataclass
class QueryMetrics:
    query_id: str
    start_time: float
    predicate_eval_time: float = 0.0
    inner_tree_build_time: float = 0.0
    outer_tree_update_time: float = 0.0
    signature_time: float = 0.0
    shuffle_time: float = 0.0
    total_time: float = 0.0
    num_matching_users: int = 0
    num_total_leaves: int = 0


@dataclass
class ServerResponse:
    query_id: str
    matching_users: List[str]
    user_data: Dict[str, Dict[str, Any]]
    outer_root: bytes
    outer_root_signature: bytes
    outer_paths: Dict[str, MerklePath]
    outer_leaf_signatures: Dict[str, int]  # signature for each outer leaf
    metrics: QueryMetrics


class EncryptedDatabaseServer:
    """server managing encrypted database with merkle commitments."""
    
    def __init__(self, encryption_key: bytes, issuer_keypair: BlindSignatureIssuer, 
                 use_aes: bool = True, attribute_order: Optional[List[str]] = None,
                 schnorr_keypair: Optional[SchnorrKeypair] = None):
        """
        initialize server with encryption and signing keys.
        
        args:
            encryption_key: 32-byte master key
            issuer_keypair: blind signature issuer (legacy, for outer root if needed)
            use_aes: if true, use aes-ecb (cryptdb-style); if false, use legacy hash-based
            attribute_order: ordered list of attribute names (e.g., ["age", "country", "score"])
                             maps attribute names to indices for privacy-preserving queries
            schnorr_keypair: Schnorr keypair for blind signing (generates new if None)
        """
        if use_aes:
            self.enc = DeterministicEncryptionAES(encryption_key)
            self.enc_type = "AES-ECB"
        else:
            self.enc = DeterministicEncryption(encryption_key)
            self.enc_type = "Hash-based"
        
        self.issuer = issuer_keypair
        self.schnorr_issuer = SchnorrIssuer(schnorr_keypair)
        
        # Attribute order: maps names to indices
        # Default: ["age", "country", "score"] if not specified
        self.attribute_order = attribute_order or ["age", "country", "score"]
        self.attr_name_to_index = {name: idx for idx, name in enumerate(self.attribute_order)}
        
        self.db: Dict[str, Dict[str, DeterministicCiphertext]] = {}
        self.user_keys: Dict[str, bytes] = {}
        self.inner_trees: Dict[str, MerkleTree] = {}
        self.outer_tree: Optional[MerkleTree] = None
        self.outer_users: Set[str] = set()
        
        self.query_count = 0
        self.total_queries_served = 0
        self.access_log: List[QueryMetrics] = []
    
    def get_attr_index(self, attr_name: str) -> int:
        """Get attribute index from name."""
        if attr_name not in self.attr_name_to_index:
            raise ValueError(f"Unknown attribute: {attr_name}")
        return self.attr_name_to_index[attr_name]
    
    def load_user(self, uid: str, pk_user: bytes, attributes: Dict[str, str]):
        encrypted_attrs = {}
        for attr_name, plaintext_value in attributes.items():
            plaintext_bytes = plaintext_value.encode('utf-8')
            
            if isinstance(self.enc, DeterministicEncryptionAES):
                ct = self.enc.encrypt(plaintext_bytes, column_name=attr_name)
            else:
                ct = self.enc.encrypt(plaintext_bytes)
            
            encrypted_attrs[attr_name] = ct
        
        self.db[uid] = encrypted_attrs
        self.user_keys[uid] = pk_user
    
    def query(self, predicate_func, query_id: Optional[str] = None) -> ServerResponse:
        """
        Process a query on the encrypted database.
        
        NEW DESIGN: Attribute-agnostic leaf handling.
        - Leaves use attr_index instead of attr_name
        - Shuffling happens BEFORE extracting auth paths
        - No explicit signatures (preparing for blind Schnorr integration)
        """
        if query_id is None:
            query_id = f"query_{self.query_count}"
        self.query_count += 1
        
        metrics = QueryMetrics(query_id=query_id, start_time=time.time())
        query_nonce = secrets.token_bytes(32)  # Fresh nonce for this query
        
        t0 = time.time()
        matching_users = []
        for uid in self.db.keys():
            if predicate_func(uid, self.db[uid]):
                matching_users.append(uid)
        metrics.predicate_eval_time = time.time() - t0
        metrics.num_matching_users = len(matching_users)
        
        if not matching_users:
            metrics.total_time = time.time() - metrics.start_time
            self.access_log.append(metrics)
            return ServerResponse(
                query_id=query_id,
                matching_users=[],
                user_data={},
                outer_root=b"",
                outer_root_signature=b"",
                outer_paths={},
                outer_leaf_signatures={},
                metrics=metrics
            )
        
        t0 = time.time()
        user_data = {}
        total_leaves = 0
        
        #build inner trees with attribute-agnostic leaves
        for uid in matching_users:
            leaves_data = []
            attr_leaves = []
            
            pk_user = self.user_keys[uid]
            
            #process attributes in order (using indices)
            for attr_name in self.attribute_order:
                if attr_name not in self.db[uid]:
                    continue  #skip if user doesn't have this attribute
                
                ct = self.db[uid][attr_name]
                attr_index = self.attr_name_to_index[attr_name]
                randomizer = derive_leaf_randomizer(uid, attr_index)
                
                leaf_obj = AttributeLeaf(
                    uid=uid,
                    pk_user=pk_user,
                    attr_index=attr_index,
                    ciphertext=ct,
                    randomizer=randomizer,
                    attr_name=attr_name  # Keep for internal use only
                )
                leaf_hash = leaf_obj.compute_leaf_hash()
                leaves_data.append(leaf_hash)
                attr_leaves.append((attr_index, leaf_obj, leaf_hash))
            
            inner_tree = MerkleTree(leaves_data)
            total_leaves += len(leaves_data)
            
            user_data[uid] = {
                'inner_tree': inner_tree,
                'attr_leaves': attr_leaves
            }
        
        metrics.inner_tree_build_time = time.time() - t0
        metrics.num_total_leaves = total_leaves
        
        # Shuffle inner trees BEFORE extracting auth paths
        # This prevents linking leaf positions to attribute semantics
        t0 = time.time()
        for uid in matching_users:
            user_data[uid]['inner_tree'] = user_data[uid]['inner_tree'].shuffle_and_rebuild()
            # Update the tree reference
            self.inner_trees[uid] = user_data[uid]['inner_tree']
        metrics.shuffle_time = time.time() - t0
        
        # Build outer tree
        t0 = time.time()
        self.outer_users.update(matching_users)
        outer_leaves = []
        outer_leaf_map = {}
        
        for uid in sorted(self.outer_users):
            if uid in self.inner_trees:
                inner_root = self.inner_trees[uid].root
                outer_leaf_obj = OuterLeaf(uid=uid, inner_root=inner_root)
                outer_hash = outer_leaf_obj.compute_hash()
                outer_leaves.append(outer_hash)
                outer_leaf_map[uid] = outer_hash
        
        self.outer_tree = MerkleTree(outer_leaves)
        metrics.outer_tree_update_time = time.time() - t0
        
        # Extract auth paths AFTER shuffling
        # Sign all leaves with Schnorr signatures
        t0 = time.time()
        for uid in matching_users:
            attr_leaves = user_data[uid]['attr_leaves']
            attr_data_dict = {}
            
            for attr_index, leaf_obj, leaf_hash in attr_leaves:
                inner_tree = user_data[uid]['inner_tree']
                inner_path = inner_tree.get_auth_path(leaf_hash)
                
                # Compute message for Schnorr signing (attribute-agnostic)
                leaf_message = compute_leaf_message_for_signing(
                    leaf_obj.ciphertext,
                    query_nonce,
                    leaf_obj.randomizer
                )
                
                # Actually sign with Schnorr (non-blind for now)
                # In full protocol, client would blind this first
                schnorr_sig = self.schnorr_issuer.sign_message(leaf_message)
                
                # Store by index (not name!)
                attr_data_dict[attr_index] = {
                    'ciphertext': leaf_obj.ciphertext,
                    'leaf_hash': leaf_hash,
                    'inner_path': inner_path,
                    'leaf_message': leaf_message,
                    'schnorr_signature': schnorr_sig,
                    'attr_index': attr_index,
                    # For demo/debug only - would be removed in production:
                    'attr_name': leaf_obj.attr_name
                }
            
            user_data[uid]['attr_data'] = attr_data_dict
        
        metrics.signature_time = time.time() - t0
        
        # Outer tree root signature (using legacy RSA for now)
        outer_root_bytes = self.outer_tree.root
        outer_root_int = int.from_bytes(outer_root_bytes, 'big')
        outer_root_sig = self.issuer.sign_message(outer_root_int)
        
        # Get outer paths
        outer_paths = {}
        outer_leaf_signatures = {}
        for uid in matching_users:
            outer_leaf = outer_leaf_map[uid]
            outer_path = self.outer_tree.get_auth_path(outer_leaf)
            outer_paths[uid] = outer_path
            
            # Outer leaf signature (legacy RSA)
            outer_leaf_int = int.from_bytes(outer_leaf, 'big')
            outer_leaf_sig = self.issuer.sign_message(outer_leaf_int)
            outer_leaf_signatures[uid] = outer_leaf_sig
        
        # Shuffle outer tree
        if self.outer_tree:
            self.outer_tree = self.outer_tree.shuffle_and_rebuild()
        
        metrics.total_time = time.time() - metrics.start_time
        self.access_log.append(metrics)
        self.total_queries_served += 1
        
        response_user_data = {}
        for uid in matching_users:
            response_user_data[uid] = user_data[uid]['attr_data']
        
        return ServerResponse(
            query_id=query_id,
            matching_users=matching_users,
            user_data=response_user_data,
            outer_root=outer_root_bytes,
            outer_root_signature=outer_root_sig,
            outer_paths=outer_paths,
            outer_leaf_signatures=outer_leaf_signatures,
            metrics=metrics
        )
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        if not self.access_log:
            return {}
        
        total_times = [m.total_time for m in self.access_log]
        pred_times = [m.predicate_eval_time for m in self.access_log]
        inner_times = [m.inner_tree_build_time for m in self.access_log]
        outer_times = [m.outer_tree_update_time for m in self.access_log]
        sig_times = [m.signature_time for m in self.access_log]
        shuffle_times = [m.shuffle_time for m in self.access_log]
        
        return {
            'total_queries': len(self.access_log),
            'avg_total_time': sum(total_times) / len(total_times),
            'avg_predicate_time': sum(pred_times) / len(pred_times),
            'avg_inner_tree_time': sum(inner_times) / len(inner_times),
            'avg_outer_tree_time': sum(outer_times) / len(outer_times),
            'avg_signature_time': sum(sig_times) / len(sig_times),
            'avg_shuffle_time': sum(shuffle_times) / len(shuffle_times),
            'total_users_in_db': len(self.db),
            'total_users_in_outer_tree': len(self.outer_users)
        }


@dataclass
class ClientProofRequest:
    """
    Client proof request (attribute-agnostic design).
    
    Uses attr_index instead of attr_name to hide attribute semantics.
    """
    uid: str
    attr_index: int  # Attribute position (not semantic name)
    attr_value: str  # Decrypted value
    inner_path: MerklePath
    outer_path: MerklePath
    outer_root: bytes
    leaf_message: bytes  # Message for Schnorr verification
    schnorr_signature: 'SchnorrSignature'  # Schnorr signature on leaf message
    proof_data: Dict[str, Any]
    
    # For demo/debug only (would be removed in production):
    attr_name: Optional[str] = None


class EncryptedDatabaseClient:
    """client that queries encrypted db and generates zk proofs."""
    
    def __init__(self, uid: str, sk_user: bytes, pk_user: bytes, 
                 decryption_key: bytes, use_aes: bool = True,
                 attribute_order: Optional[List[str]] = None):
        """
        initialize client with keys.
        
        args:
            uid: user identifier
            sk_user: user's secret key
            pk_user: user's public key
            decryption_key: master key for decrypting attributes
            use_aes: if true, use aes-ecb; if false, use legacy hash-based
            attribute_order: must match server's attribute order for index lookups
        """
        self.uid = uid
        self.sk_user = sk_user
        self.pk_user = pk_user
        
        if use_aes:
            self.enc = DeterministicEncryptionAES(decryption_key)
        else:
            self.enc = DeterministicEncryption(decryption_key)
        
        # Attribute order (must match server!)
        self.attribute_order = attribute_order or ["age", "country", "score"]
        self.attr_name_to_index = {name: idx for idx, name in enumerate(self.attribute_order)}
        
        self.plaintext_attrs: Dict[str, str] = {}
    
    def get_attr_index(self, attr_name: str) -> int:
        """Get attribute index from name."""
        if attr_name not in self.attr_name_to_index:
            raise ValueError(f"Unknown attribute: {attr_name}")
        return self.attr_name_to_index[attr_name]
    
    def decrypt_attribute(self, ciphertext: DeterministicCiphertext, 
                         attr_name: str) -> str:
        """decrypt an attribute value."""
        if isinstance(self.enc, DeterministicEncryptionAES):
            plaintext_bytes = self.enc.decrypt(ciphertext, column_name=attr_name)
        else:
            raise NotImplementedError("hash-based encryption doesn't support direct decryption")
        
        return plaintext_bytes.decode('utf-8')
    
    def query_and_prove(self, server: EncryptedDatabaseServer, 
                       predicate_func, 
                       attr_name: str,
                       verifier_predicate=None) -> Optional[ClientProofRequest]:
        """
        Query server and generate proof for a specific attribute.
        
        Args:
            server: Database server
            predicate_func: Predicate function for filtering users
            attr_name: Attribute name (will be converted to index)
            verifier_predicate: Optional predicate for verifier (unused in current impl)
        
        Returns:
            Proof request or None if user didn't match
        """
        response = server.query(predicate_func)
        
        if self.uid not in response.matching_users:
            return None
        
        our_data = response.user_data[self.uid]
        
        # Convert attr_name to index
        attr_index = self.get_attr_index(attr_name)
        
        if attr_index not in our_data:
            return None
        
        attr_data = our_data[attr_index]
        ciphertext = attr_data['ciphertext']
        
        try:
            decrypted_value = self.decrypt_attribute(ciphertext, attr_name)
        except:
            decrypted_value = "<encrypted>"
        
        proof_request = ClientProofRequest(
            uid=self.uid,
            attr_index=attr_index,
            attr_value=decrypted_value,
            inner_path=attr_data['inner_path'],
            outer_path=response.outer_paths[self.uid],
            outer_root=response.outer_root,
            leaf_message=attr_data['leaf_message'],
            schnorr_signature=attr_data['schnorr_signature'],
            proof_data={
                'leaf_hash': attr_data['leaf_hash'].hex(),
                'inner_root': attr_data['inner_path'].root.hex(),
                'outer_root': response.outer_root.hex()
            },
            attr_name=attr_name  # For demo/debug only
        )
        
        return proof_request


class EncryptedDatabaseVerifier:
    """
    Verifier that checks ZK proofs against public merkle roots.
    
    NEW DESIGN: Attribute-agnostic verification.
    - Verifies Schnorr signatures on leaf messages (optional for testing)
    - Verifies Merkle path consistency
    - In production: Schnorr verification would happen inside ZK circuit
    """
    
    def __init__(self, schnorr_pk=None, issuer: Optional[BlindSignatureIssuer] = None,
                 verify_schnorr: bool = False):
        """
        initialize verifier.
        
        args:
            schnorr_pk: Schnorr public key (Point) for signature verification
            issuer: Optional blind signature issuer (legacy, may be removed)
            verify_schnorr: If True, verify Schnorr signatures in cleartext (for testing)
        """
        self.schnorr_pk = schnorr_pk
        self.issuer = issuer
        self.verify_schnorr = verify_schnorr
        self.known_roots: Set[bytes] = set()
    
    def register_root(self, root: bytes):
        """Register a known outer root."""
        self.known_roots.add(root)
    
    def verify_proof(self, proof: ClientProofRequest) -> bool:
        """
        Verify proof of attribute membership.
        
        Checks:
        1. Outer root is known (registered by verifier)
        2. Inner Merkle path is valid
        3. Outer Merkle path is valid
        4. (Optional) Schnorr signature is valid
        
        NOTE: In production, Schnorr signature verification would happen
        inside a ZK circuit, not in cleartext here.
        """
        # check 1: outer root is registered
        if proof.outer_root not in self.known_roots:
            print(f"unknown outer root")
            return False
        
        # check 2: verify inner merkle path (attribute leaf → inner root)
        if not self._verify_merkle_path(proof.inner_path):
            print(f"invalid inner merkle path")
            return False
        
        # check 3: verify outer merkle path (user leaf → outer root)
        if not self._verify_merkle_path(proof.outer_path):
            print(f"invalid outer merkle path")
            return False
        
        # check 4: optionally verify Schnorr signature (for testing)
        if self.verify_schnorr and self.schnorr_pk:
            from zkid.schnorr import verify
            if not verify(self.schnorr_pk, proof.leaf_message, proof.schnorr_signature):
                print(f"invalid Schnorr signature on leaf message")
                return False
        
        # Display results (using attr_name for demo only; in production would not have this)
        attr_display = f"index {proof.attr_index}"
        if proof.attr_name:
            attr_display = f"{proof.attr_name} (index {proof.attr_index})"
        
        print(f"proof verified for user {proof.uid}, attribute {attr_display}")
        print(f"  ✓ outer root registered")
        print(f"  ✓ inner merkle path valid")
        print(f"  ✓ outer merkle path valid")
        if self.verify_schnorr:
            print(f"  ✓ schnorr signature valid")
        print(f"  ✓ attribute value: {proof.attr_value}")
        return True
    
    def _verify_merkle_path(self, path: MerklePath) -> bool:
        """Verify a Merkle authentication path."""
        current = path.leaf_hash
        
        for sibling, is_right in path.sibling_hashes:
            if is_right:
                current = hash_internal(current, sibling)
            else:
                current = hash_internal(sibling, current)
        
        return current == path.root

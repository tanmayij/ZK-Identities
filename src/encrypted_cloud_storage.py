"""
encrypted cloud storage with zkp proof generation

this implements a client-server model where:
- client: hospital/organization holding encryption keys
- server: untrusted cloud storage (malicious, curious)
- client queries cloud for encrypted bundles
- client decrypts and generates proofs locally
"""

import json
import secrets
from pathlib import Path
from cryptography.fernet import Fernet
import pandas as pd


class EncryptedCloudStorage:
    """
    untrusted cloud storage for credential bundles
    
    cloud can:
    - store encrypted data
    - see access patterns
    
    cloud cannot:
    - decrypt data
    - learn user attributes
    - forge proofs
    """
    
    def __init__(self, storage_dir="cloud_storage"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self.access_log = []  # cloud logs all accesses
        # simple ppe-style equality index: (attr_name, ppe_value) -> list of bundle_ids
        self.ppe_index = {}
    
    def store_encrypted_bundle(self, bundle_id, encrypted_data):
        """store encrypted bundle (cloud operation)"""
        storage_path = self.storage_dir / f"{bundle_id}.enc"
        with open(storage_path, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"[cloud] stored bundle {bundle_id} ({len(encrypted_data)} bytes)")
        return str(storage_path)
    
    def retrieve_encrypted_bundle(self, bundle_id):
        """retrieve encrypted bundle (cloud operation)"""
        import time
        self.access_log.append({
            'bundle_id': bundle_id,
            'timestamp': time.time()
        })
        
        storage_path = self.storage_dir / f"{bundle_id}.enc"
        with open(storage_path, 'rb') as f:
            data = f.read()
        
        print(f"[cloud] retrieved bundle {bundle_id} (access logged)")
        return data

    def register_ppe_tag(self, bundle_id, attr_name, ppe_value):
        """register a deterministic ppe tag for equality queries

        the client can call this after decrypting a bundle and
        computing a deterministic encryption or hash of a specific
        attribute. the cloud never sees the plaintext value, only
        the opaque ppe_value that is stable for equality checks.
        """

        key = (attr_name, ppe_value)
        ids = self.ppe_index.get(key)
        if ids is None:
            ids = []
            self.ppe_index[key] = ids
        if bundle_id not in ids:
            ids.append(bundle_id)

    def query_by_ppe_tag(self, attr_name, ppe_value):
        """return bundle_ids matching an equality-style ppe tag

        this models a cryptdb-style query of the form
        select * from t where attr_ppe = Enc_det(value)
        but at the level of bundle identifiers rather than full
        sql rows. for this demo we only use it as a building block
        for thinking about ppe-backed queries.
        """

        key = (attr_name, ppe_value)
        return list(self.ppe_index.get(key, []))
    
    def get_access_pattern_summary(self):
        """what cloud learned from access patterns"""
        from collections import Counter
        access_counts = Counter(log['bundle_id'] for log in self.access_log)
        return {
            'total_accesses': len(self.access_log),
            'unique_bundles': len(access_counts),
            'most_accessed': access_counts.most_common(5)
        }


class ClientEncryptionLayer:
    """client-side encryption and index management"""
    
    def __init__(self, master_key=None):
        if master_key is None:
            self.master_key = Fernet.generate_key()
        else:
            self.master_key = master_key
        
        self.cipher = Fernet(self.master_key)
        self.index = {}  # real_user_id -> bundle_id mapping
    
    def save_master_key(self, key_path="client_keys/master.key"):
        """save master key (client keeps this secret)"""
        Path(key_path).parent.mkdir(exist_ok=True)
        with open(key_path, 'wb') as f:
            f.write(self.master_key)
        print(f"[client] master key saved (keep secret!)")
    
    @staticmethod
    def load_master_key(key_path="client_keys/master.key"):
        """load master key"""
        with open(key_path, 'rb') as f:
            return f.read()
    
    def generate_obfuscated_id(self, user_id):
        """generate obfuscated bundle id from real user id"""
        import hashlib
        h = hashlib.sha256(f"bundle_{user_id}".encode()).hexdigest()
        return h[:16]
    
    def encrypt_bundle(self, user_id, bundle_data):
        """encrypt user bundle before uploading to cloud"""
        bundle_id = self.generate_obfuscated_id(user_id)
        
        bundle_json = json.dumps(bundle_data).encode('utf-8')
        encrypted_data = self.cipher.encrypt(bundle_json)
        
        self.index[str(user_id)] = bundle_id
        
        return bundle_id, encrypted_data
    
    def decrypt_bundle(self, encrypted_data):
        """decrypt bundle retrieved from cloud"""
        decrypted_json = self.cipher.decrypt(encrypted_data)
        return json.loads(decrypted_json)
    
    def save_index(self, index_path="client_keys/index.json"):
        """save index (client keeps this secret)"""
        Path(index_path).parent.mkdir(exist_ok=True)
        with open(index_path, 'w') as f:
            json.dump(self.index, f, indent=2)
        print(f"[client] index saved with {len(self.index)} entries")
    
    def load_index(self, index_path="client_keys/index.json"):
        """load index"""
        with open(index_path, 'r') as f:
            self.index = json.load(f)


class Client:
    """client that uses encrypted cloud storage"""
    
    def __init__(self, master_key=None):
        self.encryption = ClientEncryptionLayer(master_key)
        self.cloud = EncryptedCloudStorage()
    
    def upload_user_bundle(self, user_id, bundle_path):
        """upload user bundle to cloud (encrypted)"""
        with open(bundle_path, 'r') as f:
            bundle_data = json.load(f)
        
        bundle_id, encrypted_data = self.encryption.encrypt_bundle(
            user_id, bundle_data
        )
        
        self.cloud.store_encrypted_bundle(bundle_id, encrypted_data)
        
        print(f"[client] uploaded user {user_id} as bundle {bundle_id}")
        return bundle_id
    
    def query_user_bundle(self, user_id):
        """query cloud for user bundle"""
        bundle_id = self.encryption.index.get(str(user_id))
        if not bundle_id:
            raise ValueError(f"user {user_id} not in index")
        
        print(f"[client] querying cloud for user {user_id}...")
        encrypted_data = self.cloud.retrieve_encrypted_bundle(bundle_id)
        
        print(f"[client] decrypting locally...")
        bundle = self.encryption.decrypt_bundle(encrypted_data)
        
        return bundle
    
    def generate_proof_for_user(self, user_id, predicates):
        """generate zk proof for user"""
        import sys
        sys.path.append(str(Path(__file__).parent))
        from zkid.prover import generate_proof
        
        bundle = self.query_user_bundle(user_id)
        
        temp_bundle_path = Path(f"temp_bundles/{user_id}.json")
        temp_bundle_path.parent.mkdir(exist_ok=True)
        with open(temp_bundle_path, 'w') as f:
            json.dump(bundle, f, indent=2)
        
        print(f"[client] generating zk proof locally...")
        proof = generate_proof(user_id, predicates, 
                              bundles_dir="temp_bundles")
        
        temp_bundle_path.unlink()
        
        return proof


if __name__ == "__main__":
    print("\nencrypted cloud storage demonstration")
    print("=" * 60)
    
    # setup client
    print("\n[setup] initializing client...")
    client = Client()
    client.encryption.save_master_key()
    
    # upload some user bundles to cloud (encrypted)
    print("\n[phase 1] uploading encrypted bundles to cloud...")
    print("-" * 60)
    for user_id in [1, 123, 456, 789]:
        original_bundle = f"artifacts/user_bundles/{user_id}.json"
        if Path(original_bundle).exists():
            bundle_id = client.upload_user_bundle(user_id, original_bundle)
    
    client.encryption.save_index()
    
    # simulate client querying for user
    print("\n[phase 2] client needs to verify user 123...")
    print("-" * 60)
    bundle = client.query_user_bundle(123)
    print(f"[client] retrieved bundle for user {bundle['user_id']}")
    print(f"[client] bundle has {len(bundle['attributes'])} attributes")
    
    # generate proof
    print("\n[phase 3] generating zk proof for verification...")
    print("-" * 60)
    predicates = [
        {"type": "range", "attribute": "Date_of_Birth", "threshold": 18},
        {"type": "equality", "attribute": "Citizenship", "value": "Germany"}
    ]
    proof = client.generate_proof_for_user(123, predicates)
    print(f"[client] proof generated with {len(proof['predicates'])} predicates")
    
    # query again (simulate repeated access)
    print("\n[phase 4] client queries user 123 again...")
    print("-" * 60)
    bundle2 = client.query_user_bundle(123)
    print(f"[client] retrieved bundle again")
    
    # show what cloud learned
    print("\n" + "=" * 60)
    print("privacy analysis")
    print("=" * 60)
    
    summary = client.cloud.get_access_pattern_summary()
    print("\nwhat cloud learned (access patterns):")
    print(f"  - total accesses: {summary['total_accesses']}")
    print(f"  - unique bundles accessed: {summary['unique_bundles']}")
    print(f"  - most accessed bundles:")
    for bundle_id, count in summary['most_accessed']:
        print(f"      {bundle_id}: {count} times")
    
    print("\nwhat cloud did NOT learn:")
    print("  - actual user ids (1, 123, 456, 789)")
    print("  - user attributes (name, citizenship, dob, etc)")
    print("  - which predicates were proven")
    print("  - proof content or verification results")
    print("  - encryption keys")
    
    print("\naccess pattern leakage:")
    print("  - cloud knows one bundle was accessed twice")
    print("  - cloud can correlate: likely same patient")
    print("  - to fix: use ORAM or add dummy queries")
    
    print("\n" + "=" * 60)

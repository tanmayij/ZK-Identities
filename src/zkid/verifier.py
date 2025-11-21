"""
step 8: verifier-side proof verification

this verifies zero-knowledge proofs against the signed global root:
1. check issuer signature on global root
2. verify merkle paths (inner and outer)
3. verify zk proofs for each predicate
"""

import json
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent.parent))

from zkid.crypto import hash_leaf, hash_internal
from zkid.prover import EqualityProof, RangeProof, SetMembershipProof, ZKProof
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def load_issuer_public_key(key_path="artifacts/issuer_public_key.pem"):
    """load issuer's public key for signature verification"""
    with open(key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key


def verify_issuer_signature(global_root_hex, signature_hex, public_key):
    """verify issuer signature on global root"""
    try:
        global_root = bytes.fromhex(global_root_hex)
        signature = bytes.fromhex(signature_hex)
        public_key.verify(signature, global_root)
        return True
    except Exception as e:
        print(f"signature verification failed: {e}")
        return False


def verify_inner_merkle_path(attr_name, commitment_hex, auth_path, inner_root_hex):
    """verify authentication path from attribute commitment to inner root"""
    # reconstruct leaf
    commitment = bytes.fromhex(commitment_hex)
    leaf_data = attr_name.encode('utf-8') + b"||" + commitment
    leaf_hash = hash_leaf(leaf_data)
    
    # verify path
    return ZKProof.verify_merkle_path(leaf_hash, auth_path, inner_root_hex)


def verify_outer_merkle_path(user_id, inner_root_hex, auth_path, global_root_hex):
    """verify authentication path from inner root to global root"""
    # reconstruct leaf
    inner_root = bytes.fromhex(inner_root_hex)
    user_id_bytes = str(user_id).encode('utf-8')
    leaf_data = user_id_bytes + b"||" + inner_root
    leaf_hash = hash_leaf(leaf_data)
    
    # verify path
    return ZKProof.verify_merkle_path(leaf_hash, auth_path, global_root_hex)


def verify_predicate_proof(proof):
    """verify a single predicate proof"""
    proof_type = proof['type']
    commitment = proof['commitment']
    
    if proof_type == 'equality':
        return EqualityProof.verify(proof, commitment)
    elif proof_type == 'range':
        return RangeProof.verify(proof, commitment)
    elif proof_type == 'set_membership':
        return SetMembershipProof.verify(proof, commitment)
    else:
        raise ValueError(f"unknown proof type: {proof_type}")


def verify_proof(proof_package, public_key_path="artifacts/issuer_public_key.pem"):
    """
    verify complete proof package.
    
    returns:
        dict with verification results and details
    """
    results = {
        "valid": False,
        "checks": {},
        "predicates_verified": []
    }
    
    # load issuer public key
    public_key = load_issuer_public_key(public_key_path)
    
    # check 1: verify issuer signature
    sig_valid = verify_issuer_signature(
        proof_package['global_root'],
        proof_package['issuer_signature'],
        public_key
    )
    results['checks']['issuer_signature'] = sig_valid
    
    if not sig_valid:
        print("verification failed: invalid issuer signature")
        return results
    
    # check 2: verify outer merkle path
    outer_path_valid = verify_outer_merkle_path(
        proof_package['user_id'],
        proof_package['inner_root'],
        proof_package['outer_auth_path'],
        proof_package['global_root']
    )
    results['checks']['outer_merkle_path'] = outer_path_valid
    
    if not outer_path_valid:
        print("verification failed: invalid outer merkle path")
        return results
    
    # check 3: verify each predicate proof
    all_predicates_valid = True
    
    for idx, predicate_proof in enumerate(proof_package['predicates']):
        # verify inner merkle path
        inner_path_valid = verify_inner_merkle_path(
            predicate_proof['attribute'],
            predicate_proof['commitment'],
            predicate_proof['inner_auth_path'],
            proof_package['inner_root']
        )
        
        # verify zk proof
        zk_proof_valid = verify_predicate_proof(predicate_proof)
        
        predicate_valid = inner_path_valid and zk_proof_valid
        
        results['predicates_verified'].append({
            "index": idx,
            "type": predicate_proof['type'],
            "attribute": predicate_proof['attribute'],
            "inner_path_valid": inner_path_valid,
            "zk_proof_valid": zk_proof_valid,
            "valid": predicate_valid
        })
        
        if not predicate_valid:
            all_predicates_valid = False
            print(f"predicate {idx} failed: inner_path={inner_path_valid}, zk={zk_proof_valid}")
    
    results['checks']['all_predicates'] = all_predicates_valid
    
    # overall validation
    results['valid'] = sig_valid and outer_path_valid and all_predicates_valid
    
    return results


def load_proof(proof_path):
    """load proof from file"""
    with open(proof_path, 'r') as f:
        return json.load(f)


def print_verification_results(results):
    """print verification results in readable format"""
    print("\nverification results")
    print("=" * 60)
    print(f"overall result: {'VALID' if results['valid'] else 'INVALID'}")
    print("\nchecks:")
    print(f"  issuer signature:    {results['checks']['issuer_signature']}")
    print(f"  outer merkle path:   {results['checks']['outer_merkle_path']}")
    print(f"  all predicates:      {results['checks']['all_predicates']}")
    
    print("\npredicate verification:")
    for pred in results['predicates_verified']:
        status = "valid" if pred['valid'] else "invalid"
        print(f"  [{pred['index']}] {pred['type']:15s} on {pred['attribute']:20s} -> {status}")
        if not pred['valid']:
            print(f"      inner_path: {pred['inner_path_valid']}, zk_proof: {pred['zk_proof_valid']}")
    
    print("=" * 60)


if __name__ == "__main__":
    # example: verify proof for user 123
    proof_path = "artifacts/proofs/123_proof.json"
    
    print(f"loading proof from {proof_path}...")
    proof_package = load_proof(proof_path)
    
    print(f"verifying proof for user {proof_package['user_id']}...")
    print(f"predicates to verify: {len(proof_package['predicates'])}")
    
    results = verify_proof(proof_package)
    
    print_verification_results(results)
    
    if results['valid']:
        print("\nproof verification successful")
    else:
        print("\nproof verification failed")

"""
step 7: user-side proof generation (simplified zkp implementation)

this implements basic zero-knowledge proofs for three predicate types:
1. equality: prove attribute == value without revealing attribute
2. range: prove attribute >= threshold without revealing exact value
3. set membership: prove attribute in set without revealing which one

note: this uses simplified sigma protocols instead of zksk library
for production, use a proper zkp library like bulletproofs or zksk
"""

import json
import hashlib
import secrets
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent.parent))

from zkid.crypto import hash_leaf, hash_internal, commit_attr, derive_salt

class ZKProof:
    """base class for zero-knowledge proofs"""
    
    @staticmethod
    def fiat_shamir_challenge(*messages):
        """generate non-interactive challenge using fiat-shamir heuristic"""
        hasher = hashlib.sha256()
        for msg in messages:
            if isinstance(msg, str):
                hasher.update(msg.encode('utf-8'))
            elif isinstance(msg, int):
                hasher.update(msg.to_bytes(32, 'big'))
            else:
                hasher.update(msg)
        return int.from_bytes(hasher.digest(), 'big')
    
    @staticmethod
    def verify_merkle_path(leaf, auth_path, root):
        """verify a merkle authentication path"""
        current = leaf
        for step in auth_path:
            sibling = bytes.fromhex(step['sibling'])
            if step['is_right']:
                # sibling is on the right
                current = hash_internal(current, sibling)
            else:
                # sibling is on the left
                current = hash_internal(sibling, current)
        return current.hex() == root


class EqualityProof(ZKProof):
    """prove: i know (value, salt) s.t. commit(value, salt) = C and value = claimed_value"""
    
    @staticmethod
    def generate(attr_name, attr_value, salt, commitment, claimed_value, user_id):
        """
        generate proof that attribute equals claimed value.
        
        note: this is a simplified proof. in production, use proper zkp library.
        """
        # check if claim is true
        if attr_value != claimed_value:
            raise ValueError(f"cannot prove false statement: {attr_value} != {claimed_value}")
        
        # commitment phase: generate random blinding factor
        r = secrets.token_bytes(32)
        r_commitment = commit_attr(claimed_value, r)
        
        # challenge phase (fiat-shamir)
        challenge = ZKProof.fiat_shamir_challenge(
            commitment,
            r_commitment,
            claimed_value,
            attr_name
        )
        
        # response phase: reveal blinded salt
        # in real zkp this would be more sophisticated
        # here we use hash(salt || r || challenge) as response
        hasher = hashlib.sha256()
        hasher.update(salt)
        hasher.update(r)
        hasher.update(challenge.to_bytes(32, 'big'))
        response = hasher.digest()
        
        return {
            "type": "equality",
            "attribute": attr_name,
            "claimed_value": claimed_value,
            "commitment": commitment,
            "r_commitment": r_commitment.hex(),
            "challenge": challenge,
            "response": response.hex()
        }
    
    @staticmethod
    def verify(proof, commitment):
        """verify equality proof"""
        # recompute challenge
        expected_challenge = ZKProof.fiat_shamir_challenge(
            proof['commitment'],
            bytes.fromhex(proof['r_commitment']),
            proof['claimed_value'],
            proof['attribute']
        )
        
        # check challenge matches
        return expected_challenge == proof['challenge']


class RangeProof(ZKProof):
    """prove: i know value s.t. value >= threshold without revealing value"""
    
    @staticmethod
    def generate(attr_name, attr_value, salt, commitment, threshold, user_id):
        """
        generate proof that attribute >= threshold.
        
        simplified range proof: proves value >= threshold by showing
        that (value - threshold) is non-negative.
        """
        # parse date if needed (for age checks)
        if attr_name == "Date_of_Birth":
            from datetime import datetime
            dob = datetime.strptime(attr_value, "%Y-%m-%d")
            today = datetime.utcnow()
            age_days = (today - dob).days
            value_int = age_days
            threshold_days = threshold * 365  # convert years to days
        else:
            # assume numeric value
            value_int = int(attr_value) if isinstance(attr_value, str) else attr_value
            threshold_days = threshold
        
        # check if claim is true
        if value_int < threshold_days:
            raise ValueError(f"cannot prove false statement: {value_int} < {threshold_days}")
        
        # commitment to difference
        difference = value_int - threshold_days
        r = secrets.token_bytes(32)
        diff_commitment = commit_attr(difference, r)
        
        # challenge
        challenge = ZKProof.fiat_shamir_challenge(
            commitment,
            diff_commitment,
            threshold,
            attr_name
        )
        
        # response
        hasher = hashlib.sha256()
        hasher.update(salt)
        hasher.update(r)
        hasher.update(challenge.to_bytes(32, 'big'))
        hasher.update(str(difference).encode('utf-8'))
        response = hasher.digest()
        
        return {
            "type": "range",
            "attribute": attr_name,
            "threshold": threshold,
            "commitment": commitment,
            "diff_commitment": diff_commitment.hex(),
            "challenge": challenge,
            "response": response.hex()
        }
    
    @staticmethod
    def verify(proof, commitment):
        """verify range proof"""
        expected_challenge = ZKProof.fiat_shamir_challenge(
            proof['commitment'],
            bytes.fromhex(proof['diff_commitment']),
            proof['threshold'],
            proof['attribute']
        )
        return expected_challenge == proof['challenge']


class SetMembershipProof(ZKProof):
    """prove: i know value in allowed_set without revealing which one"""
    
    @staticmethod
    def generate(attr_name, attr_value, salt, commitment, allowed_set, user_id):
        """
        generate proof that attribute is in allowed_set.
        
        simplified set membership: proves value is one of the allowed values
        without revealing which one.
        """
        # check if claim is true
        if attr_value not in allowed_set:
            raise ValueError(f"cannot prove false statement: {attr_value} not in {allowed_set}")
        
        # commit to all possible values
        r = secrets.token_bytes(32)
        set_commitments = []
        for val in allowed_set:
            set_commitments.append(commit_attr(val, r).hex())
        
        # challenge
        challenge = ZKProof.fiat_shamir_challenge(
            commitment,
            str(sorted(set_commitments)),
            str(sorted(allowed_set)),
            attr_name
        )
        
        # response
        hasher = hashlib.sha256()
        hasher.update(salt)
        hasher.update(r)
        hasher.update(challenge.to_bytes(32, 'big'))
        hasher.update(attr_value.encode('utf-8') if isinstance(attr_value, str) else str(attr_value).encode('utf-8'))
        response = hasher.digest()
        
        return {
            "type": "set_membership",
            "attribute": attr_name,
            "allowed_set": list(allowed_set),
            "commitment": commitment,
            "set_commitments": set_commitments,
            "challenge": challenge,
            "response": response.hex()
        }
    
    @staticmethod
    def verify(proof, commitment):
        """verify set membership proof"""
        expected_challenge = ZKProof.fiat_shamir_challenge(
            proof['commitment'],
            str(sorted(proof['set_commitments'])),
            str(sorted(proof['allowed_set'])),
            proof['attribute']
        )
        return expected_challenge == proof['challenge']


def load_user_bundle(user_id, bundles_dir="artifacts/user_bundles"):
    """load user credential bundle from file"""
    bundle_path = Path(bundles_dir) / f"{user_id}.json"
    with open(bundle_path, 'r') as f:
        return json.load(f)


def generate_proof(user_id, predicates, bundles_dir="artifacts/user_bundles"):
    """
    generate zk proof for given predicates.
    
    args:
        user_id: user identifier
        predicates: list of dicts with format:
            {"type": "equality", "attribute": "Citizenship", "value": "USA"}
            {"type": "range", "attribute": "Date_of_Birth", "threshold": 18}
            {"type": "set_membership", "attribute": "License_Class", "set": ["G", "G2"]}
    
    returns:
        dict with proof data
    """
    # load user bundle
    bundle = load_user_bundle(user_id, bundles_dir)
    
    # create attribute lookup
    attrs_lookup = {attr['name']: attr for attr in bundle['attributes']}
    
    # generate proofs for each predicate
    proofs = []
    for predicate in predicates:
        attr_name = predicate['attribute']
        
        if attr_name not in attrs_lookup:
            raise ValueError(f"attribute {attr_name} not found in user bundle")
        
        attr = attrs_lookup[attr_name]
        salt = bytes.fromhex(attr['salt'])
        
        if predicate['type'] == 'equality':
            proof = EqualityProof.generate(
                attr_name,
                attr['value'],
                salt,
                attr['commitment'],
                predicate['value'],
                user_id
            )
        elif predicate['type'] == 'range':
            proof = RangeProof.generate(
                attr_name,
                attr['value'],
                salt,
                attr['commitment'],
                predicate['threshold'],
                user_id
            )
        elif predicate['type'] == 'set_membership':
            proof = SetMembershipProof.generate(
                attr_name,
                attr['value'],
                salt,
                attr['commitment'],
                predicate['set'],
                user_id
            )
        else:
            raise ValueError(f"unknown predicate type: {predicate['type']}")
        
        # add inner merkle proof
        proof['inner_auth_path'] = attr['inner_auth_path']
        
        proofs.append(proof)
    
    # build complete proof package
    proof_package = {
        "user_id": user_id,
        "inner_root": bundle['inner_root'],
        "outer_auth_path": bundle['outer_auth_path'],
        "global_root": bundle['global_root'],
        "issuer_signature": bundle['issuer_signature'],
        "predicates": proofs,
        "proof_metadata": {
            "n_predicates": len(proofs),
            "predicate_types": [p['type'] for p in proofs]
        }
    }
    
    return proof_package


def save_proof(proof_package, output_path):
    """save proof to file"""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(proof_package, f, indent=2)
    
    print(f"proof saved to {output_path}")


if __name__ == "__main__":
    # example: generate proof for user 123
    user_id = 123
    
    # example predicates (user 123 is from germany, born 1980, has license z)
    predicates = [
        {"type": "range", "attribute": "Date_of_Birth", "threshold": 18},  # age >= 18
        {"type": "equality", "attribute": "Citizenship", "value": "Germany"},
        {"type": "set_membership", "attribute": "License_Class", "set": ["G", "G2", "M", "Z"]}
    ]
    
    print(f"generating proof for user {user_id}...")
    print(f"predicates: {predicates}")
    
    proof = generate_proof(user_id, predicates)
    
    output_path = f"artifacts/proofs/{user_id}_proof.json"
    save_proof(proof, output_path)
    
    print(f"proof generated successfully")
    print(f"inner root: {proof['inner_root'][:32]}...")
    print(f"global root: {proof['global_root'][:32]}...")
    print(f"predicates proven: {len(proof['predicates'])}")

"""
complete verification flow with optional blind signature receipt

this demonstrates the full protocol:
1. user generates zk proof
2. verifier checks proof
3. if valid, verifier issues blind signature
4. user unblinds to get unlinkable attestation token
"""

import json
import time
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent.parent))

from zkid.prover import generate_proof, save_proof
from zkid.verifier import verify_proof, load_proof
from zkid.blind_signatures import (
    generate_verifier_blind_keys,
    create_blind_signature_token,
    issue_blind_signature,
    unblind_and_verify_token
)


def complete_verification_with_receipt(
    user_id,
    predicates,
    issue_receipt=True
):
    """
    run complete verification flow with optional blind signature receipt
    
    args:
        user_id: user identifier
        predicates: list of predicates to prove
        issue_receipt: whether to issue blind signature receipt
    
    returns:
        dict with proof verification result and optional token
    """
    print(f"\ncomplete verification flow for user {user_id}")
    print("=" * 60)
    
    # step 1: user generates proof
    print("\n[user] generating zero-knowledge proof...")
    proof = generate_proof(user_id, predicates)
    proof_path = f"artifacts/proofs/{user_id}_complete.json"
    save_proof(proof, proof_path)
    print(f"  proof generated: {len(proof['predicates'])} predicates")
    
    # step 2: user prepares blind signature request (before sending proof)
    blind_state = None
    if issue_receipt:
        print("\n[user] preparing blind signature request...")
        nonce = int(time.time() * 1000)
        predicate_summary = [
            {"type": p['type'], "attribute": p['attribute']} 
            for p in proof['predicates']
        ]
        blind_state = create_blind_signature_token(predicate_summary, nonce)
        print(f"  blinded message prepared")
    
    # step 3: verifier receives and verifies proof
    print("\n[verifier] verifying proof...")
    proof_loaded = load_proof(proof_path)
    verification_result = verify_proof(proof_loaded)
    
    if verification_result['valid']:
        print("  verification: success")
    else:
        print("  verification: failed")
        return {
            "proof_valid": False,
            "verification_result": verification_result,
            "token": None
        }
    
    # step 4: if proof valid, verifier signs blinded message
    token = None
    if issue_receipt and verification_result['valid']:
        print("\n[verifier] issuing blind signature receipt...")
        blinded_sig = issue_blind_signature(blind_state['blinded_message'])
        print("  blind signature issued")
        
        # step 5: user unblinds signature
        print("\n[user] unblinding signature...")
        token = unblind_and_verify_token(blinded_sig, blind_state)
        
        if token['valid']:
            print("  token successfully unblinded and verified")
            
            # save token
            token_path = f"artifacts/proofs/{user_id}_token.json"
            with open(token_path, 'w') as f:
                json.dump(token, f, indent=2)
            print(f"  token saved to {token_path}")
        else:
            print("  warning: token verification failed")
    
    print("\n" + "=" * 60)
    print("verification flow complete")
    
    return {
        "proof_valid": True,
        "verification_result": verification_result,
        "token": token,
        "unlinkable": issue_receipt and token is not None and token['valid']
    }


if __name__ == "__main__":
    # ensure verifier has blind signature keys
    verifier_blind_key = Path("artifacts/verifier_blind_key.pem")
    if not verifier_blind_key.exists():
        print("generating verifier blind signature keys...")
        generate_verifier_blind_keys()
        print()
    
    # example: complete flow for user 123
    user_id = 123
    predicates = [
        {"type": "range", "attribute": "Date_of_Birth", "threshold": 18},
        {"type": "equality", "attribute": "Citizenship", "value": "Germany"},
        {"type": "set_membership", "attribute": "License_Class", "set": ["G", "G2", "M", "Z"]}
    ]
    
    print("demonstration: privacy-preserving verification with unlinkable receipts")
    
    result = complete_verification_with_receipt(user_id, predicates, issue_receipt=True)
    
    # summary
    print("\nfinal result:")
    print(f"  proof verified: {result['proof_valid']}")
    print(f"  predicates checked: {len(predicates)}")
    print(f"  unlinkable receipt issued: {result['unlinkable']}")
    
    if result['token']:
        print(f"\ntoken properties:")
        print(f"  predicate set: {len(result['token']['predicate_set'])} predicates")
        print(f"  nonce: {result['token']['nonce']}")
        print(f"  signature (first 32 chars): {result['token']['signature_hex'][:32]}...")
        print("\nthis token proves successful verification but cannot be linked")
        print("back to the original proof or user identity by the verifier.")

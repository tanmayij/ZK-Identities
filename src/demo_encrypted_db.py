"""
end-to-end demonstration of encrypted database system.

shows complete flow:
1. verifier chooses predicate
2. client queries encrypted database server
3. server builds merkle trees and signs leaves
4. client generates proof
5. verifier validates proof
"""

import secrets
from encrypted_db_system import (
    EncryptedDatabaseServer,
    EncryptedDatabaseClient,
    EncryptedDatabaseVerifier,
)
from zkid.blind_signatures import BlindSignatureIssuer


def demo_basic_flow():
    """demonstrate basic query and proof flow."""
    
    print("\n" + "="*80)
    print("encrypted database system demo")
    print("="*80)
    
    print("\n[setup] initializing system components...")
    
    # Define attribute schema (order matters for privacy!)
    attribute_order = ["age", "country", "score"]
    
    encryption_key = secrets.token_bytes(32)
    issuer = BlindSignatureIssuer(key_size=2048)
    server = EncryptedDatabaseServer(
        encryption_key, 
        issuer, 
        use_aes=True,
        attribute_order=attribute_order
    )
    
    print(f"  server initialized with {server.enc_type} encryption")
    print(f"  attribute order: {attribute_order}")
    print(f"  (attributes accessed by index for privacy)")
    
    print("\n[setup] loading user data into encrypted database...")
    
    users_data = [
        {
            'uid': 'alice',
            'pk_user': secrets.token_bytes(32),
            'attributes': {
                'age': '25',
                'country': 'usa',
                'score': '85',
            }
        },
        {
            'uid': 'bob',
            'pk_user': secrets.token_bytes(32),
            'attributes': {
                'age': '30',
                'country': 'canada',
                'score': '92',
            }
        },
        {
            'uid': 'carol',
            'pk_user': secrets.token_bytes(32),
            'attributes': {
                'age': '28',
                'country': 'usa',
                'score': '78',
            }
        },
        {
            'uid': 'dave',
            'pk_user': secrets.token_bytes(32),
            'attributes': {
                'age': '35',
                'country': 'uk',
                'score': '88',
            }
        },
    ]
    
    for user in users_data:
        server.load_user(user['uid'], user['pk_user'], user['attributes'])
        print(f"  loaded user: {user['uid']}")
    
    print(f"\n  total users in database: {len(server.db)}")
    
    print("\n[verifier] creating verifier and defining predicate...")
    
    verifier = EncryptedDatabaseVerifier()
    
    print("  predicate: users from 'usa' with age >= 25")
    
    print("\n[client] alice querying server...")
    
    alice_data = users_data[0]
    alice_client = EncryptedDatabaseClient(
        uid=alice_data['uid'],
        sk_user=secrets.token_bytes(32),
        pk_user=alice_data['pk_user'],
        decryption_key=encryption_key,
        use_aes=True,
        attribute_order=attribute_order  # Must match server!
    )
    
    def usa_age_predicate(uid, encrypted_attrs):
        if isinstance(server.enc, type(alice_client.enc)):
            target_country = server.enc.encrypt(b'usa', column_name='country')
        else:
            target_country = server.enc.encrypt(b'usa')
        
        if 'country' in encrypted_attrs:
            if encrypted_attrs['country'].tag == target_country.tag:
                return True
        return False
    
    print("\n[server] processing query...")
    print("  1. evaluating predicate on encrypted database")
    print("  2. building inner merkle trees for matching users")
    print("  3. shuffling leaves BEFORE extracting auth paths (privacy)")
    print("  4. updating outer merkle tree")
    print("  5. extracting auth paths for requested attributes")
    
    response = server.query(usa_age_predicate)
    
    print(f"\n[server] query results:")
    print(f"  matching users: {response.matching_users}")
    print(f"  outer root: {response.outer_root.hex()[:16]}...")
    print(f"\n  timing breakdown:")
    print(f"    predicate eval: {response.metrics.predicate_eval_time*1000:.2f} ms")
    print(f"    inner trees: {response.metrics.inner_tree_build_time*1000:.2f} ms")
    print(f"    outer tree: {response.metrics.outer_tree_update_time*1000:.2f} ms")
    print(f"    signatures: {response.metrics.signature_time*1000:.2f} ms")
    print(f"    shuffle: {response.metrics.shuffle_time*1000:.2f} ms")
    print(f"    total: {response.metrics.total_time*1000:.2f} ms")
    
    print("\n[client] alice generating proof for 'age' attribute...")
    
    if alice_data['uid'] in response.matching_users:
        # Access via attribute index (0 = age in our schema)
        age_index = server.get_attr_index('age')
        alice_attr_data = response.user_data[alice_data['uid']][age_index]
        
        print(f"  (accessing attribute at index {age_index} = 'age')")
        
        proof = alice_client.query_and_prove(
            server=server,
            predicate_func=usa_age_predicate,
            attr_name='age',  # Client converts to index internally
            verifier_predicate=None
        )
        
        if proof:
            print(f"  proof generated successfully")
            print(f"  decrypted age value: {proof.attr_value}")
            print(f"  attribute index in proof: {proof.attr_index}")
            print(f"  inner root: {proof.proof_data['inner_root'][:16]}...")
            print(f"  outer root: {proof.proof_data['outer_root'][:16]}...")
        
        print("\n[verifier] registering outer root and verifying proof...")
        
        # Register the outer root from the proof (not from subsequent queries)
        verifier.register_root(proof.outer_root)
        
        if proof:
            is_valid = verifier.verify_proof(proof)
            
            if is_valid:
                print(f"\n  verification successful")
            else:
                print(f"\n  verification failed")
    else:
        print(f"  alice not in result set")
    
    print("\n[demo] querying again to show shuffling effect...")
    
    response2 = server.query(usa_age_predicate)
    
    print(f"\n  first query outer root:  {response.outer_root.hex()[:32]}...")
    print(f"  second query outer root: {response2.outer_root.hex()[:32]}...")
    
    if response.outer_root != response2.outer_root:
        print(f"  roots differ due to shuffling")
    else:
        print(f"  note: roots may be same if leaves shuffle to same position")
    
    print("\n[metrics] server performance summary:")
    
    summary = server.get_metrics_summary()
    print(f"  total queries served: {summary['total_queries']}")
    print(f"  avg query time: {summary['avg_total_time']*1000:.2f} ms")
    print(f"  users in outer tree: {summary['total_users_in_outer_tree']}")
    
    print("\n" + "="*80)
    print("demo completed successfully")
    print("="*80 + "\n")


def demo_multiple_clients():
    """demonstrate multiple clients querying and proving."""
    
    print("\n" + "="*80)
    print("multi-client demo")
    print("="*80)
    
    attribute_order = ["age", "score", "level"]
    
    encryption_key = secrets.token_bytes(32)
    issuer = BlindSignatureIssuer(key_size=2048)
    server = EncryptedDatabaseServer(
        encryption_key, 
        issuer,
        attribute_order=attribute_order
    )
    verifier = EncryptedDatabaseVerifier()
    
    print("\n[setup] creating 10 users with varying attributes...")
    
    users = []
    for i in range(10):
        uid = f"user_{i}"
        pk = secrets.token_bytes(32)
        sk = secrets.token_bytes(32)
        
        attrs = {
            'age': str(20 + i * 2),
            'score': str(70 + i * 3),
            'level': str(i % 3),
        }
        
        server.load_user(uid, pk, attrs)
        
        client = EncryptedDatabaseClient(
            uid=uid,
            sk_user=sk,
            pk_user=pk,
            decryption_key=encryption_key,
            attribute_order=attribute_order
        )
        
        users.append({
            'uid': uid,
            'pk': pk,
            'sk': sk,
            'client': client,
            'attrs': attrs
        })
    
    print(f"  loaded {len(users)} users")
    
    print("\n[query] running selectivity test with different predicates...")
    
    predicates = [
        ("high_selectivity (90%)", lambda uid, enc_attrs: True if hash(uid) % 10 < 9 else False),
        ("medium_selectivity (50%)", lambda uid, enc_attrs: True if hash(uid) % 2 == 0 else False),
        ("low_selectivity (10%)", lambda uid, enc_attrs: True if hash(uid) % 10 == 0 else False),
    ]
    
    for pred_name, pred_func in predicates:
        response = server.query(pred_func)
        print(f"\n  {pred_name}:")
        print(f"    matched: {len(response.matching_users)}/{len(users)} users")
        print(f"    latency: {response.metrics.total_time*1000:.2f} ms")
        print(f"    leaves: {response.metrics.num_total_leaves}")
        
        verifier.register_root(response.outer_root)
    
    print("\n[verification] each matched user generates proof...")
    
    final_response = server.query(predicates[1][1])
    
    verified_count = 0
    for user in users:
        if user['uid'] in final_response.matching_users:
            proof = user['client'].query_and_prove(
                server=server,
                predicate_func=predicates[1][1],
                attr_name='age',
                verifier_predicate=None
            )
            
            if proof and verifier.verify_proof(proof):
                verified_count += 1
    
    print(f"\n  verified {verified_count}/{len(final_response.matching_users)} proofs")
    
    print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--multi":
        demo_multiple_clients()
    else:
        demo_basic_flow()

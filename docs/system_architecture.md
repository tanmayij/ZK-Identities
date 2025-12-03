system architecture overview

this document describes the current encrypted identity verifier service. all content is new and replaces the archived design notes.

component summary
client device generates read verify rotate requests and prepares groth16 proofs. server node stores encrypted user bundles and maintains both inner and outer merkle structures. poseidon bridge process exposes hash and merkle utilities through node and snarkjs. database backend uses sqlalchemy with sqlite or postgres. external verifier consumes predicate proofs and issues authorization decisions.

diagram client server verifier
client application
server api and storage
poseidon helper process
external verifier

threat model
attackers may control the network and observe all traffic. server operator may be honest but curious and tries to learn user attributes. malicious clients may attempt double spends or forge membership. trusted components include the circuit parameters the proving keys and the deployed verifier binaries. secrets include user encryption keys salts and nullifiers. we assume snarkjs groth16 verifier and poseidon functions are correct and the database host is hardened against privilege escalation.

security goals
preserve confidentiality of user attributes while supporting batched queries. provide integrity for merkle commitments and rotation updates. prevent double rotation through nullifier tracking. enable clients to convince an external verifier that decrypted attributes satisfy agreed predicates without exposing cleartext.

cold start end to end flow
step one initialize database schema and seed user records with auto computed outer paths.
step two launch poseidon bridge and warm the wasm modules.
step three client issues k plus one fetch request and decrypts the matching blob.
step four client produces rotation groth16 proof referencing the cached outer path.
step five client produces predicate groth16 proof for the external verifier using the same witness bundle.
step six server verifies rotation proof updates the outer tree and records the nullifier.
step seven external verifier validates the predicate proof and releases the decision.

warm invocation flow
step one client repeats fetch decrypt rotate after caches are hot.
step two prove rotation again while reusing poseidon merkle data.
step three generate predicate proof and forward to external verifier.
step four collect timing metrics to monitor cache lifetime.

attribute mutation flow
step one operator registers new users through register user auto path and triggers outer tree refresh.
step two rotation proof updates rewrite stored inner roots and nullifiers.
step three periodic recompute outer tree validates integrity snapshots.

grouped predicate workflow
step one external verifier publishes policy age eighteen plus citizenship ca license class g or g2.
step two client pulls encrypted cohort decrypts locally and identifies matching users.
step three for each target client assembles inner path and outer path witness data.
step four client proves predicate satisfaction and submits proof bundle to external verifier along with reference nullifier.
step five verifier checks groth16 proof and records authorization event.

operational notes
all numeric values are handled as field elements through poseidon hash and groth16 circuits. cached outer paths are refreshed in bulk using the new compute all paths helper. rotation and predicate proofs share witnesses to avoid redundant hashing. benchmarking harnesses should persist timings for cold boot warm invocation attribute mutation and grouped predicate scenarios.

pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

/**
 * Circuit B: Business Predicate Verification
 * 
 * Proves a specific claim about a user's attribute (e.g., "Age > 18")
 * without revealing the attribute value, user identity, or attribute position.
 * 
 * Privacy Properties:
 * - Verifier learns only that some user satisfies the predicate
 * - User identity is hidden (zero-knowledge of which outer leaf)
 * - Attribute value is hidden (only predicate satisfaction is proven)
 * - Attribute position can be hidden or revealed depending on use case
 */

template InnerMerkleProof(depth) {
    signal input leaf;
    signal input path_elements[depth];
    signal input path_indices[depth];
    signal output root;
    
    component hashers[depth];
    component muxes[depth];
    
    signal hashes[depth + 1];
    hashes[0] <== leaf;
    
    for (var i = 0; i < depth; i++) {
        path_indices[i] * (1 - path_indices[i]) === 0;
        
        muxes[i] = MultiMux1(2);
        muxes[i].c[0][0] <== hashes[i];
        muxes[i].c[0][1] <== path_elements[i];
        muxes[i].c[1][0] <== path_elements[i];
        muxes[i].c[1][1] <== hashes[i];
        muxes[i].s <== path_indices[i];
        
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxes[i].out[0];
        hashers[i].inputs[1] <== muxes[i].out[1];
        
        hashes[i + 1] <== hashers[i].out;
    }
    
    root <== hashes[depth];
}

template OuterMerkleProof(depth) {
    signal input leaf;
    signal input path_elements[depth];
    signal input path_indices[depth];
    signal output root;
    
    component hashers[depth];
    component muxes[depth];
    
    signal hashes[depth + 1];
    hashes[0] <== leaf;
    
    for (var i = 0; i < depth; i++) {
        path_indices[i] * (1 - path_indices[i]) === 0;
        
        muxes[i] = MultiMux1(2);
        muxes[i].c[0][0] <== hashes[i];
        muxes[i].c[0][1] <== path_elements[i];
        muxes[i].c[1][0] <== path_elements[i];
        muxes[i].c[1][1] <== hashes[i];
        muxes[i].s <== path_indices[i];
        
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxes[i].out[0];
        hashers[i].inputs[1] <== muxes[i].out[1];
        
        hashes[i + 1] <== hashers[i].out;
    }
    
    root <== hashes[depth];
}

template PredicateCircuit(num_attributes, inner_depth, outer_depth) {
    // Private inputs
    signal input attributes[num_attributes];          // User's attributes
    signal input salts[num_attributes];              // Randomness for each attribute
    signal input inner_path_elements[inner_depth];   // Path to specific attribute in inner tree
    signal input inner_path_indices[inner_depth];    // Path direction bits
    signal input outer_path_elements[outer_depth];   // Path to user in outer tree
    signal input outer_path_indices[outer_depth];    // Path direction bits
    
    // Public inputs
    signal input outer_root;                         // Current outer tree root
    signal input attribute_index;                    // Which attribute to check (0-7)
    signal input threshold;                          // Threshold value for comparison
    
    // Step 1: Select the target attribute based on attribute_index
    // We need to prove attributes[attribute_index] > threshold
    // Use a multiplexer to select without revealing in constraints
    signal selected_attribute;
    signal selected_salt;
    
    // Simple linear scan (constant-time, preserves privacy)
    // Declare all components outside the loop (Circom 2.x requirement)
    component is_equal_checks[num_attributes];
    component attr_selectors[num_attributes];
    component salt_selectors[num_attributes];
    signal attr_matches[num_attributes];
    signal salt_matches[num_attributes];
    signal attr_accumulator[num_attributes + 1];
    signal salt_accumulator[num_attributes + 1];
    
    attr_accumulator[0] <== 0;
    salt_accumulator[0] <== 0;
    
    for (var i = 0; i < num_attributes; i++) {
        is_equal_checks[i] = IsEqual();
        is_equal_checks[i].in[0] <== attribute_index;
        is_equal_checks[i].in[1] <== i;
        
        attr_matches[i] <== is_equal_checks[i].out * attributes[i];
        salt_matches[i] <== is_equal_checks[i].out * salts[i];
        
        attr_accumulator[i + 1] <== attr_accumulator[i] + attr_matches[i];
        salt_accumulator[i + 1] <== salt_accumulator[i] + salt_matches[i];
    }
    
    selected_attribute <== attr_accumulator[num_attributes];
    selected_salt <== salt_accumulator[num_attributes];
    
    // Step 2: Verify predicate: selected_attribute > threshold
    component greater_than = GreaterThan(64); // Support 64-bit values
    greater_than.in[0] <== selected_attribute;
    greater_than.in[1] <== threshold;
    greater_than.out === 1; // Must be true
    
    // Step 3: Compute the leaf hash for the selected attribute
    component leaf_hasher = Poseidon(2);
    leaf_hasher.inputs[0] <== selected_attribute;
    leaf_hasher.inputs[1] <== selected_salt;
    signal attribute_leaf;
    attribute_leaf <== leaf_hasher.out;
    
    // Step 4: Verify attribute_leaf exists in inner tree
    component inner_proof = InnerMerkleProof(inner_depth);
    inner_proof.leaf <== attribute_leaf;
    for (var i = 0; i < inner_depth; i++) {
        inner_proof.path_elements[i] <== inner_path_elements[i];
        inner_proof.path_indices[i] <== inner_path_indices[i];
    }
    signal inner_root;
    inner_root <== inner_proof.root;
    
    // Step 5: Verify inner_root exists in outer tree
    component outer_proof = OuterMerkleProof(outer_depth);
    outer_proof.leaf <== inner_root;
    for (var i = 0; i < outer_depth; i++) {
        outer_proof.path_elements[i] <== outer_path_elements[i];
        outer_proof.path_indices[i] <== outer_path_indices[i];
    }
    outer_proof.root === outer_root;
    
    // Output: proof verifies, no values revealed
}

// Main component for 8 attributes, inner depth 3, outer depth 10
// Public inputs: outer_root, attribute_index, threshold
component main {public [outer_root, attribute_index, threshold]} = PredicateCircuit(8, 3, 10);

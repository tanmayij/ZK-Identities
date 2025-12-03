pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

/**
 * Circuit A: Identity Maintenance (Rotation)
 * 
 * Allows a user to "rotate" their position in the Outer Tree to prevent tracking.
 * The user proves they control a valid leaf, then commits to a new position with re-randomized salts.
 * 
 * Privacy Properties:
 * - Old position is nullified (prevents double-spending)
 * - New position is unlinkable to old position
 * - Attributes remain unchanged, only salts are refreshed
 */

template InnerMerkleVerifier(depth) {
    // Verify a leaf exists in an inner tree of given depth
    signal input leaf;
    signal input path_elements[depth];
    signal input path_indices[depth];
    signal output root;
    
    component hashers[depth];
    component muxes[depth];
    
    signal hashes[depth + 1];
    hashes[0] <== leaf;
    
    for (var i = 0; i < depth; i++) {
        path_indices[i] * (1 - path_indices[i]) === 0; // binary constraint
        
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

template OuterMerkleVerifier(depth) {
    // Verify a leaf exists in the outer tree
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

template ComputeInnerRoot(num_attributes, inner_depth) {
    // Compute inner Merkle root from attributes and salts
    signal input attributes[num_attributes];
    signal input salts[num_attributes];
    signal output inner_root;
    
    // Hash each attribute with its salt to create leaves
    component leaf_hashers[num_attributes];
    signal leaves[num_attributes];
    
    for (var i = 0; i < num_attributes; i++) {
        leaf_hashers[i] = Poseidon(2);
        leaf_hashers[i].inputs[0] <== attributes[i];
        leaf_hashers[i].inputs[1] <== salts[i];
        leaves[i] <== leaf_hashers[i].out;
    }
    
    // Build Merkle tree from leaves (assuming num_attributes = 2^inner_depth)
    var num_nodes = num_attributes;
    component level_hashers[inner_depth][num_attributes / 2];
    signal level_hashes[inner_depth + 1][num_attributes];
    
    // Level 0: leaves
    for (var i = 0; i < num_attributes; i++) {
        level_hashes[0][i] <== leaves[i];
    }
    
    // Levels 1 to inner_depth
    for (var level = 0; level < inner_depth; level++) {
        num_nodes = num_nodes \ 2;
        for (var i = 0; i < num_nodes; i++) {
            level_hashers[level][i] = Poseidon(2);
            level_hashers[level][i].inputs[0] <== level_hashes[level][2*i];
            level_hashers[level][i].inputs[1] <== level_hashes[level][2*i + 1];
            level_hashes[level + 1][i] <== level_hashers[level][i].out;
        }
    }
    
    inner_root <== level_hashes[inner_depth][0];
}

template RotationCircuit(num_attributes, inner_depth, outer_depth) {
    // Private inputs
    signal input attributes[num_attributes];           // User's attributes (unchanged)
    signal input old_salts[num_attributes];           // Old randomness
    signal input new_salts[num_attributes];           // New randomness (for re-randomization)
    signal input outer_path_elements[outer_depth];    // Merkle path in outer tree
    signal input outer_path_indices[outer_depth];     // Path direction bits
    
    // Public inputs
    signal input old_outer_root;                      // Current outer tree root
    signal input new_outer_leaf;                      // New commitment (public to allow server update)
    signal input nullifier;                           // Prevents double-use of old position
    
    // Step 1: Compute old inner root from attributes + old_salts
    component old_inner_computer = ComputeInnerRoot(num_attributes, inner_depth);
    for (var i = 0; i < num_attributes; i++) {
        old_inner_computer.attributes[i] <== attributes[i];
        old_inner_computer.salts[i] <== old_salts[i];
    }
    signal old_inner_root;
    old_inner_root <== old_inner_computer.inner_root;
    
    // Step 2: Verify old_inner_root exists in old_outer_root
    component outer_verifier = OuterMerkleVerifier(outer_depth);
    outer_verifier.leaf <== old_inner_root;
    for (var i = 0; i < outer_depth; i++) {
        outer_verifier.path_elements[i] <== outer_path_elements[i];
        outer_verifier.path_indices[i] <== outer_path_indices[i];
    }
    outer_verifier.root === old_outer_root;
    
    // Step 3: Compute new inner root with same attributes but new salts
    component new_inner_computer = ComputeInnerRoot(num_attributes, inner_depth);
    for (var i = 0; i < num_attributes; i++) {
        new_inner_computer.attributes[i] <== attributes[i];
        new_inner_computer.salts[i] <== new_salts[i];
    }
    signal new_inner_root;
    new_inner_root <== new_inner_computer.inner_root;
    
    // Step 4: Verify new_outer_leaf == new_inner_root
    new_outer_leaf === new_inner_root;
    
    // Step 5: Compute and verify nullifier
    // Nullifier = Poseidon(old_inner_root, secret_value_from_old_salts)
    component nullifier_hasher = Poseidon(2);
    nullifier_hasher.inputs[0] <== old_inner_root;
    nullifier_hasher.inputs[1] <== old_salts[0]; // Use first salt as secret
    nullifier_hasher.out === nullifier;
}

// Main component for 8 attributes, inner depth 3, outer depth 10
component main {public [old_outer_root, new_outer_leaf, nullifier]} = RotationCircuit(8, 3, 10);

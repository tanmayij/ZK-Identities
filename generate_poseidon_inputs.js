// Poseidon hash wrapper for test data generation
// This uses circomlibjs to compute Poseidon hashes compatible with the circuits

const buildPoseidon = require("circomlibjs").buildPoseidon;
const fs = require("fs");

async function computePoseidonHash(inputs) {
    const poseidon = await buildPoseidon();
    const hash = poseidon(inputs);
    return poseidon.F.toString(hash);
}

async function computeInnerRoot(attributes, salts) {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    
    // Compute leaves: Poseidon(attribute, salt)
    const leaves = [];
    for (let i = 0; i < attributes.length; i++) {
        const hash = poseidon([attributes[i], salts[i]]);
        leaves.push(F.toObject(hash));
    }
    
    // Build Merkle tree (depth 3, 8 leaves)
    let currentLevel = leaves;
    while (currentLevel.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
            const left = currentLevel[i];
            const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
            const hash = poseidon([left, right]);
            nextLevel.push(F.toObject(hash));
        }
        currentLevel = nextLevel;
    }
    
    return currentLevel[0];
}

async function getMerklePath(leaves, leafIndex) {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    const pathElements = [];
    const pathIndices = [];
    
    let currentLevel = leaves.slice();
    let currentIndex = leafIndex;
    
    while (currentLevel.length > 1) {
        if (currentIndex % 2 === 0) {
            const sibling = currentIndex + 1 < currentLevel.length ? currentLevel[currentIndex + 1] : currentLevel[currentIndex];
            pathElements.push(sibling);
            pathIndices.push(0);
        } else {
            pathElements.push(currentLevel[currentIndex - 1]);
            pathIndices.push(1);
        }
        
        const nextLevel = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
            const left = currentLevel[i];
            const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
            const hash = poseidon([left, right]);
            nextLevel.push(F.toObject(hash));
        }
        currentLevel = nextLevel;
        currentIndex = Math.floor(currentIndex / 2);
    }
    
    return { pathElements, pathIndices };
}

async function generateRotationInput() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    
    // Test attributes (as field elements)
    const attributes = [25, 1, 42, 100, 5, 999, 12345, 7];
    
    // Generate random salts (as field elements)
    const oldSalts = Array(8).fill(0).map((_, i) => 
        BigInt("0x1000000000000000") + BigInt(i) * BigInt("0x1111111111111111")
    );
    const newSalts = Array(8).fill(0).map((_, i) => 
        BigInt("0x9000000000000000") + BigInt(i) * BigInt("0x1111111111111111")
    );
    
    // Compute old inner root
    const oldInnerRoot = await computeInnerRoot(attributes, oldSalts);
    
    // Compute new inner root
    const newInnerRoot = await computeInnerRoot(attributes, newSalts);
    
    // Compute inner leaves for path generation
    const oldInnerLeaves = [];
    for (let i = 0; i < attributes.length; i++) {
        const hash = poseidon([attributes[i], oldSalts[i]]);
        oldInnerLeaves.push(F.toObject(hash));
    }
    
    // Create outer tree with 1024 users
    const userIndex = 42;
    const outerLeaves = Array(1024).fill(0).map((_, i) => {
        if (i === userIndex) return oldInnerRoot;
        return BigInt(1000 + i);  // Dummy values for other users
    });
    
    // Get Merkle path for user 42
    const { pathElements: outerPathElements, pathIndices: outerPathIndices } = await getMerklePath(outerLeaves, userIndex);
    
    // Compute old outer root
    let currentLevel = outerLeaves.slice();
    while (currentLevel.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
            const left = currentLevel[i];
            const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
            const hash = poseidon([left, right]);
            nextLevel.push(F.toObject(hash));
        }
        currentLevel = nextLevel;
    }
    const oldOuterRoot = currentLevel[0];
    
    // Compute nullifier: Poseidon(oldInnerRoot, oldSalts[0])
    const nullifierHash = poseidon([oldInnerRoot, oldSalts[0]]);
    const nullifier = F.toObject(nullifierHash);
    
    return {
        attributes: attributes.map(a => a.toString()),
        old_salts: oldSalts.map(s => s.toString()),
        new_salts: newSalts.map(s => s.toString()),
        outer_path_elements: outerPathElements.map(e => e.toString()),
        outer_path_indices: outerPathIndices,
        old_outer_root: oldOuterRoot.toString(),
        new_outer_leaf: newInnerRoot.toString(),
        nullifier: nullifier.toString()
    };
}

async function generatePredicateInput() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    
    // Test attributes
    const attributes = [25, 1, 42, 100, 5, 999, 12345, 7];
    
    // Generate salts
    const salts = Array(8).fill(0).map((_, i) => 
        BigInt("0x1000000000000000") + BigInt(i) * BigInt("0x1111111111111111")
    );
    
    // Compute inner leaves
    const innerLeaves = [];
    for (let i = 0; i < attributes.length; i++) {
        const hash = poseidon([attributes[i], salts[i]]);
        innerLeaves.push(F.toObject(hash));
    }
    
    // Compute inner root
    const innerRoot = await computeInnerRoot(attributes, salts);
    
    // Get path for attribute 0 (age)
    const { pathElements: innerPathElements, pathIndices: innerPathIndices } = await getMerklePath(innerLeaves, 0);
    
    // Create outer tree
    const userIndex = 42;
    const outerLeaves = Array(1024).fill(0).map((_, i) => {
        if (i === userIndex) return innerRoot;
        return BigInt(1000 + i);  // Dummy values for other users
    });
    
    // Get path for user 42
    const { pathElements: outerPathElements, pathIndices: outerPathIndices } = await getMerklePath(outerLeaves, userIndex);
    
    // Compute outer root
    let currentLevel = outerLeaves.slice();
    while (currentLevel.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
            const left = currentLevel[i];
            const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
            const hash = poseidon([left, right]);
            nextLevel.push(F.toObject(hash));
        }
        currentLevel = nextLevel;
    }
    const outerRoot = currentLevel[0];
    
    return {
        attributes: attributes.map(a => a.toString()),
        salts: salts.map(s => s.toString()),
        inner_path_elements: innerPathElements.map(e => e.toString()),
        inner_path_indices: innerPathIndices,
        outer_path_elements: outerPathElements.map(e => e.toString()),
        outer_path_indices: outerPathIndices,
        outer_root: outerRoot.toString(),
        attribute_index: "0",
        threshold: "18"
    };
}

async function main() {
    console.log("Generating Poseidon-compatible test inputs...\n");
    
    const rotationInput = await generateRotationInput();
    fs.writeFileSync("circuits/input_rotation.json", JSON.stringify(rotationInput, null, 2));
    console.log("✓ Generated circuits/input_rotation.json");
    
    const predicateInput = await generatePredicateInput();
    fs.writeFileSync("circuits/input_predicate.json", JSON.stringify(predicateInput, null, 2));
    console.log("✓ Generated circuits/input_predicate.json");
    
    console.log("\nInputs are now compatible with Poseidon circuits!");
}

main().catch(console.error);

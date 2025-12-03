#!/usr/bin/env node
/**
 * Poseidon Hash Bridge - Python to Node.js
 * 
 * Provides Poseidon hash computation for Python code via subprocess.
 * Usage: node poseidon_bridge.js <command> <args...>
 * 
 * Commands:
 *   hash <input1> <input2> ... - Hash multiple inputs
 *   merkle_root <leaf1> <leaf2> ... - Compute Merkle root from leaves
 *   merkle_paths <leaf1> <leaf2> ... - Compute root and authentication paths for all leaves
 */

const { buildPoseidon } = require('circomlibjs');

let poseidon = null;

async function initPoseidon() {
    if (!poseidon) {
        poseidon = await buildPoseidon();
    }
    return poseidon;
}

function bigIntToHex(value) {
    return '0x' + value.toString(16).padStart(64, '0');
}

function hexToBigInt(hex) {
    return BigInt(hex);
}

async function hashInputs(inputs) {
    const p = await initPoseidon();
    const bigIntInputs = inputs.map(x => BigInt(x));
    const hash = p(bigIntInputs);
    return bigIntToHex(p.F.toObject(hash));
}

async function computeMerkleRoot(leaves) {
    const p = await initPoseidon();
    
    // Convert leaves to BigInt
    let currentLevel = leaves.map(leaf => BigInt(leaf));
    
    // Build tree bottom-up
    while (currentLevel.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
            const left = currentLevel[i];
            const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : currentLevel[i];
            
            const hash = p([left, right]);
            nextLevel.push(p.F.toObject(hash));
        }
        currentLevel = nextLevel;
    }
    
    return bigIntToHex(currentLevel[0]);
}

async function computeMerklePaths(leaves) {
    const p = await initPoseidon();

    let currentLevel = leaves.map(leaf => BigInt(leaf));
    const levels = [currentLevel.slice()];

    while (currentLevel.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
            const left = currentLevel[i];
            const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : currentLevel[i];
            const hash = p([left, right]);
            nextLevel.push(p.F.toObject(hash));
        }
        currentLevel = nextLevel;
        levels.push(currentLevel.slice());
    }

    const depth = levels.length - 1;
    const root = levels[depth][0];

    const allPathElements = [];
    const allPathIndices = [];

    for (let index = 0; index < leaves.length; index++) {
        let currentIndex = index;
        const pathElems = [];
        const pathIdx = [];

        for (let level = 0; level < depth; level++) {
            const levelNodes = levels[level];
            const isLeft = currentIndex % 2 === 0;
            const siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1;
            const sibling = siblingIndex < levelNodes.length
                ? levelNodes[siblingIndex]
                : levelNodes[currentIndex];

            pathElems.push(bigIntToHex(sibling));
            pathIdx.push(isLeft ? 0 : 1);
            currentIndex = Math.floor(currentIndex / 2);
        }

        allPathElements.push(pathElems);
        allPathIndices.push(pathIdx);
    }

    return {
        root: bigIntToHex(root),
        pathElements: allPathElements,
        pathIndices: allPathIndices
    };
}

async function computeInnerRoot(attributes, salts) {
    const p = await initPoseidon();
    
    // Compute leaves: Poseidon(attribute, salt)
    const leaves = [];
    for (let i = 0; i < attributes.length; i++) {
        const attr = BigInt(attributes[i]);
        const salt = hexToBigInt(salts[i]);
        const leaf = p([attr, salt]);
        leaves.push(p.F.toObject(leaf));
    }
    
    // Build Merkle tree
    let currentLevel = leaves;
    while (currentLevel.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
            const left = currentLevel[i];
            const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : currentLevel[i];
            
            const hash = p([left, right]);
            nextLevel.push(p.F.toObject(hash));
        }
        currentLevel = nextLevel;
    }
    
    return bigIntToHex(currentLevel[0]);
}

async function computeNullifier(innerRoot, salt) {
    const p = await initPoseidon();
    const hash = p([hexToBigInt(innerRoot), hexToBigInt(salt)]);
    return bigIntToHex(p.F.toObject(hash));
}

async function getMerklePath(leafIndex, leaves) {
    const p = await initPoseidon();
    
    // Build tree and track paths
    let currentLevel = leaves.map(leaf => BigInt(leaf));
    const pathElements = [];
    const pathIndices = [];
    let currentIndex = leafIndex;
    
    while (currentLevel.length > 1) {
        const nextLevel = [];
        const isLeft = currentIndex % 2 === 0;
        const siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1;
        
        // Get sibling (or duplicate if at edge)
        const sibling = siblingIndex < currentLevel.length 
            ? currentLevel[siblingIndex] 
            : currentLevel[currentIndex];
        
        pathElements.push(bigIntToHex(sibling));
        pathIndices.push(isLeft ? 0 : 1);
        
        // Hash current level
        for (let i = 0; i < currentLevel.length; i += 2) {
            const left = currentLevel[i];
            const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : currentLevel[i];
            const hash = p([left, right]);
            nextLevel.push(p.F.toObject(hash));
        }
        
        currentLevel = nextLevel;
        currentIndex = Math.floor(currentIndex / 2);
    }
    
    return {
        root: bigIntToHex(currentLevel[0]),
        pathElements,
        pathIndices
    };
}

async function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0) {
        console.error('Usage: node poseidon_bridge.js <command> <args...>');
        console.error('Commands:');
        console.error('  hash <input1> <input2> ... - Hash multiple inputs');
        console.error('  inner_root <attr1> <attr2>... <salt1> <salt2>... - Compute inner Merkle root');
        console.error('  nullifier <innerRoot> <salt> - Compute nullifier');
        console.error('  merkle_path <leafIndex> <leaf1> <leaf2>... - Get Merkle path');
        console.error('  merkle_paths <leaf1> <leaf2>... - Get all Merkle paths');
        process.exit(1);
    }
    
    const command = args[0];
    
    try {
        switch (command) {
            case 'hash': {
                const inputs = args.slice(1);
                const result = await hashInputs(inputs);
                console.log(result);
                break;
            }
            
            case 'inner_root': {
                // Expect: attr1 attr2 ... attr8 salt1 salt2 ... salt8
                const numAttrs = 8;
                const attributes = args.slice(1, 1 + numAttrs);
                const salts = args.slice(1 + numAttrs, 1 + 2 * numAttrs);
                const result = await computeInnerRoot(attributes, salts);
                console.log(result);
                break;
            }
            
            case 'nullifier': {
                const innerRoot = args[1];
                const salt = args[2];
                const result = await computeNullifier(innerRoot, salt);
                console.log(result);
                break;
            }
            
            case 'merkle_path': {
                const leafIndex = parseInt(args[1]);
                const leaves = args.slice(2);
                const result = await getMerklePath(leafIndex, leaves);
                console.log(JSON.stringify(result));
                break;
            }
            
            case 'merkle_root': {
                const leaves = args.slice(1);
                const result = await computeMerkleRoot(leaves);
                console.log(result);
                break;
            }

            case 'merkle_paths': {
                const leaves = args.slice(1);
                const result = await computeMerklePaths(leaves);
                console.log(JSON.stringify(result));
                break;
            }
            
            default:
                console.error(`Unknown command: ${command}`);
                process.exit(1);
        }
    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

main();

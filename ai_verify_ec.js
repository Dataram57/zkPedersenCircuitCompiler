import {Dimperpreter, DimProtect} from './dimperpreter.js';
import fs from "node:fs";
import pkg from 'elliptic';
const { ec: EC } = pkg;
import crypto from 'crypto';

//================================================================
//#region Elliptic Curve Math

const ec = new EC('secp256k1');
const curve = ec.curve;

// Generator points G and H on the elliptic curve
const G = ec.g;

// Derive second generator H deterministically
function deriveH() {
    const gEncoded = G.encode('hex', true);
    const hash = crypto.createHash('sha256')
        .update('PEDERSEN_H_GENERATOR')
        .update(Buffer.from(gEncoded, 'hex'))
        .digest();
    const scalar = ec.keyFromPrivate(hash).getPrivate();
    return G.mul(scalar);
}

const H = deriveH();

// Get curve order (prime modulus for scalars)
const q = ec.n; // This is the order of the curve (prime)

// Point to hex string
const pointToHex = (point) => point.encode('hex', true);

// Hex string to point
const hexToPoint = (hex) => ec.curve.decodePoint(hex, 'hex');

// Modular arithmetic for scalars
const modAdd = (a, b) => a.add(b).umod(q);
const modMul = (a, b) => a.mul(b).umod(q);
const modSub = (a, b) => a.sub(b).umod(q);

const BigIntMod = (v) => {
    let bn = ec.keyFromPrivate(Buffer.from(BigInt(v).toString(16).padStart(64, '0'), 'hex')).getPrivate();
    return bn.umod(q);
};

//#endregion

//================================================================
//#region Pedersen Squared Verification (Elliptic Curve Version)

const verify_SquareProof = (env, proof) => {
    const c1 = env.c1;
    const c2 = env.c2;
    const G2 = c1;

    // Parse proof values
    const c3 = hexToPoint(proof.c3);
    const c4 = hexToPoint(proof.c4);
    const k = ec.keyFromPrivate(proof.k, 'hex').getPrivate();
    const z1 = ec.keyFromPrivate(proof.z1, 'hex').getPrivate();
    const z2 = ec.keyFromPrivate(proof.z2, 'hex').getPrivate();
    const z3 = ec.keyFromPrivate(proof.z3, 'hex').getPrivate();

    // Verify: c3 + k*c1 = z1*G + z2*H
    const left1 = c3.add(c1.mul(k));
    const right1 = G.mul(z1).add(H.mul(z2));
    const check1 = left1.eq(right1);

    // Verify: c4 + k*c2 = z1*G2 + z3*H
    const left2 = c4.add(c2.mul(k));
    const right2 = G2.mul(z1).add(H.mul(z3));
    const check2 = left2.eq(right2);

    return check1 && check2;
};

//#endregion

//================================================================
//#region Pedersen Equal Secrets Verification (Elliptic Curve Version)

const verify_bond_commit_equal_commit = (env, proof) => {
    const c1 = env.c1;
    const c2 = env.c2;
    const r = ec.keyFromPrivate(proof.r, 'hex').getPrivate();

    // Verify: c1 - c2 = r*H
    const left = c1.add(c2.neg());
    const right = H.mul(r);
    
    return left.eq(right);
};

//#endregion

//================================================================
//#region Pedersen Equal Value Verification (Schnorr Protocol on EC)

const verify_bond_commit_equal_secret = (env, proof) => {
    // Extract commitment C and secret value s
    const C = env.c;
    const s = BigIntMod(env.secret);
    
    // Calculate Y = C - s*G (should equal t*H)
    const Y = C.add(G.mul(s).neg());

    // Parse proof
    const u = hexToPoint(proof.u);
    const c = ec.keyFromPrivate(proof.c, 'hex').getPrivate();
    const z = ec.keyFromPrivate(proof.z, 'hex').getPrivate();

    // Verify: z*H = u + c*Y
    const left = H.mul(z);
    const right = u.add(Y.mul(c));

    return left.eq(right);
};

//#endregion

//================================================================
//#region Main

// Running
const dimpCode = new Dimperpreter(fs.readFileSync('./be_bit.dim', 'utf8'));
const dimpReceipt = new Dimperpreter(fs.readFileSync('./receipt.dim', 'utf8'));
const memCommits = {};
let args = [];
let proof = [];
let i = 0;
let com = null;
let x = null;
let sumCommits = null;
let proofEnv = null;
let proofProof = null;
let verification = false;
let temp = "";

while(true) {
    // Read next
    args = dimpCode.Next();
    if(args.length <= 0)
        break;
    
    // Trim args
    i = args.length;
    while(i--)
        args[i] = args[i].trim();
    
    // Interpret
    switch(args[0]) {
        case "input":
            com = hexToPoint(dimpReceipt.Next()[0]);
            memCommits[args[1]] = com;
            console.log("signal input", args[1], "<== SECRET");
            break;
            
        case "commit":
            com = hexToPoint(dimpReceipt.Next()[0]);
            memCommits[args[1]] = com;
            console.log("signal", args[1], "<== SECRET_ADDITIONAL");
            break;
            
        case "sum":
            x = null;
            sumCommits = ec.curve.point(null, null); // Point at infinity (identity element)
            
            for(i = 2; i < args.length; i++) {
                if(i % 2 == 0) {
                    switch(args[i][0]) {
                        case '.':
                            x = BigIntMod(Math.ceil(Number(BigInt(q)) * parseFloat(args[i])));
                            break;
                        case '/':
                            const divisor = args[i].substring(1);
                            console.log(divisor);
                            const divisorBN = BigIntMod(divisor);
                            x = divisorBN.invm(q);
                            break;
                        default:
                            x = BigIntMod(args[i]);
                            break;
                    }
                } else {
                    // Homomorphic addition: sumCommits += x * memCommits[args[i]]
                    sumCommits = sumCommits.add(memCommits[args[i]].mul(x));
                }
            }
            
            memCommits[args[1]] = sumCommits;
            temp = "";
            for(i = 2; i < args.length; i++) {
                if(i % 2 == 0)
                    temp += args[i] + "*";
                else
                    temp += args[i] + " + ";
            }
            console.log("signal", args[1], "<==", temp + "0");
            break;
            
        case "equal":
            proof = dimpReceipt.Next();
            proofEnv = {
                c: memCommits[args[1]],
                secret: BigIntMod(args[2])
            };
            proofProof = {
                u: proof[0],
                c: proof[1],
                z: proof[2]
            };
            verification = verify_bond_commit_equal_secret(proofEnv, proofProof);
            console.log(args[1], "===", args[2], "//", verification ? "✅" : "❌");
            break;
            
        case "square":
            com = hexToPoint(dimpReceipt.Next()[0]);
            memCommits[args[1]] = com;
            proof = dimpReceipt.Next();
            proofEnv = {
                c1: memCommits[args[2]],
                c2: memCommits[args[1]]
            };
            proofProof = {
                c3: proof[0],
                c4: proof[1],
                k: proof[2],
                z1: proof[3],
                z2: proof[4],
                z3: proof[5]
            };
            verification = verify_SquareProof(proofEnv, proofProof);
            console.log("signal", args[1], "<==", args[2], "*", args[2], "//", verification ? "✅" : "❌");
            break;
            
        case "same":
            proof = dimpReceipt.Next();
            proofEnv = {
                c1: memCommits[args[1]],
                c2: memCommits[args[2]]
            };
            proofProof = {
                r: proof[0]
            };
            verification = verify_bond_commit_equal_commit(proofEnv, proofProof);
            console.log(args[1], "===", args[2], "//", verification ? "✅" : "❌");
            break;
    }
}

//#endregion
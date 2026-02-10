import {Dimperpreter, DimProtect} from './dimperpreter.js';
import fs from "node:fs";
import { create, all } from 'mathjs';
import pkg from 'elliptic';
const { ec: EC } = pkg;
import crypto from 'crypto';

const math = create(all);

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

// Elliptic curve Pedersen commitment: C = secret*G + rand*H
const commit = (secret, rand) => {
    const s = ec.keyFromPrivate(Buffer.from(secret.toString(16).padStart(64, '0'), 'hex')).getPrivate();
    const r = ec.keyFromPrivate(Buffer.from(rand.toString(16).padStart(64, '0'), 'hex')).getPrivate();
    
    const sG = G.mul(s);
    const rH = H.mul(r);
    return sG.add(rH);
};

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
//#region Pedersen Squared (Elliptic Curve Version)

const commit_squared = (secret, t1) => {
    // Get current commitment: C1 = secret*G + t1*H
    let c1 = commit(secret, t1);

    // Pick random t2
    let t2 = BigIntMod(456n);

    // Set new generator G2 = C1
    let G2 = c1;
    
    // C2 = secret*G2 + t2*H
    const s = ec.keyFromPrivate(Buffer.from(secret.toString(16).padStart(64, '0'), 'hex')).getPrivate();
    const t2_bn = ec.keyFromPrivate(Buffer.from(t2.toString(16).padStart(64, '0'), 'hex')).getPrivate();
    let c2 = G2.mul(s).add(H.mul(t2_bn));

    // Random values for zero-knowledge proof
    let r1 = BigIntMod(555n);
    let r2 = BigIntMod(444n);
    let r3 = BigIntMod(222n);

    // Commitments for proof
    let c3 = commit(r1.toString(16), r2.toString(16));
    
    const r1_bn = ec.keyFromPrivate(Buffer.from(r1.toString(16).padStart(64, '0'), 'hex')).getPrivate();
    const r3_bn = ec.keyFromPrivate(Buffer.from(r3.toString(16).padStart(64, '0'), 'hex')).getPrivate();
    let c4 = G2.mul(r1_bn).add(H.mul(r3_bn));

    // Challenge (should use Fiat-Shamir)
    let k = BigIntMod(666666n);

    // Responses
    const s_bn = BigIntMod(secret);
    const t1_bn = BigIntMod(t1);
    const t2_bn_mod = BigIntMod(t2);
    
    let z1 = modAdd(modMul(k, s_bn), r1);
    let z2 = modAdd(modMul(k, t1_bn), r2);
    let z3 = modAdd(modMul(k, t2_bn_mod), r3);

    return {
        out: {
            secret: modMul(s_bn, s_bn), // secret²
            t: modAdd(modMul(s_bn, t1_bn), t2_bn_mod), // secret*t1 + t2
            commit: c2
        },
        env: {
            c1,
            c2
        },
        proof: {
            c3: pointToHex(c3),
            c4: pointToHex(c4),
            k: k.toString(16),
            z1: z1.toString(16),
            z2: z2.toString(16),
            z3: z3.toString(16)
        }
    };
};

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
//#region Pedersen Equal Secrets (Elliptic Curve Version)

const bond_commit_equal_commit = (c1, t1, c2, t2) => {
    // Calculate difference: r = t1 - t2
    const t1_bn = BigIntMod(t1);
    const t2_bn = BigIntMod(t2);
    const r = modSub(t1_bn, t2_bn);
    
    return {
        env: {
            c1, 
            c2
        },
        proof: {
            r: r.toString(16)
        }
    };
};

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
//#region Pedersen Equal Value (Schnorr Protocol on EC)

const bond_commit_equal_secret = (ped_commit, ped_secret, ped_t) => {
    // Schnorr protocol to prove knowledge of discrete log
    const x = BigIntMod(ped_t); // Private key
    
    // Calculate public key: Y = x*H (the blinding part of commitment)
    const Y = H.mul(x);

    // Random nonce
    const r = BigIntMod(33n);
    const u = H.mul(r); // Commitment to randomness

    // Challenge (should use Fiat-Shamir hash)
    const c = BigIntMod(66n);

    // Response: z = r + c*x
    const z = modAdd(r, modMul(c, x));

    return {
        env: {
            secret: BigIntMod(ped_secret),
            c: ped_commit,
            Y: Y // Public key = t*H
        },
        proof: {
            u: pointToHex(u),
            c: c.toString(16),
            z: z.toString(16)
        }
    };
};

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

// Setup
const inputs = {
    a: 19,
    b: 3,
    c: 5,
    x: 1
};

const data = fs.readFileSync('./be_bit.dim', 'utf8');

// Running
const receipt = fs.createWriteStream('receipt.dim');
const dimp = new Dimperpreter(data);
const memRand = {};
const memSecrets = {};
let args = [];
let i = 0;
let secret = 0n;
let rand = 0n;
let x = 0n;
let sumSecret, sumRand;
let proof = null;
let temp = "";

while(true) {
    args = dimp.Next();
    if(args.length <= 0)
        break;
    
    i = args.length;
    while(i--)
        args[i] = args[i].trim();
    
    switch(args[0]) {
        case "log":
            console.log(memSecrets);
            break;
        case "input":
            secret = BigInt(inputs[args[1]]);
            rand = BigInt(Math.floor(Math.random() * 1000000));
            memSecrets[args[1]] = secret;
            memRand[args[1]] = rand;
            await receipt.write(pointToHex(commit(secret, rand)) + ";\n");
            console.log("signal input", args[1], "<==", secret.toString());
            break;
            
        case "commit":
            secret = BigInt(math.evaluate(args[2], 
                Object.fromEntries(Object.entries(memSecrets).map(([k,v]) => [k, Number(v)]))));
            
            // Handle negative values by converting to positive modulo q
            // -9 becomes q - 9 (which is the additive inverse in the field)
            if (secret < 0n) {
                secret = q.sub(BigIntMod(-secret));
            } else {
                secret = BigIntMod(secret);
            }
            
            rand = BigInt(Math.floor(Math.random() * 1000000));
            memSecrets[args[1]] = BigInt('0x' + secret.toString(16));
            memRand[args[1]] = rand;
            await receipt.write(pointToHex(commit(BigInt('0x' + secret.toString(16)), rand)) + ";\n");
            console.log("signal", args[1], "<--", args[2], "\t//", memSecrets[args[1]].toString());
            break;
            
        case "sum":
            // Calculate new secret as sum of weighted values
            sumSecret = BigIntMod(0n);
            sumRand = BigIntMod(0n);
            
            for(i = 2; i < args.length; i++) {
                if(i % 2 == 0) {
                    switch(args[i][0]) {
                        case '.':
                            x = BigIntMod(Math.ceil(Number(BigInt(q)) * parseFloat(args[i])));
                            //console.log(BigInt(q) / 2n);
                            //x = BigIntMod(Number(BigInt(q)) / 2n + 1n);
                            break;
                        case '/':
                            const divisor = args[i].substring(1);
                            // For elliptic curves, division is multiplication by modular inverse
                            const divisorBN = BigIntMod(divisor);
                            // Calculate modular inverse: divisor^(-1) mod q
                            x = divisorBN.invm(q);
                            break;
                        default:
                            x = BigIntMod(args[i]);
                            break;
                    }
                } else {
                    // Add weighted secret and randomness
                    const varSecret = BigIntMod(memSecrets[args[i]]);
                    const varRand = BigIntMod(memRand[args[i]]);
                    
                    sumSecret = modAdd(sumSecret, modMul(x, varSecret));
                    sumRand = modAdd(sumRand, modMul(x, varRand));
                }
            }
            
            // Store new secret and randomness
            memSecrets[args[1]] = BigInt('0x' + sumSecret.toString(16));
            memRand[args[1]] = BigInt('0x' + sumRand.toString(16));
            
            temp = "";
            for(i = 2; i < args.length; i++) {
                if(i % 2 == 0)
                    temp += args[i] + "*";
                else
                    temp += args[i] + " + ";
            }
            console.log("signal", args[1], "<==", temp + "0", "\t//", memSecrets[args[1]].toString());
            break;
            
        case "equal":
            proof = bond_commit_equal_secret(
                commit(memSecrets[args[1]], memRand[args[1]]),
                BigInt(args[2]),
                memRand[args[1]]
            );
            await receipt.write(proof.proof.u + "," + proof.proof.c + "," + proof.proof.z + ";\n");
            console.log(args[1], "===", args[2], "\t//", 
                verify_bond_commit_equal_secret(proof.env, proof.proof) ? "✅" : "❌");
            break;
            
        case "square":
            secret = memSecrets[args[2]];
            rand = memRand[args[2]];
            proof = commit_squared(secret, rand);
            
            // Store new secret (secret²) and new randomness
            memSecrets[args[1]] = BigInt('0x' + proof.out.secret.toString(16));
            memRand[args[1]] = BigInt('0x' + proof.out.t.toString(16));
            
            await receipt.write(pointToHex(proof.out.commit) + ";\n");
            await receipt.write(
                proof.proof.c3 + "," +
                proof.proof.c4 + "," +
                proof.proof.k + "," +
                proof.proof.z1 + "," +
                proof.proof.z2 + "," +
                proof.proof.z3 + ";\n"
            );
            console.log("signal", args[1], "<==", args[2], "*", args[2], "\t//", memSecrets[args[1]].toString(), "\t//", verify_SquareProof(proof.env, proof.proof) ? "✅" : "❌");
            break;
            
        case "same":
            proof = bond_commit_equal_commit(
                commit(memSecrets[args[1]], memRand[args[1]]),
                memRand[args[1]],
                commit(memSecrets[args[2]], memRand[args[2]]),
                memRand[args[2]]
            );
            await receipt.write(proof.proof.r + ";\n");
            console.log(args[1], "===", args[2], "\t//", 
                verify_bond_commit_equal_commit(proof.env, proof.proof) ? "✅" : "❌");
            break;
    }
}

receipt.end();

//#endregion
import {Dimperpreter, DimProtect} from './dimperpreter.js';
import fs from "node:fs";

//================================================================
//#region Modular Math

//https://www.boxentriq.com/code-breaking/modular-exponentiation

const powermod = (a, b, p) => {
    let r = 1n;
    while(b){
        if(b & 1n)
            r = (r * a) % p;
        a = (a * a) % p;
        b >>= 1n;
    }
    return r;
};
const multi = (a, b, p) => (a * b) % p;
const add = (a, b, p) => (a + b) % p;
const commit = (secret, rand, g, h, p) => multi(powermod(g, secret,p), powermod(h, rand, p), p);
const BigIntMod = (v, p) => {
    v = BigInt(v);
    while(v < 0)
        v += p;
    return v % p;
}

//#endregion

//================================================================
//#region Pedersen Squared

//returns a squared commitment
const commit_squared = (secret, t1, g, h, p, q) => {
    //get current commit
    let c1 = commit(secret, t1, g, h, p);

    //pick random t2
    let t2 = 456n;      // random blinding factor for c2

    //set new g
    let g2 = c1;        //THIS IS REQUIRED FOR THE VERIFIER TO BE SURE THAT THE NEW GENERATOR IS THE RESULT FOR
    
    let c2 = commit(secret, t2, g2, h, p);

    let r1 = 555n;
    let r2 = 444n;
    let r3 = 222n;

    let c3 = commit(r1, r2, g, h, p);
    let c4 = commit(r1, r3, g2, h, p);

    let k = 666666n;    //can use fiat shamir

    let z1 = (multi(k, secret, q) + r1) % q;
    let z2 = (multi(k, t1, q) + r2) % q;
    let z3 = (multi(k, t2, q) + r3) % q;

    //verification
    //let check1 = multi(c3, powermod(c1, k, p), p) == commit(z1, z2, g, h, p);
    //let check2 = multi(c4, powermod(c2, k, p), p) == commit(z1, z3, g2, h, p);
    //console.log(check1, check2);

    return {
        out:{
            secret: multi(secret, secret, q),   //maybe q
            t: (multi(secret, t1, q) + t2) % q,
            g: g,
            h: h,
            p: p,
            q: q,
            commit: c2 // commit(secret_new, t_new, g, h, p)
        },
        env:{
            g,
            h,
            p,
            c1,
            c2
        },
        proof:{
            //r1,r2,r3,
            c3,c4,
            k,
            z1,z2,z3
        }
    };
};

const verify_SquareProof = (env, proof) => {
    //general info
    const g = env.g;
    const h = env.h;
    const p = env.p;

    //commits to check
    const c1 = env.c1;
    const c2 = env.c2;

    //Proof of Squared Commitments
    const g2 = c1;

    //map proof values
    const c3 = proof.c3;
    const c4 = proof.c4;
    const z1 = proof.z1;
    const z2 = proof.z2;
    const z3 = proof.z3;

    //calculate challenge
    const k = proof.k;  //Fiat-Shamir

    //Proof of Equal Commitments with Different Binding Generators 
    const check1 = multi(c3, powermod(c1, k, p), p) == commit(z1, z2, g, h, p);
    const check2 = multi(c4, powermod(c2, k, p), p) == commit(z1, z3, g2, h, p);

    //result
    return check1 && check2;
};

//#endregion

//================================================================
//#region Pedersen Equal Secrets

const bond_commit_equal_commit = (c1, t1, c2, t2, g, h, p, q) => {
    //calculate envs
    //const c1 = commit(secret, t1, g, h, p);
    //const c2 = commit(secret, t2, g, h, p);
    
    //calculate difference
    const r = (t1 - t2 + q) % q;
    
    //result
    return {
        env: {
            g,
            h,
            p,
            q,
            c1, c2
        },
        proof:{
            r
        }
    };
};

const verify_bond_commit_equal_commit = (env, proof) => {
    //general
    const c1 = env.c1;
    const c2 = env.c2;
    const p = env.p;
    const h = env.h;

    //proof
    const r = proof.r;

    //get inversion of c2
    const inv_c2 = powermod(c2, p - 2n, p);
    
    //check
    return multi(c1, inv_c2, p) == powermod(h, r, p);
};

//#endregion

//================================================================
//#region Pedersen Equal Value 

const bond_commit_equal_secret = (ped_commit, ped_secret, ped_t, ped_g, ped_h, ped_p, ped_q) => {
    //calculate envs
    //https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/schnorr/

    //get values
    const x = ped_t;
    //const h = powermod(ped_h, ped_t, ped_p);
    const g = ped_h;
    const p = ped_p;
    //const q = ped_q;

    //shnorr here
    const r = 33n;  //in q
    const u = powermod(g, r, p);
    const c = 66n; //Fiat shamir //in q
    const z = add(r, multi(x, c, p), p);

    //result
    return {
        env: {
            g: ped_g,
            h: ped_h,
            p: ped_p,
            q: ped_q,
            secret: ped_secret,
            c: ped_commit
        },
        proof:{
            u,
            c,
            z
        }
    };
};

const verify_bond_commit_equal_secret = (env, proof) => {
    //h to check
    const h = multi(env.c, powermod(powermod(env.g, env.secret, env.p), env.p - 2n, env.p), env.p);

    //general
    const g = env.h;
    const p = env.p;

    //get shnorr data
    const u = proof.u;
    const c = proof.c; //should be recomputed
    const z = proof.z;

    //checl
    const check1 = z > 0n;
    //check c (hash)...
    const check2 = powermod(g, z, p) == multi(u, powermod(h, c, p), p);

    //return
    return check1 && check2;
};

//#endregion

//================================================================
//#region Main

let p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
let g = 3n;
let q = p - 1n;

//check
console.log(powermod(g, q, p)); //must
let h = powermod(g, 33n, p);//Hash(g);   //trusted setup



//Running
const dimpCode = new Dimperpreter(fs.readFileSync('./negate.dim', 'utf8'));
const dimpReceipt = new Dimperpreter(fs.readFileSync('./receipt.dim', 'utf8'));
const memCommits = {};
let args = [];
let proof = [];
let i = 0;
let com = 0n;
let x = 0n;
let sumCommits = 0n;
let proofEnv = null;
let proofProof = null;
let verification = false;
while(true){
    //read next
    args = dimpCode.Next();
    if(args.length <= 0)
        break;
    //trim args
    i = args.length;
    while(i--)
        args[i] = args[i].trim();
    console.log(args);
    //interpret
    switch(args[0]){
        case "input":
            com = BigIntMod(dimpReceipt.Next()[0], p);
            memCommits[args[1]] = com;
            break;
        case "commit":
            com = BigIntMod(dimpReceipt.Next()[0], p);
            memCommits[args[1]] = com;
            break;
        case "sum":
            x = 0n;
            sumCommits = 1n;
            for(i = 2; i < args.length; i++){
                if(i % 2 == 0)
                    x = BigIntMod(args[i], p);
                else
                    sumCommits = multi(sumCommits, powermod(memCommits[args[i]], x, p), p);
            }
            memCommits[args[1]] = sumCommits;
            break;
        case "equal_secret":
            proof = dimpReceipt.Next();
            proofEnv = {
                c: memCommits[args[1]],
                secret: BigIntMod(args[2], p),
                g,h,p,q
            };
            proofProof = {
                u: BigIntMod(proof[0], p),
                c: BigIntMod(proof[1], p),
                z: BigIntMod(proof[2], p)
            };
            verification = verify_bond_commit_equal_secret(proofEnv, proofProof);
            console.log(verification ? "✅" : "❌", args[1], "===", args[2]);
            break;
    }

}

//#endregion
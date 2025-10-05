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


const commit_squared = (secret, t1, g, h, p) => {
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

    let z1 = (multi(k, secret, p) + r1) % p;
    let z2 = (multi(k, t1, p) + r2) % p;
    let z3 = (multi(k, t2, p) + r3) % p;

    //verification
    //let check1 = multi(c3, powermod(c1, k, p), p) == commit(z1, z2, g, h, p);
    //let check2 = multi(c4, powermod(c2, k, p), p) == commit(z1, z3, g2, h, p);
    //console.log(check1, check2);

    return {
        out:{
            secret: multi(secret, secret, p),
            t: (multi(secret, t1, p) + t2) % p,
            g: g,
            h: h,
            p: p,
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

let p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
let g = 3n;
let h = powermod(g, 33n, p);//Hash(g);   //trusted setup

//console.log(powermod(g, p, p));


//===========================================


let secret = 69n;   // Alice’s secret
let t1 = 123n;      // random blinding factor for c1
let t2 = 456n;      // random blinding factor for c2

// Commit to s
let c1 = commit(secret, t1, g, h, p);

/*
// Commit to s^2
//let c2 = commit(secret * secret % p, t2, g, h, p);
let g2 = c1;        //THIS IS REQUIRED FOR THE VERIFIER TO BE SURE THAT THE NEW GENERATOR IS THE RESULT FOR
let c2 = commit(secret, t2, g2, h, p);

console.log("Commitment to s:", c1.toString());
console.log("Commitment to s^2:", c2.toString());

//===========================================
//Proof of Equal Commitments with Different Binding Generators 

let r1 = 555n;
let r2 = 444n;
let r3 = 222n;

let c3 = commit(r1, r2, g, h, p);
let c4 = commit(r1, r3, g2, h, p);


let k = 666666n;    //can use fiat shamir


let z1 = (multi(k, secret, p) + r1) % p;
let z2 = (multi(k, t1, p) + r2) % p;
let z3 = (multi(k, t2, p) + r3) % p;



let check1 = multi(c3, powermod(c1, k, p), p) == commit(z1, z2, g, h, p);
let check2 = multi(c4, powermod(c2, k, p), p) == commit(z1, z3, g2, h, p);
console.log(check1, check2);


//===========================================

//simplify out commit

let t3 = ((secret * t1) % p + t2) % p;
secret = multi(secret, secret, p);
console.log(commit(secret, t3, g, h, p));
*/

secret = 333333n;
let c = commit_squared(secret, t1, g, h, p);
console.log(c);
console.log(verify_SquareProof(c.env, c.proof));
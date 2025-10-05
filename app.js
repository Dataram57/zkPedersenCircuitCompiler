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


//returns a squared commitment
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


let q = p - 1n;

//check
console.log(powermod(g, q, p)); //must


let h = powermod(g, 33n, p);//Hash(g);   //trusted setup

//console.log(powermod(g, p, p));


//===========================================


let secret = 69n;
let t = 123n;
let t2 = 456n;

let c1 = commit(secret, t, g, h, p);
let c2 = commit(secret, t2, g, h, p);

let r = (t - t2 + q) % q;

let inv_c2 = powermod(c2, p - 2n, p);

let a = powermod(h, r, p);
let b = multi(c1, inv_c2, p);
const check = a == b;
console.log(a, b, check);

/*
let c1 = commit(secret, t, g, h, p);
let c2 = commit_squared(secret, t, g, h, p);
console.log(verify_SquareProof(c2.env, c2.proof));
let c3 = commit_squared(c2.out.secret, c2.out.t, g, h, p);
console.log(verify_SquareProof(c3.env, c3.proof));
*/
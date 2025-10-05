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

const bond_equal_commits = (c1, t1, c2, t2, g, h, p, q) => {
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

const verify_bond_equal_commits = (env, proof) => {
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


let p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
let g = 3n;


let q = p - 1n;

//check
console.log(powermod(g, q, p)); //must


let h = powermod(g, 33n, p);//Hash(g);   //trusted setup

//console.log(powermod(g, p, p));


//===========================================


let secret = 2n;
console.log("secret is", secret);   
let t = 123n;

//circuit that makes
let c = commit(secret, t, g, h, p);
let c_squared = commit_squared(secret, t, g, h, p, q);
let c_squared_bond = bond_equal_commits(c, t, c_squared.out.commit, c_squared.out.t, g, h, p, q);
const constrain1 = verify_SquareProof(c_squared.env, c_squared.proof);
const constrain2 = verify_bond_equal_commits(c_squared_bond.env, c_squared_bond.proof);
console.log("is secret a bit?", constrain1, "&&",constrain2, "=",constrain1 && constrain2);

/*
let c1 = commit(secret, t, g, h, p);
let c2 = commit_squared(secret, t, g, h, p, q);
console.log(verify_SquareProof(c2.env, c2.proof));
let c3 = commit_squared(c2.out.secret, c2.out.t, g, h, p, q);
console.log(verify_SquareProof(c3.env, c3.proof));
*/
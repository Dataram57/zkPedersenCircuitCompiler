// pedersen_equal_proof.js
// Node.js (>=12) script demonstrating "Proof of Equal Commitments with Different Binding Generators"
// - interactive sigma protocol (simulated)
// - non-interactive Fiat-Shamir variant

const crypto = require('crypto');

// --- basic big-int modular helpers ---
const powermod = (a, b, p) => {
    a = ((a % p) + p) % p;
    let r = 1n;
    while (b > 0n) {
        if (b & 1n) r = (r * a) % p;
        a = (a * a) % p;
        b >>= 1n;
    }
    return r;
};
const modMul = (a, b, p) => ((a % p) * (b % p)) % p;
const modAdd = (a, b, p) => ((a % p) + (b % p)) % p;

// --- hash -> BigInt (for Fiat-Shamir challenge) ---
function sha256ToBigInt(...items) {
    // items: array of BigInt or strings; we concatenate hex representations
    const hash = crypto.createHash('sha256');
    for (const it of items) {
        if (typeof it === 'bigint') {
            // convert to hex string without 0x, zero-pad minimally
            let hex = it.toString(16);
            if (hex.length % 2) hex = '0' + hex;
            hash.update(Buffer.from(hex, 'hex'));
        } else if (Buffer.isBuffer(it)) {
            hash.update(it);
        } else {
            hash.update(String(it));
        }
    }
    const digest = hash.digest('hex');
    return BigInt('0x' + digest);
}

// --- Pedersen commit ---
const commit = (secret, rand, g, h, p) =>
    modMul(powermod(g, secret, p), powermod(h, rand, p), p);

// --- Protocol: Proof of equal committed exponent s in
//     c1 = g1^s * h^t1  and  c2 = g2^s * h^t2
//
// Prover:
//   - picks r1,r2,r3 at random
//   - computes a1 = g1^r1 * h^r2
//             a2 = g2^r1 * h^r3
//   - gets challenge e (from verifier or Fiat-Shamir)
//   - computes z1 = r1 + e*s
//             z2 = r2 + e*t1
//             z3 = r3 + e*t2
// Verifier checks:
//   g1^{z1} h^{z2} == a1 * c1^e
//   g2^{z1} h^{z3} == a2 * c2^e
//
// We'll implement both interactive (simulated) and non-interactive (Fiat-Shamir)
// Important: e must be reduced modulo group order q. For demo we use q = p (caveat below).

// --- Utility random BigInt in [0, q-1] ---
function randomBigIntBelow(q) {
    // sample bytes long enough for q
    const nbytes = Math.ceil((q.toString(2).length) / 8);
    while (true) {
        const rb = crypto.randomBytes(nbytes);
        let val = BigInt('0x' + rb.toString('hex'));
        if (val < q) return val;
    }
}

// --- Prover (produces proof) ---
function proverProduceProof({
    s, t1, t2, g1, g2, h, p, useFiatShamir = true, label = 'pedersen-eq'
}) {
    // NOTE: For correct security you should use the group's prime order `q` (not p).
    // For demo we will reduce challenges modulo `q = p` (acceptable for demonstration only).
    const q = p;

    const r1 = randomBigIntBelow(q);
    const r2 = randomBigIntBelow(q);
    const r3 = randomBigIntBelow(q);

    const a1 = modMul(powermod(g1, r1, p), powermod(h, r2, p), p);
    const a2 = modMul(powermod(g2, r1, p), powermod(h, r3, p), p);

    // produce challenge e
    let e;
    if (useFiatShamir) {
        // Fiat–Shamir: hash(g1,g2,h,c1,c2,a1,a2,label)
        // We'll expect the caller computed c1,c2; so include them in args later
        // For convenience we compute here after we expect c1,c2 passed in context
        e = null; // caller will compute using helper with c1,c2
    } else {
        // interactive: verifier will supply e (simulated externally)
        e = null;
    }

    return { a1, a2, r1, r2, r3, makeResponse: (eVal) => {
        const z1 = (r1 + eVal * s) % q;
        const z2 = (r2 + eVal * t1) % q;
        const z3 = (r3 + eVal * t2) % q;
        return { z1, z2, z3 };
    }};
}

// --- Verifier check ---
function verifierCheck({
    g1, g2, h, p, c1, c2, a1, a2, z1, z2, z3, e
}) {
    // check 1: g1^{z1} h^{z2} == a1 * c1^e mod p
    const left1 = modMul(powermod(g1, z1, p), powermod(h, z2, p), p);
    const right1 = modMul(a1, powermod(c1, e, p), p);

    const left2 = modMul(powermod(g2, z1, p), powermod(h, z3, p), p);
    const right2 = modMul(a2, powermod(c2, e, p), p);

    return left1 === right1 && left2 === right2;
}

// --- Demo run ---
(function demo() {
    // Example prime (BN254 field prime from your earlier code)
    const p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const g = 3n;
    // derive h for demo from g to have a generator-like element (NOT a secure setup)
    const h = powermod(g, 33n, p);

    // Example secret and randomness
    const s = 69n;        // the secret exponent
    const t1 = 123n;      // blinding for c1
    const t2 = 456n;      // blinding for c2

    // Case A: general equal-commitments with different binding generators
    // choose a second generator g2 (for demo we can choose powermod(g, 7) - in practice must be independent)
    const g2 = powermod(g, 7n, p);
    const c1 = commit(s, t1, g, h, p);      // c1 = g^s h^{t1}
    const c2 = commit(s, t2, g2, h, p);     // c2 = g2^s h^{t2}

    console.log('=== Demo: equal exponent s in c1 and c2 (different g1,g2) ===');
    console.log('c1:', c1.toString());
    console.log('c2:', c2.toString());

    // Prover builds a1,a2
    const prover = proverProduceProof({ s, t1, t2, g1: g, g2, h, p, useFiatShamir: true });

    // Non-interactive Fiat-Shamir: derive e = H(domain||g||g2||h||c1||c2||a1||a2) mod q
    const q = p; // demo only: use group order in real system
    const eBigHash = sha256ToBigInt('FS', g, g2, h, c1, c2, prover.a1, prover.a2, 'proof-eq');
    const e = eBigHash % q;

    // Prover computes responses
    const resp = prover.makeResponse(e);

    // Verifier checks
    const ok = verifierCheck({
        g1: g, g2, h, p, c1, c2,
        a1: prover.a1, a2: prover.a2,
        z1: resp.z1, z2: resp.z2, z3: resp.z3, e
    });

    console.log('Fiat-Shamir non-interactive proof verification:', ok);

    // ---------------------------------------------------------------------
    // Case B: the "squared commitment" trick from zkdocs:
    // let g2 = c1 (use c1 as binding generator), and c2 = c1^s * h^{t2}
    // This makes c2 correspond to g^{s^2} * h^{s*t1 + t2}
    const c1_sq = c1;
    const g2_sq = c1_sq;
    const c2_linked = modMul(powermod(c1_sq, s, p), powermod(h, t2, p), p);

    console.log('\n=== Demo: squared-commitment trick (g2 = c1) ===');
    console.log('c1:', c1.toString());
    console.log('c2_linked (should commit to s^2):', c2_linked.toString());

    // Prove equality of exponent s between:
    //  c1 = g^s h^{t1}  and  c2_linked = (c1)^s h^{t2}
    const prover2 = proverProduceProof({ s, t1, t2, g1: g, g2: g2_sq, h, p, useFiatShamir: true });
    // derive e
    const e2 = sha256ToBigInt('FS', g, g2_sq, h, c1, c2_linked, prover2.a1, prover2.a2, 'proof-eq2') % q;
    const resp2 = prover2.makeResponse(e2);
    const ok2 = verifierCheck({
        g1: g, g2: g2_sq, h, p, c1, c2: c2_linked,
        a1: prover2.a1, a2: prover2.a2,
        z1: resp2.z1, z2: resp2.z2, z3: resp2.z3, e: e2
    });
    console.log('Fiat-Shamir proof (s equality for squared trick) verification:', ok2);

    // For clarity show that c2_linked equals a direct commit to s^2 (with effective randomness)
    const s2 = (s * s) % p; // s^2
    const t2_effective = (s * t1 + t2) % p;
    const c2_direct = commit(s2, t2_effective, g, h, p); // this equals c2_linked up to algebra
    console.log('c2_direct (g^{s^2} h^{s*t1 + t2}):', c2_direct.toString());
    console.log('c2_linked == c2_direct ?', c2_direct === c2_linked);
})();

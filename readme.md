# zkPedersenCircuitCompiler

Write blind programs and make computation prove-able.

### Goal

This was my attempt of recreating ZK crypto system (like zkSNARK) that could serve a safe and verified runner of the app written in language described here.

### Reality check:

ZkSNARKs already give you a decent and much more efficient solution than this.

### Comparison

| Feature | This | zkSNARKs |
| :--: | :--: | :--: |
| Proof size | infinite | constant |
| Circuit gate count | infinite  | <=Trusted Setup | 
| Trusted Setup | Done via Fiat-Shamir | Ceremony required | 

# Running

Requirements: `npm install mathjs`

- `proof.js` - generates proof of the transaction (`receipt.dim`).
- `verify.js`- verifies proof of the transaction (`receipt.dim`).

### Conversion to ECC with AI

***Be cautious and suspicious of AI solutions as I haven't and probably will not verify them.***

Requirements: `npm install elliptic`

- `ai_proof_ecc.js` - generates proof of the transaction (`receipt.dim`).
- `ai_verify_ecc.js`- verifies proof of the transaction (`receipt.dim`).

# Language

All circuits are written in the pseudo assembly-like language called dim, and all of them have `.dim` extension.

Commitments:
- `input, NEW_COMMITMENT;` - Commits to a value from the input.
- `commit, NEW_COMMITMENT, EXPRESSION;` - Commits to a given expression.

Operations:
- `sum, NEW_COMMITMENT, SCALAR, COMMITMENT,...;` - Commits to the sum of all of the given secrets multiplied by the corresponding scalar from given commitments. (Based on [Pedersen: The Additive Property](https://www.zkdocs.com/docs/zkdocs/commitments/pedersen/#the-additive-property))
- `square, NEW_COMMITMENT, REFERENCE_COMMITMENT` - Commits to a secret that is a square of the secret from the reference commitment. (Based on [Pedersen: Proof of Squared Commitments](https://www.zkdocs.com/docs/zkdocs/commitments/pedersen/#proof-of-squared-commitments))

Constraints:
- `same, COM_A, COM_B;` - Proofs that the commitments `A` and `B` commit to the same secret. (Based on [Pedersen: An Easy Proof of Equal Commitments](https://www.zkdocs.com/docs/zkdocs/commitments/pedersen/#an-easy-proof-of-equal-commitments))
- `equal, COM, VALUE;` - Proofs that the commitment commits to a specific secret. (Based on [Schnorr’s identification protocol](https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/schnorr/)) 

# Examples

### Negation of Secrets:

Comparison constraints:

$$a+\left(-a\right)=0$$

Code:
```
input, a;
commit,neg_a, -a;
sum,s1, 1,a, 1,neg_a;
equal, s1, 0;
```

### Secret is a bit:

Comparison constraints:

$$x=x^{2}$$

This forces $x$ to be either $0$ or $1$.

Code:
```
input, x;
square,sq_x, x;
same, sq_x, x;
```

### Multiplication of Secrets :

General way of computing the multiplication of secrets:

$$a\cdot b=\frac{\left(a+b\right)^{2}-a^{2}-b^{2}}{2}$$

Comparison constraints:

$$
\begin{cases}
a^{2} + (-a^{2}) = 0 \\
b^{2} + (-b^{2}) = 0
\end{cases}
$$

Additions:

$$
\text{top} = 1\cdot\left(a+b\right)^{2}+1\cdot\left(-a^{2}\right)+1\cdot\left(-b^{2}\right)
$$

$$
\text{out} = \frac{\text{top}}{2} \tag{2}
$$



Code:
```
input, a;
input, b;

sum, sum_ab,
    1, a,
    1, b;
square, squared_sum_ab, sum_ab;

square, squared_a, a;
commit, negated_squared_a, (-1) * squared_a;
sum, sum_constraint_a,
    1, squared_a,
    1, negated_squared_a; 
equal, sum_constraint_a, 0;

square, squared_b, b;
commit, negated_squared_b, (-1) * squared_b;
sum, sum_constraint_b,
    1, squared_b,
    1, negated_squared_b;
equal, sum_constraint_b, 0;

sum, top,
    1, squared_sum_ab,
    1, negated_squared_a,
    1, negated_squared_b;

sum, out,
    /2, top;
```

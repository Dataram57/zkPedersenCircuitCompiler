# Running

- `proof.js` - generates proof of the transaction (`receipt.dim`).
- `verify.js`- verifies proof of the transaction (`receipt.dim`).

# Goal

This was my attempt of recreating ZK crypto system (like zkSNARK) that could serve a safe and verified runner of the app written in language described here.

### Reality check:

ZkSNARKs already give you a decent and much more efficient solution than this.

### Comparison

| Feature | This | zkSNARKs |
| :--: | :--: | :--: |
| Proof size | infinite | constant |
| Circuit gate count | infinite  | <=Trusted Setup | 

# Examples

### Negation of Secrets:
Constraints:
$$a+\left(-a\right)=0$$

Code:
```
input, a;
commit,neg_a, -a;
sum,s1, 1,a, 1,neg_a;
equal, s1, 0;
```

### Secret is a bit:

Constraints:
$$a=a^{2}$$

Code:
```
input, x;
square,sq_x, x;
same, sq_x, x;
```

### Multiplication of Secrets :

General way of computing the multiplication of secrets:
$$a\cdot b=\frac{\left(a+b\right)^{2}-a^{2}-b^{2}}{2}$$

Constraints:
$$
\left\{
\begin{aligned}
a^{2}+\left(-a^{2}\right)=0 \\
b^{2}+\left(-b^{2}\right)=0
\end{aligned}
\right.
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
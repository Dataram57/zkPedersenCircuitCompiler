

# Language

### Templates

Defining:
```
template(args) MyCircuit(input_nodes){
    //...code, constrains...
};
```

Using:

```
MyCircuit(args) c(input_nodes);
//c.something...
```

### Nodes

- `b = a` - `b`'s value is said to be `a`. ***No verification of putting different value.***

### Automatic nodes

```
//sum = a + 14*b + (1/2)*c + d 
sum += [
    a
    ,[14, b]
    ,[1/2, c]
    ,d
];
```
Based on [The Additive Property](https://www.zkdocs.com/docs/zkdocs/commitments/pedersen/#the-additive-property).

Makes usage of homomorphic properties.

### Native components

- `square b(a)` - `b`'s value is and must be a square of `a`'s value. Based on [Proof of Squared Commitments](https://www.zkdocs.com/docs/zkdocs/commitments/pedersen/#proof-of-squared-commitments) and [Proof of Equal Commitments with Different Binding Generators](https://www.zkdocs.com/docs/zkdocs/commitments/pedersen/#proof-of-equal-commitments-with-different-binding-generators)

### Constrains

- `a === b` - `a`'s value must be equal `b`'s value. Based on [An Easy Proof of Equal Commitments](https://www.zkdocs.com/docs/zkdocs/commitments/pedersen/#an-easy-proof-of-equal-commitments).
- `a === NUMBER` - `a`'s value must be equal `NUMBER`. Based on [Schnorr’s identification protocol - Non-interactive protocol](https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/schnorr/#non-interactive-protocol).
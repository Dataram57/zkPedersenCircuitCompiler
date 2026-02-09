import { create, all } from 'mathjs';

const math = create(all);

// expression with variables
const expr = "a * b + sqrt(c)";

const result = math.evaluate(expr, { a: 5, b: 10, c: 16 });
console.log(result); // 5*10 + 4 = 54

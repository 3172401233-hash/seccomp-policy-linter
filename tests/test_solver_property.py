import random
import unittest

from seccomp_linter.model import Condition, Operator, UINT64_MAX
from seccomp_linter.solver import (
    evaluate,
    is_subset,
    solve,
    witness_matches,
)


OPS = [
    Operator.EQ,
    Operator.NE,
    Operator.LT,
    Operator.LE,
    Operator.GT,
    Operator.GE,
    Operator.MASKED_EQ,
    Operator.MASKED_NE,
]


def random_condition(rng, index=None):
    operator = rng.choice(OPS)
    if rng.random() < 0.4:
        mask = rng.choice([0x1, 0xF, 0xFF, 0xFFFF, 0xFFFFFFFF, UINT64_MAX])
    else:
        mask = UINT64_MAX
    value = rng.randrange(0, 1 << 16)
    return Condition(
        index=rng.randrange(0, 3) if index is None else index,
        operator=operator,
        value=value,
        mask=mask,
    )


class SolverPropertyTest(unittest.TestCase):
    def test_witnesses_always_evaluate_true(self):
        rng = random.Random(20261114)
        checked = 0
        for _ in range(400):
            conditions = [random_condition(rng, index=0) for _ in range(rng.randrange(1, 4))]
            witness = solve(conditions)
            if witness is None:
                continue
            checked += 1
            self.assertTrue(witness_matches(conditions, witness))
            for condition in conditions:
                self.assertTrue(evaluate(condition, witness[condition.index]))
        self.assertGreater(checked, 100)

    def test_solver_agrees_with_bruteforce(self):
        rng = random.Random(42)
        for _ in range(200):
            conditions = [
                random_condition(rng, index=0) for _ in range(rng.randrange(1, 3))
            ]
            # 小值域暴力枚举，掩码与比较值限制在 0..63。
            bounded = [
                Condition(
                    index=0,
                    operator=cond.operator,
                    value=cond.value & 0x3F,
                    mask=cond.mask & 0x3F,
                )
                for cond in conditions
            ]
            brute = any(
                all(evaluate(cond, value) for cond in bounded)
                for value in range(64)
            )
            witness = solve(bounded)
            self.assertEqual(brute, witness is not None, bounded)
            if witness is not None:
                self.assertLess(witness[0], 1 << 64)

    def test_subset_matches_bruteforce(self):
        rng = random.Random(7)
        for _ in range(200):
            subset = tuple(random_condition(rng, index=1) for _ in range(rng.randrange(1, 2)))
            superset = tuple(random_condition(rng, index=1) for _ in range(rng.randrange(1, 2)))
            bounded_sub = tuple(
                Condition(1, cond.operator, cond.value & 0x1F, cond.mask & 0x1F)
                for cond in subset
            )
            bounded_super = tuple(
                Condition(1, cond.operator, cond.value & 0x1F, cond.mask & 0x1F)
                for cond in superset
            )
            brute = all(
                not (
                    all(evaluate(c, v) for c in bounded_sub)
                    and not all(evaluate(c, v) for c in bounded_super)
                )
                for v in range(32)
            )
            self.assertEqual(
                brute,
                is_subset(bounded_sub, bounded_super),
                (bounded_sub, bounded_super),
            )


if __name__ == "__main__":
    unittest.main()

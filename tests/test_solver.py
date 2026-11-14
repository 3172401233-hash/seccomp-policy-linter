import unittest

from seccomp_linter.model import Condition, Operator, UINT64_MAX
from seccomp_linter.solver import (
    evaluate,
    intersection_witness,
    is_subset,
    negate,
    solve,
    witness_matches,
)


def cond(index, operator, value, mask=UINT64_MAX):
    return Condition(
        index=index,
        operator=Operator(operator),
        value=value,
        mask=mask,
    )


class SolverTest(unittest.TestCase):
    def assertWitness(self, conditions):
        witness = solve(conditions)
        self.assertIsNotNone(witness, "预期存在见证值")
        self.assertTrue(witness_matches(conditions, witness))
        return witness

    def assertUnsat(self, conditions):
        self.assertIsNone(solve(conditions), "预期条件合取不可满足")

    def test_open_ranges(self):
        witness = self.assertWitness(
            [cond(0, "GT", 100), cond(0, "LT", 200)]
        )
        self.assertLess(witness[0], 200)
        self.assertGreater(witness[0], 100)

    def test_boundary_values(self):
        self.assertEqual(
            solve([cond(0, "GE", 0), cond(0, "LE", 0)])[0], 0
        )
        self.assertEqual(
            solve([cond(0, "GE", UINT64_MAX)])[0], UINT64_MAX
        )

    def test_impossible_open_range(self):
        self.assertUnsat([cond(0, "LT", 10), cond(0, "GT", 10)])
        self.assertUnsat([cond(0, "LT", 5), cond(0, "GE", 5)])

    def test_masked_equality(self):
        # 只看低 8 位，高位置位不影响相等。
        witness = self.assertWitness(
            [cond(1, "MASKED_EQ", 0x0A, mask=0xFF)]
        )
        self.assertEqual(witness[1] & 0xFF, 0x0A)

    def test_multiple_masks_on_same_index(self):
        witness = self.assertWitness(
            [
                cond(0, "MASKED_EQ", 0x0F, mask=0x0F),
                cond(0, "MASKED_EQ", 0xF0, mask=0xF0),
            ]
        )
        self.assertEqual(witness[0] & 0x0F, 0x0F)
        self.assertEqual(witness[0] & 0xF0, 0xF0)

    def test_contradictory_masks(self):
        self.assertUnsat(
            [
                cond(0, "MASKED_EQ", 0x01, mask=0x01),
                cond(0, "MASKED_EQ", 0x00, mask=0x01),
            ]
        )

    def test_ne_constraint(self):
        witness = self.assertWitness(
            [cond(2, "NE", 7), cond(2, "LT", 10)]
        )
        self.assertNotEqual(witness[2], 7)
        self.assertLess(witness[2], 10)

    def test_ne_covering_whole_range(self):
        self.assertUnsat(
            [
                cond(0, "GE", 5),
                cond(0, "LE", 5),
                cond(0, "NE", 5),
            ]
        )

    def test_zero_mask_ne_is_free(self):
        witness = self.assertWitness([cond(0, "NE", 0, mask=0)])
        self.assertEqual(witness[0], 0)

    def test_multi_index_conjunction(self):
        witness = self.assertWitness(
            [
                cond(0, "GT", 1000),
                cond(3, "EQ", 42, mask=0xFF),
                cond(5, "LE", 0),
            ]
        )
        self.assertGreater(witness[0], 1000)
        self.assertEqual(witness[3] & 0xFF, 42)
        self.assertEqual(witness[5], 0)

    def test_negation_roundtrip(self):
        original = cond(1, "LE", 0x1234, mask=0xFFFF)
        negated = negate(original)
        self.assertIs(negated.operator, Operator.GT)
        self.assertEqual(negated.mask, 0xFFFF)
        for value in (0, 1, 0x1234, 0x1235, UINT64_MAX):
            self.assertNotEqual(
                evaluate(original, value), evaluate(negated, value)
            )

    def test_intersection_witness(self):
        witness = intersection_witness(
            (cond(0, "GE", 10),),
            (cond(0, "LE", 20), cond(1, "EQ", 3)),
        )
        self.assertIsNotNone(witness)
        self.assertTrue(10 <= witness[0] <= 20)
        self.assertEqual(witness[1], 3)

    def test_subset_direction(self):
        narrow = (cond(0, "GE", 10), cond(0, "LE", 20))
        wide = (cond(0, "GE", 5),)
        self.assertTrue(is_subset(narrow, wide))
        self.assertFalse(is_subset(wide, narrow))

    def test_subset_with_masks(self):
        narrow = (cond(0, "EQ", 0x03, mask=0x0F),)
        wide = (cond(0, "MASKED_EQ", 0x01, mask=0x01),)
        self.assertTrue(is_subset(narrow, wide))
        self.assertFalse(is_subset(wide, narrow))

    def test_witness_is_concrete_uint64(self):
        witness = solve([cond(0, "GT", 0)])
        self.assertIn(0, witness)
        self.assertIsInstance(witness[0], int)
        self.assertGreaterEqual(witness[0], 1)


if __name__ == "__main__":
    unittest.main()

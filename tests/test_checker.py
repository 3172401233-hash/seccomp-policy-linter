import unittest

from seccomp_linter import analyze, evaluate, load_policy, syscall_number
from seccomp_linter.model import (
    Action,
    CompleteOverlap,
    Condition,
    DuplicateRule,
    MutuallyExclusiveActions,
    Operator,
    PartialOverlap,
    Policy,
    Rule,
    UINT64_MAX,
    UnknownSyscall,
    UnreachableRule,
    UnsatisfiableRule,
)


def cond(index, operator, value, mask=UINT64_MAX):
    return Condition(
        index=index,
        operator=Operator(operator),
        value=value,
        mask=mask,
    )


def rule(index, action, syscalls, conditions=()):
    return Rule(
        index=index,
        action=Action(action),
        syscalls=tuple(syscalls),
        conditions=tuple(conditions),
    )


def policy(rules, arches=("x86_64",), default=Action.ALLOW):
    return Policy(
        architectures=arches,
        rules=tuple(rules),
        default_action=default,
    )


def kinds(findings):
    return [item.kind for item in findings]


def find(findings, kind):
    return next(item for item in findings if item.kind == kind)


class UnknownSyscallTest(unittest.TestCase):
    def test_unknown_name_reported(self):
        result = analyze(
            policy([rule(0, "ALLOW", ["definitely_not_a_syscall"])])
        )
        self.assertEqual(kinds(result), ["unknown_syscall"])
        self.assertIsInstance(result[0], UnknownSyscall)
        self.assertEqual(result[0].syscall, "definitely_not_a_syscall")

    def test_known_name_not_reported(self):
        result = analyze(policy([rule(0, "ALLOW", ["read", "write"])]))
        self.assertEqual(kinds(result), [])


class UnsatisfiableTest(unittest.TestCase):
    def test_trivial_false_mask_zero(self):
        result = analyze(
            policy(
                [rule(0, "DENY", ["read"], [cond(0, "EQ", 1, mask=0)])]
            )
        )
        self.assertEqual(kinds(result), ["unsatisfiable_rule"])
        self.assertIsInstance(result[0], UnsatisfiableRule)

    def test_trivial_false_value_escapes_mask(self):
        result = analyze(
            policy(
                [rule(0, "DENY", ["read"], [cond(0, "EQ", 0x10, mask=0x0F)])]
            )
        )
        self.assertEqual(kinds(result), ["unsatisfiable_rule"])

    def test_impossible_bounds(self):
        result = analyze(
            policy(
                [
                    rule(
                        0,
                        "DENY",
                        ["read"],
                        [cond(0, "LT", 5), cond(0, "GT", 5)],
                    )
                ]
            )
        )
        self.assertEqual(kinds(result), ["unsatisfiable_rule"])
        self.assertGreaterEqual(len(result[0].core), 1)

    def test_unsatisfiable_rule_excluded_from_overlaps(self):
        result = analyze(
            policy(
                [
                    rule(0, "ALLOW", ["read"], [cond(0, "GT", 1)]),
                    rule(
                        1,
                        "DENY",
                        ["read"],
                        [cond(0, "LT", 0)],
                    ),
                ]
            )
        )
        self.assertEqual(kinds(result), ["unsatisfiable_rule"])


class DuplicateTest(unittest.TestCase):
    def test_exact_duplicate(self):
        conditions = [cond(0, "EQ", 3)]
        result = analyze(
            policy(
                [
                    rule(0, "ALLOW", ["read"], conditions),
                    rule(1, "ALLOW", ["read"], conditions),
                ]
            )
        )
        self.assertEqual(kinds(result), ["complete_overlap", "duplicate_rule"])
        duplicate = find(result, "duplicate_rule")
        self.assertIsInstance(duplicate, DuplicateRule)
        self.assertEqual((duplicate.rule_index, duplicate.duplicate_of), (1, 0))

    def test_different_action_is_not_duplicate(self):
        conditions = [cond(0, "EQ", 3)]
        result = analyze(
            policy(
                [
                    rule(0, "ALLOW", ["read"], conditions),
                    rule(1, "KILL", ["read"], conditions),
                ]
            )
        )
        self.assertNotIn("duplicate_rule", kinds(result))


class OverlapTest(unittest.TestCase):
    def _witness_valid(self, finding, rules):
        by_index = {item.index: item for item in rules}
        for target in (by_index[finding.first], by_index[finding.second]):
            for condition in target.conditions:
                self.assertTrue(
                    evaluate(condition, finding.witness[condition.index])
                )

    def test_partial_overlap_with_witness(self):
        rules = [
            rule(0, "ALLOW", ["read"], [cond(0, "GT", 10)]),
            rule(1, "DENY", ["read"], [cond(0, "LT", 20)]),
        ]
        result = analyze(policy(rules))
        partial = find(result, "partial_overlap")
        self.assertIsInstance(partial, PartialOverlap)
        self.assertTrue(10 < partial.witness[0] < 20)
        self._witness_valid(partial, rules)

    def test_complete_overlap_subset(self):
        rules = [
            rule(
                0,
                "ALLOW",
                ["read"],
                [cond(0, "GE", 0), cond(0, "LE", 100)],
            ),
            rule(1, "DENY", ["read"], [cond(0, "EQ", 50)]),
        ]
        result = analyze(policy(rules))
        complete = find(result, "complete_overlap")
        self.assertIsInstance(complete, CompleteOverlap)
        self.assertEqual(complete.witness[0], 50)
        self.assertTrue(complete.action_conflict)
        self._witness_valid(complete, rules)

    def test_disjoint_ranges_no_overlap(self):
        result = analyze(
            policy(
                [
                    rule(0, "ALLOW", ["read"], [cond(0, "LT", 10)]),
                    rule(1, "DENY", ["read"], [cond(0, "GT", 20)]),
                ]
            )
        )
        self.assertEqual(kinds(result), [])

    def test_disjoint_syscalls_no_overlap(self):
        result = analyze(
            policy(
                [
                    rule(0, "ALLOW", ["read"]),
                    rule(1, "ALLOW", ["write"]),
                ]
            )
        )
        self.assertEqual(kinds(result), [])

    def test_mutually_exclusive_actions(self):
        result = analyze(
            policy(
                [
                    rule(0, "ALLOW", ["openat"], [cond(0, "GT", 1)]),
                    rule(1, "KILL", ["openat"], [cond(0, "LT", 9)]),
                ]
            )
        )
        mutex = find(result, "mutually_exclusive_actions")
        self.assertIsInstance(mutex, MutuallyExclusiveActions)
        self.assertEqual(mutex.relation, "partial_overlap")
        self.assertEqual(mutex.syscalls, ("openat",))
        self.assertTrue(1 < mutex.witness[0] < 9)

    def test_same_action_no_mutex(self):
        result = analyze(
            policy(
                [
                    rule(0, "DENY", ["openat"], [cond(0, "GT", 1)]),
                    rule(1, "DENY", ["openat"], [cond(0, "LT", 9)]),
                ]
            )
        )
        self.assertNotIn("mutually_exclusive_actions", kinds(result))


class UnreachableTest(unittest.TestCase):
    def test_broad_allow_shadows_deny(self):
        # 题目场景：一条过宽的 ALLOW 把后面的限制完全盖住。
        result = analyze(
            policy(
                [
                    rule(0, "ALLOW", ["socket"]),
                    rule(1, "DENY", ["socket"], [cond(0, "EQ", 1)]),
                ],
                default=Action.DENY,
            )
        )
        unreachable = find(result, "unreachable_rule")
        self.assertIsInstance(unreachable, UnreachableRule)
        self.assertEqual(unreachable.rule_index, 1)
        self.assertEqual(unreachable.covered_by, (0,))
        self.assertTrue(unreachable.action_conflict)
        self.assertEqual(unreachable.witness, {0: 1})
        target_rule = Rule(
            index=1,
            action=Action.DENY,
            syscalls=("socket",),
            conditions=(cond(0, "EQ", 1),),
        )
        self.assertTrue(
            all(
                evaluate(condition, unreachable.witness[condition.index])
                for condition in target_rule.conditions
            )
        )

    def test_union_of_two_rules_covers_third(self):
        result = analyze(
            policy(
                [
                    rule(0, "ALLOW", ["read"], [cond(0, "LT", 10)]),
                    rule(1, "ALLOW", ["read"], [cond(0, "GE", 10)]),
                    rule(2, "DENY", ["read"]),
                ]
            )
        )
        unreachable = find(result, "unreachable_rule")
        self.assertEqual(unreachable.rule_index, 2)
        self.assertEqual(unreachable.covered_by, (0, 1))

    def test_partial_union_does_not_cover(self):
        result = analyze(
            policy(
                [
                    rule(0, "ALLOW", ["read"], [cond(0, "LT", 10)]),
                    rule(1, "ALLOW", ["read"], [cond(0, "GT", 20)]),
                    rule(2, "DENY", ["read"]),
                ]
            )
        )
        self.assertNotIn("unreachable_rule", kinds(result))


class ArchitectureTest(unittest.TestCase):
    def test_32_64_number_differences(self):
        self.assertEqual(syscall_number("x86_64", "read"), 0)
        self.assertEqual(syscall_number("i386", "read"), 3)
        self.assertEqual(syscall_number("x86_64", "socketcall"), None)
        self.assertEqual(syscall_number("i386", "socketcall"), 102)
        self.assertEqual(syscall_number("arm64", "openat"), 56)
        self.assertEqual(syscall_number("arm", "openat"), 322)

    def test_arch_specific_unknown_syscall(self):
        result = analyze(
            policy(
                [rule(0, "ALLOW", ["socketcall"])],
                arches=("x86_64",),
            )
        )
        self.assertEqual(kinds(result), ["unknown_syscall"])

        result = analyze(
            policy(
                [rule(0, "ALLOW", ["socketcall"])],
                arches=("i386",),
            )
        )
        self.assertEqual(kinds(result), [])

    def test_known_in_any_arch_is_not_unknown(self):
        result = analyze(
            policy(
                [rule(0, "ALLOW", ["socketcall"])],
                arches=("x86_64", "i386"),
            )
        )
        self.assertEqual(kinds(result), [])


class OrderingTest(unittest.TestCase):
    def test_stable_sort_by_rule_index_and_kind(self):
        result = analyze(
            policy(
                [
                    rule(0, "ALLOW", ["read"], [cond(0, "GT", 1)]),
                    rule(1, "ALLOW", ["read"], [cond(0, "LT", 9)]),
                    rule(2, "KILL", ["read"]),
                ]
            )
        )
        keys = [item.sort_key() for item in result]
        self.assertEqual(keys, sorted(keys))
        # 规则 2 被前两条的并集覆盖，且与它们动作互斥。
        self.assertIn("unreachable_rule", kinds(result))


class EmptyPolicyTest(unittest.TestCase):
    def test_empty_rules_no_default(self):
        result = analyze(Policy(architectures=("x86_64",), rules=(), default_action=None))
        self.assertEqual(result, [])

    def test_empty_rules_empty_arch(self):
        result = analyze(load_policy({"rules": []}))
        self.assertEqual(result, [])


class LoadPolicyIntegrationTest(unittest.TestCase):
    def test_end_to_end_dict_policy(self):
        raw = {
            "architectures": ["amd64"],
            "default_action": "SCMP_ACT_ERRNO",
            "rules": [
                {"action": "SCMP_ACT_ALLOW", "syscalls": ["socket"]},
                {
                    "action": "SCMP_ACT_KILL",
                    "syscalls": ["socket"],
                    "conditions": [
                        {
                            "index": 0,
                            "operator": "SCMP_CMP_MASKED_EQ",
                            "value": 0x0F,
                            "masked_value": 0x01,
                        }
                    ],
                },
            ],
        }
        result = analyze(load_policy(raw))
        unreachable = find(result, "unreachable_rule")
        self.assertEqual(unreachable.rule_index, 1)
        mutex = find(result, "mutually_exclusive_actions")
        self.assertEqual(mutex.witness[0] & 0x0F, 0x01)

    def test_multiple_masks_end_to_end(self):
        raw = {
            "architectures": ["x86_64"],
            "default_action": "DENY",
            "rules": [
                {
                    "action": "ALLOW",
                    "syscalls": ["ioctl"],
                    "conditions": [
                        {"index": 1, "operator": "MASKED_EQ", "value": 0x0034, "mask": 0x00FF},
                        {"index": 1, "operator": "MASKED_EQ", "value": 0x1200, "mask": 0xFF00},
                    ],
                },
                {
                    "action": "KILL",
                    "syscalls": ["ioctl"],
                    "conditions": [
                        {"index": 1, "operator": "EQ", "value": 0x1234},
                    ],
                },
            ],
        }
        result = analyze(load_policy(raw))
        complete = find(result, "complete_overlap")
        self.assertEqual(complete.witness[1], 0x1234)
        unreachable = find(result, "unreachable_rule")
        self.assertEqual(unreachable.rule_index, 1)


if __name__ == "__main__":
    unittest.main()

import unittest

from seccomp_linter.loader import load_policy
from seccomp_linter.model import Action, Operator, UINT64_MAX


class LoaderTest(unittest.TestCase):
    def test_action_and_operator_aliases(self):
        policy = load_policy(
            {
                "architectures": ["SCMP_ARCH_X86_64"],
                "default_action": "SCMP_ACT_KILL_PROCESS",
                "rules": [
                    {
                        "action": "SCMP_ACT_ALLOW",
                        "syscalls": ["read"],
                        "conditions": [
                            {
                                "index": "0",
                                "operator": "SCMP_CMP_LE",
                                "value": "0x10",
                            }
                        ],
                    }
                ],
            }
        )
        self.assertEqual(policy.architectures, ("x86_64",))
        self.assertIs(policy.default_action, Action.KILL)
        rule = policy.rules[0]
        self.assertIs(rule.action, Action.ALLOW)
        self.assertIs(rule.conditions[0].operator, Operator.LE)
        self.assertEqual(rule.conditions[0].value, 16)
        self.assertEqual(rule.conditions[0].mask, UINT64_MAX)

    def test_masked_eq_short_form(self):
        policy = load_policy(
            {
                "rules": [
                    {
                        "action": "ALLOW",
                        "syscalls": ["ioctl"],
                        "conditions": [
                            {"index": 1, "operator": "MASKED_EQ", "value": 0xFF}
                        ],
                    }
                ]
            }
        )
        condition = policy.rules[0].conditions[0]
        self.assertEqual(condition.mask, 0xFF)
        self.assertEqual(condition.value, 0)

    def test_missing_default_action(self):
        policy = load_policy(
            {"architectures": ["i386"], "rules": []}
        )
        self.assertIsNone(policy.default_action)

    def test_invalid_action_raises(self):
        with self.assertRaises(ValueError):
            load_policy(
                {"rules": [{"action": "LOG", "syscalls": ["read"]}]}
            )

    def test_invalid_integer_raises(self):
        with self.assertRaises(ValueError):
            load_policy(
                {
                    "rules": [
                        {
                            "action": "ALLOW",
                            "syscalls": ["read"],
                            "conditions": [
                                {"index": 0, "operator": "EQ", "value": "nope"}
                            ],
                        }
                    ]
                }
            )

    def test_empty_syscall_list_raises(self):
        with self.assertRaises(ValueError):
            load_policy(
                {"rules": [{"action": "ALLOW", "syscalls": []}]}
            )

    def test_rule_indices_assigned_in_order(self):
        policy = load_policy(
            {
                "architectures": ["x86_64"],
                "rules": [
                    {"action": "ALLOW", "syscalls": ["read"]},
                    {"action": "DENY", "syscalls": ["write"]},
                ],
            }
        )
        self.assertEqual([rule.index for rule in policy.rules], [0, 1])


if __name__ == "__main__":
    unittest.main()

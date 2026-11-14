"""seccomp 策略静态检查库（不执行任何系统调用）。"""

from .checker import analyze
from .loader import load_policy
from .model import (
    Action,
    CompleteOverlap,
    Condition,
    DuplicateRule,
    Finding,
    MutuallyExclusiveActions,
    Operator,
    PartialOverlap,
    Policy,
    Rule,
    UnsatisfiableRule,
    UnknownSyscall,
    UnreachableRule,
)
from .solver import evaluate, intersection_witness, is_subset, solve, witness_matches
from .syscalls import syscall_number

__all__ = [
    "Action",
    "CompleteOverlap",
    "Condition",
    "DuplicateRule",
    "Finding",
    "MutuallyExclusiveActions",
    "Operator",
    "PartialOverlap",
    "Policy",
    "Rule",
    "UnsatisfiableRule",
    "UnknownSyscall",
    "UnreachableRule",
    "analyze",
    "evaluate",
    "intersection_witness",
    "is_subset",
    "load_policy",
    "solve",
    "syscall_number",
    "witness_matches",
]

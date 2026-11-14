"""seccomp 策略静态检查器的核心数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

UINT64_MAX = (1 << 64) - 1
MAX_ARG_INDEX = 5


class Action(str, Enum):
    """规则终止动作。"""

    ALLOW = "ALLOW"
    DENY = "DENY"
    KILL = "KILL"


class Operator(str, Enum):
    """参数比较运算，统一语义为 ``(arg & mask) op value``。"""

    EQ = "EQ"
    NE = "NE"
    LT = "LT"
    LE = "LE"
    GT = "GT"
    GE = "GE"
    MASKED_EQ = "MASKED_EQ"
    MASKED_NE = "MASKED_NE"


@dataclass(frozen=True, slots=True)
class Condition:
    """单个参数条件：``(args[index] & mask) operator value``。"""

    index: int
    operator: Operator
    value: int
    mask: int = UINT64_MAX

    def __post_init__(self) -> None:
        if not 0 <= self.index <= MAX_ARG_INDEX:
            raise ValueError(f"参数索引必须位于 0..{MAX_ARG_INDEX}，收到 {self.index}")
        if not 0 <= self.value <= UINT64_MAX:
            raise ValueError(f"比较值超出 uint64 范围: {self.value}")
        if not 0 <= self.mask <= UINT64_MAX:
            raise ValueError(f"掩码超出 uint64 范围: {self.mask}")

    def describe(self) -> str:
        return (
            f"arg{self.index} & 0x{self.mask:x} {self.operator.value} "
            f"0x{self.value:x}"
        )


@dataclass(frozen=True, slots=True)
class Rule:
    """一条 seccomp 规则，条件之间为合取（AND）关系。"""

    action: Action
    syscalls: tuple[str, ...]
    conditions: tuple[Condition, ...] = ()
    index: int = -1

    def describe(self) -> str:
        syscalls = ",".join(self.syscalls) or "<empty>"
        if self.conditions:
            conds = " && ".join(c.describe() for c in self.conditions)
            return f"#{self.index} {self.action.value} {syscalls} [{conds}]"
        return f"#{self.index} {self.action.value} {syscalls}"


@dataclass(frozen=True, slots=True)
class Policy:
    """完整 seccomp 策略；default_action 为 None 表示未指定默认动作。"""

    architectures: tuple[str, ...]
    rules: tuple[Rule, ...]
    default_action: Action | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    """检查结论的基类，kind 用于稳定分类与序列化。"""

    kind: str = field(init=False, default="finding")

    def sort_key(self) -> tuple:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class UnknownSyscall(Finding):
    kind: str = field(init=False, default="unknown_syscall")
    rule_index: int
    syscall: str
    architectures: tuple[str, ...]

    def sort_key(self) -> tuple:
        return (self.rule_index, 0, self.syscall)


@dataclass(frozen=True, slots=True)
class UnsatisfiableRule(Finding):
    kind: str = field(init=False, default="unsatisfiable_rule")
    rule_index: int
    reason: str
    core: tuple[str, ...]

    def sort_key(self) -> tuple:
        return (self.rule_index, 1, self.reason)


@dataclass(frozen=True, slots=True)
class DuplicateRule(Finding):
    kind: str = field(init=False, default="duplicate_rule")
    rule_index: int
    duplicate_of: int

    def sort_key(self) -> tuple:
        return (self.rule_index, 2, self.duplicate_of)


@dataclass(frozen=True, slots=True)
class UnreachableRule(Finding):
    """规则匹配集合被更早规则（的并集）完全覆盖，首条匹配永不发生。

    ``witness`` 给出目标规则本会命中的一组参数，这组参数实际会被
    ``covered_by`` 中的更早规则抢先处理。
    """

    kind: str = field(init=False, default="unreachable_rule")
    rule_index: int
    covered_by: tuple[int, ...]
    witness: dict[int, int]
    action_conflict: bool

    def sort_key(self) -> tuple:
        return (self.rule_index, 3, self.covered_by[0])


@dataclass(frozen=True, slots=True)
class CompleteOverlap(Finding):
    kind: str = field(init=False, default="complete_overlap")
    first: int
    second: int
    syscalls: tuple[str, ...]
    witness: dict[int, int]
    action_conflict: bool

    def sort_key(self) -> tuple:
        return (min(self.first, self.second), 4, max(self.first, self.second))


@dataclass(frozen=True, slots=True)
class PartialOverlap(Finding):
    kind: str = field(init=False, default="partial_overlap")
    first: int
    second: int
    syscalls: tuple[str, ...]
    witness: dict[int, int]
    action_conflict: bool

    def sort_key(self) -> tuple:
        return (min(self.first, self.second), 5, max(self.first, self.second))


@dataclass(frozen=True, slots=True)
class MutuallyExclusiveActions(Finding):
    kind: str = field(init=False, default="mutually_exclusive_actions")
    first: int
    second: int
    syscalls: tuple[str, ...]
    witness: dict[int, int]
    relation: str

    def sort_key(self) -> tuple:
        return (min(self.first, self.second), 6, max(self.first, self.second))

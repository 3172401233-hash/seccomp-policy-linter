"""静态规则冲突分析，全程只做集合推理，不执行系统调用。"""

from __future__ import annotations

from functools import lru_cache

from . import solver
from .model import (
    CompleteOverlap,
    Condition,
    DuplicateRule,
    Finding,
    MutuallyExclusiveActions,
    PartialOverlap,
    Rule,
    Policy,
    UnsatisfiableRule,
    UnknownSyscall,
    UnreachableRule,
)
from .solver import intersection_witness, is_subset, negate, solve
from .syscalls import unknown_syscalls


def _rule_signature(rule: Rule):
    return (
        rule.action,
        tuple(sorted(rule.syscalls)),
        tuple(
            (c.index, c.operator, c.value, c.mask) for c in rule.conditions
        ),
    )


def _group_conditions(
    conditions: tuple[Condition, ...],
) -> dict[int, list[Condition]]:
    grouped: dict[int, list[Condition]] = {}
    for cond in conditions:
        grouped.setdefault(cond.index, []).append(cond)
    return grouped


def _unsat_core(rule: Rule) -> tuple[str, ...]:
    """贪心找出仍不可满足的最小条件子集，作为可读原因。"""

    kept = list(rule.conditions)
    changed = True
    while changed and len(kept) > 1:
        changed = False
        for pos in range(len(kept)):
            trial = kept[:pos] + kept[pos + 1 :]
            if solve(trial) is None:
                kept = trial
                changed = True
                break
    return tuple(cond.describe() for cond in kept)


def _shared_syscalls(first: Rule, second: Rule) -> tuple[str, ...]:
    return tuple(name for name in first.syscalls if name in second.syscalls)


def _union_cover_witness(
    target: tuple[Condition, ...],
    earlier: list[tuple[Condition, ...]],
) -> dict[int, int] | None:
    """寻找命中 target 但避开 earlier 全部规则的见证；None 表示被完全覆盖。"""

    target_groups = _group_conditions(target)
    avoid_groups = [_group_conditions(rule) for rule in earlier]
    # 无条件规则匹配该 syscall 的全部参数组合，目标规则无法避让。
    if any(not group for group in avoid_groups):
        return None
    all_indices = sorted(
        set(target_groups)
        | {index for group in avoid_groups for index in group}
    )

    @lru_cache(maxsize=None)
    def search(pos: int) -> dict | None:
        if pos == len(all_indices):
            return {}
        index = all_indices[pos]
        base = target_groups.get(index, [])

        def walk(avoid_pos: int, extra: tuple[Condition, ...]) -> dict | None:
            if avoid_pos == len(avoid_groups):
                witness_value = solver._solve_index(base + list(extra))
                if witness_value is None:
                    return None
                rest = search(pos + 1)
                if rest is None:
                    return None
                return {index: witness_value, **rest}

            group = avoid_groups[avoid_pos].get(index)
            if not group:
                return walk(avoid_pos + 1, extra)
            # 要避开某条规则，只需在它关心的某个索引上违反其中一个条件。
            for cond in group:
                candidate = extra + (negate(cond),)
                if solve(base + list(candidate)) is not None:
                    result = walk(avoid_pos + 1, candidate)
                    if result is not None:
                        return result
            return None

        return walk(0, ())

    return search(0)


def _analyze_pair(first: Rule, second: Rule) -> list[Finding]:
    shared = _shared_syscalls(first, second)
    if not shared:
        return []

    witness = intersection_witness(first.conditions, second.conditions)
    if witness is None:
        return []

    first_in_second = is_subset(first.conditions, second.conditions)
    second_in_first = is_subset(second.conditions, first.conditions)
    conflict = first.action is not second.action
    findings: list[Finding] = []

    if first_in_second or second_in_first:
        findings.append(
            CompleteOverlap(
                first=first.index,
                second=second.index,
                syscalls=shared,
                witness=witness,
                action_conflict=conflict,
            )
        )
    else:
        findings.append(
            PartialOverlap(
                first=first.index,
                second=second.index,
                syscalls=shared,
                witness=witness,
                action_conflict=conflict,
            )
        )

    if conflict:
        relation = (
            "complete_overlap"
            if first_in_second or second_in_first
            else "partial_overlap"
        )
        findings.append(
            MutuallyExclusiveActions(
                first=first.index,
                second=second.index,
                syscalls=shared,
                witness=witness,
                relation=relation,
            )
        )
    return findings


def analyze(policy: Policy) -> list[Finding]:
    """返回按稳定顺序排序的全部检查结论。"""

    findings: list[Finding] = []
    rules = policy.rules

    # 1. 未知 syscall。
    for rule in rules:
        for syscall in unknown_syscalls(policy.architectures, rule.syscalls):
            findings.append(
                UnknownSyscall(
                    rule_index=rule.index,
                    syscall=syscall,
                    architectures=policy.architectures,
                )
            )

    # 2. 恒假比较与不可满足规则。
    satisfiable: list[Rule] = []
    for rule in rules:
        trivial = next(
            (
                reason
                for cond in rule.conditions
                if (reason := solver.trivial_false_reason(cond)) is not None
            ),
            None,
        )
        if trivial is not None:
            findings.append(
                UnsatisfiableRule(
                    rule_index=rule.index,
                    reason=trivial,
                    core=(trivial.split("：", 1)[0],),
                )
            )
            continue
        if solve(rule.conditions) is None:
            findings.append(
                UnsatisfiableRule(
                    rule_index=rule.index,
                    reason="规则条件合取不存在任何参数见证",
                    core=_unsat_core(rule),
                )
            )
            continue
        satisfiable.append(rule)

    # 3. 重复规则（动作、syscall 集合、条件序列完全一致）。
    seen: dict = {}
    duplicate_indices: set[int] = set()
    for rule in satisfiable:
        signature = _rule_signature(rule)
        if signature in seen:
            duplicate_indices.add(rule.index)
            findings.append(
                DuplicateRule(
                    rule_index=rule.index,
                    duplicate_of=seen[signature].index,
                )
            )
        else:
            seen[signature] = rule

    # 4. 两两完全/部分重叠与互斥动作。
    for pos, first in enumerate(satisfiable):
        for second in satisfiable[pos + 1 :]:
            findings.extend(_analyze_pair(first, second))

    # 5. 并集不可达：某 syscall 上规则匹配集合被更早规则的并集完全覆盖。
    by_syscall: dict[str, list[Rule]] = {}
    for rule in satisfiable:
        for syscall in rule.syscalls:
            by_syscall.setdefault(syscall, []).append(rule)

    rule_by_index = {rule.index: rule for rule in satisfiable}
    for rule in satisfiable:
        if rule.index in duplicate_indices:
            continue
        covering: set[int] = set()
        for syscall in rule.syscalls:
            earlier = [
                item
                for item in by_syscall[syscall]
                if item.index < rule.index
            ]
            if not earlier:
                continue
            witness = _union_cover_witness(
                rule.conditions, [item.conditions for item in earlier]
            )
            if witness is None:
                covering.update(item.index for item in earlier)
        if covering:
            unique_cover = tuple(sorted(covering))
            shadowed_witness = solve(rule.conditions) or {}
            findings.append(
                UnreachableRule(
                    rule_index=rule.index,
                    covered_by=unique_cover,
                    witness=shadowed_witness,
                    action_conflict=any(
                        rule_by_index[idx].action is not rule.action
                        for idx in unique_cover
                    ),
                )
            )

    return sorted(findings, key=lambda item: item.sort_key())

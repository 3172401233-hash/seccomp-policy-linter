"""掩码参数条件的静态求解器。

条件统一写成 ``(arg & mask) op value``，arg 为 64 位无符号整数。
求解过程不执行任何系统调用，只做位级别的区间传播：

* ``EQ`` / ``NE`` / ``MASKED_EQ`` 给出掩码位上的固定值；
* 有序比较（``LT``/``LE``/``GT``/``GE``）在按位 DP 中维护
  “已处理高位小于/等于比较值”的状态，天然支持开放范围；
* 掩码只保留条件关心的位，未掩码位可自由取值。
"""

from __future__ import annotations

from .model import Condition, Operator, UINT64_MAX

NEGATION = {
    Operator.EQ: Operator.NE,
    Operator.NE: Operator.EQ,
    Operator.LT: Operator.GE,
    Operator.LE: Operator.GT,
    Operator.GT: Operator.LE,
    Operator.GE: Operator.LT,
    Operator.MASKED_EQ: Operator.MASKED_NE,
    Operator.MASKED_NE: Operator.MASKED_EQ,
}

_ORDERING = {Operator.LT, Operator.LE, Operator.GT, Operator.GE}


def negate(condition: Condition) -> Condition:
    """返回条件的逻辑否定，掩码与参数索引保持不变。"""

    if condition.operator in _ORDERING:
        # 掩码比较的否定必须取相反方向，不能只翻运算符。
        flipped = {
            Operator.LT: Operator.GE,
            Operator.LE: Operator.GT,
            Operator.GT: Operator.LE,
            Operator.GE: Operator.LT,
        }[condition.operator]
        return Condition(
            index=condition.index,
            operator=flipped,
            value=condition.value,
            mask=condition.mask,
        )
    return Condition(
        index=condition.index,
        operator=NEGATION[condition.operator],
        value=condition.value,
        mask=condition.mask,
    )


def _masked(value: int, bit: int) -> int:
    return (value >> bit) & 1


def _solve_index(conditions: list[Condition]) -> int | None:
    """求单个参数索引上条件合取的一个具体 uint64 见证值。"""

    not_equal: list[Condition] = []
    ordering: list[Condition] = []
    equalities: list[Condition] = []
    fixed_bits: dict[int, int] = {}

    for cond in conditions:
        op = cond.operator
        if op in (Operator.NE, Operator.MASKED_NE):
            # 掩码为 0 时左侧恒为 0，NE 0 是重言式，直接忽略。
            if cond.mask != 0:
                not_equal.append(cond)
        elif op in _ORDERING:
            ordering.append(cond)
        else:
            for previous in equalities:
                overlap = cond.mask & previous.mask
                if overlap and (
                    (cond.value & overlap) != (previous.value & overlap)
                ):
                    return None
            equalities.append(cond)
            for bit in range(64):
                if _masked(cond.mask, bit):
                    fixed_bits[bit] = _masked(cond.value, bit)

    equality_mask = 0
    for cond in equalities:
        equality_mask |= cond.mask

    # 相等条件把掩码位固定下来；NE 若在“不被任何相等条件覆盖”的位上
    # 还有自由度，就把这些位当作可求解空间。完全被相等掩码覆盖的 NE，
    # 其真假由固定值直接决定。
    free_ne: list[Condition] = []
    base_value = 0
    for bit, wanted in fixed_bits.items():
        base_value |= wanted << bit

    for ne_cond in not_equal:
        free_part = ne_cond.mask & ~equality_mask
        if free_part:
            free_ne.append(
                Condition(
                    index=ne_cond.index,
                    operator=ne_cond.operator,
                    value=ne_cond.value & free_part,
                    mask=free_part,
                )
            )
            continue
        if (base_value & ne_cond.mask) == (ne_cond.value & ne_cond.mask):
            return None

    def bit_candidates(bit: int) -> tuple[int, ...]:
        if bit in fixed_bits:
            return (fixed_bits[bit],)
        return (0, 1)

    def equality_satisfied(candidate: int) -> bool:
        return all(
            (candidate & cond.mask) == (cond.value & cond.mask)
            for cond in equalities
        )

    # 按位 DP 状态包含两部分：
    # cmp 跟踪有序比较（0=大于，1=相等，2=小于），有序条件在候选值
    # 回溯完成后用 evaluate 整体校验；ne_done 跟踪自由 NE 是否已在某个
    # 掩码位上确定不相等。相等条件已通过 fixed_bits 锁死掩码位。
    initial_cmp = tuple([1] * len(ordering))
    initial_ne = tuple([0] * len(free_ne))
    states = {(initial_cmp, initial_ne): None}
    parents: list[dict] = []

    for bit in range(63, -1, -1):
        next_states: dict[tuple, tuple] = {}
        for (cmp_flags, ne_done), _ in states.items():
            for bit_value in bit_candidates(bit):
                new_cmp = list(cmp_flags)
                new_ne = list(ne_done)
                for pos, cond in enumerate(ordering):
                    if new_cmp[pos] != 1 or not _masked(cond.mask, bit):
                        continue
                    target = _masked(cond.value, bit)
                    if bit_value > target:
                        new_cmp[pos] = 0
                    elif bit_value < target:
                        new_cmp[pos] = 2
                for pos, cond in enumerate(free_ne):
                    if new_ne[pos] == 0 and _masked(cond.mask, bit):
                        if bit_value != _masked(cond.value, bit):
                            new_ne[pos] = 1
                new_state = (
                    tuple(new_cmp),
                    tuple(new_ne),
                )
                if new_state not in next_states:
                    next_states[new_state] = (
                        (cmp_flags, ne_done),
                        bit_value,
                    )
        if not next_states:
            return None
        parents.append(next_states)
        states = next_states

    def reconstruct(final_state) -> int:
        value = 0
        current = final_state
        for bit in range(0, 64):
            layer = parents[63 - bit]
            previous, bit_value = layer[current]
            value |= bit_value << bit
            current = previous
        return value

    for final_state in states:
        _, ne_done = final_state
        if 0 in ne_done:
            continue
        candidate = reconstruct(final_state)
        if not equality_satisfied(candidate):
            continue
        if not all(evaluate(cond, candidate) for cond in ordering):
            continue
        return candidate
    return None


def solve(conditions: list[Condition] | tuple[Condition, ...]) -> dict[int, int] | None:
    """求条件合取的见证参数；无解返回 None。"""

    grouped: dict[int, list[Condition]] = {}
    for cond in conditions:
        grouped.setdefault(cond.index, []).append(cond)

    witness: dict[int, int] = {}
    for index, group in grouped.items():
        value = _solve_index(group)
        if value is None:
            return None
        witness[index] = value
    return witness


def is_satisfiable(conditions) -> bool:
    return solve(conditions) is not None


def intersection_witness(
    left: tuple[Condition, ...], right: tuple[Condition, ...]
) -> dict[int, int] | None:
    """两组条件合取后的具体见证参数。"""

    return solve(list(left) + list(right))


def is_subset(
    subset: tuple[Condition, ...], superset: tuple[Condition, ...]
) -> bool:
    """判断 subset 的匹配集合是否被 superset 完全包含。"""

    # subset ⊆ superset 等价于 subset 与 “superset 中至少一个条件被违反”
    # 的析取不存在交集，即对 superset 的每个条件单独尝试反例。
    for cond in superset:
        if solve(list(subset) + [negate(cond)]) is not None:
            return False
    return True


def evaluate(cond: Condition, arg_value: int) -> bool:
    """用具体参数值判定单个条件，供测试与不可达分析复用。"""

    masked = arg_value & cond.mask
    op = cond.operator
    value = cond.value
    if op in (Operator.EQ, Operator.MASKED_EQ):
        return masked == (value & cond.mask)
    if op in (Operator.NE, Operator.MASKED_NE):
        if cond.mask == 0:
            # 掩码为 0 时左侧恒为 0：NE 0 恒真，NE 非零恒假。
            return value == 0
        return masked != (value & cond.mask)
    if op is Operator.LT:
        return masked < value
    if op is Operator.LE:
        return masked <= value
    if op is Operator.GT:
        return masked > value
    if op is Operator.GE:
        return masked >= value
    raise AssertionError(f"未知运算符: {op}")


def witness_matches(conditions, witness: dict[int, int]) -> bool:
    return all(evaluate(cond, witness.get(cond.index, 0)) for cond in conditions)


def trivial_false_reason(cond: Condition) -> str | None:
    """快速识别一眼可判的恒假比较，返回人类可读原因。"""

    op = cond.operator
    if cond.mask == 0 and op in (Operator.EQ, Operator.MASKED_EQ) and cond.value != 0:
        return (
            f"{cond.describe()} 恒假：掩码为 0 时左侧恒为 0，不可能等于 "
            f"0x{cond.value:x}"
        )
    if cond.mask == 0:
        return None
    if op is Operator.GT and (cond.value & cond.mask) == cond.mask:
        return (
            f"{cond.describe()} 恒假：掩码内最大值 0x{cond.mask:x} "
            f"不可能严格大于 0x{cond.value & cond.mask:x}"
        )
    if op is Operator.LT and (cond.value & cond.mask) == 0:
        return (
            f"{cond.describe()} 恒假：掩码内最小值为 0，不可能严格小于 0"
        )
    if op in (Operator.EQ, Operator.MASKED_EQ) and (cond.value & ~cond.mask):
        return (
            f"{cond.describe()} 恒假：value 含有掩码之外的置位 "
            f"0x{cond.value & ~cond.mask:x}"
        )
    return None

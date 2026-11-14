"""从字典结构（通常来自 JSON/YAML）构建 :class:`Policy`。"""

from __future__ import annotations

from .model import Action, Condition, Operator, Policy, Rule, UINT64_MAX
from .syscalls import normalize_arch

ACTION_ALIASES = {
    "ALLOW": Action.ALLOW,
    "SCMP_ACT_ALLOW": Action.ALLOW,
    "allow": Action.ALLOW,
    "DENY": Action.DENY,
    "SCMP_ACT_ERRNO": Action.DENY,
    "SCMP_ACT_DENY": Action.DENY,
    "deny": Action.DENY,
    "KILL": Action.KILL,
    "SCMP_ACT_KILL": Action.KILL,
    "SCMP_ACT_KILL_PROCESS": Action.KILL,
    "SCMP_ACT_KILL_THREAD": Action.KILL,
    "kill": Action.KILL,
}

OPERATOR_ALIASES = {
    "EQ": Operator.EQ,
    "NE": Operator.NE,
    "LT": Operator.LT,
    "LE": Operator.LE,
    "GT": Operator.GT,
    "GE": Operator.GE,
    "MASKED_EQ": Operator.MASKED_EQ,
    "SCMP_CMP_EQ": Operator.EQ,
    "SCMP_CMP_NE": Operator.NE,
    "SCMP_CMP_LT": Operator.LT,
    "SCMP_CMP_LE": Operator.LE,
    "SCMP_CMP_GT": Operator.GT,
    "SCMP_CMP_GE": Operator.GE,
    "SCMP_CMP_MASKED_EQ": Operator.MASKED_EQ,
    "==": Operator.EQ,
    "!=": Operator.NE,
    "<": Operator.LT,
    "<=": Operator.LE,
    ">": Operator.GT,
    ">=": Operator.GE,
    "&=": Operator.MASKED_EQ,
}


def _parse_int(raw, field_name: str) -> int:
    if isinstance(raw, bool):
        raise ValueError(f"{field_name} 不能是布尔值: {raw!r}")
    if isinstance(raw, int):
        value = raw
    elif isinstance(raw, str):
        try:
            value = int(raw, 0)
        except ValueError as exc:
            raise ValueError(f"{field_name} 不是整数: {raw!r}") from exc
    else:
        raise ValueError(f"{field_name} 不是整数: {raw!r}")
    if not 0 <= value <= UINT64_MAX:
        raise ValueError(f"{field_name} 超出 uint64 范围: {value}")
    return value


def _parse_action(raw) -> Action:
    if isinstance(raw, Action):
        return raw
    try:
        return ACTION_ALIASES[raw]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"未知动作: {raw!r}") from exc


def _parse_operator(raw) -> Operator:
    try:
        return OPERATOR_ALIASES[raw]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"未知比较运算: {raw!r}") from exc


def _parse_condition(raw) -> Condition:
    if not isinstance(raw, dict):
        raise ValueError(f"条件必须是对象: {raw!r}")
    if "index" not in raw:
        raise ValueError(f"条件缺少 index: {raw!r}")
    index = _parse_int(raw["index"], "index")
    operator = _parse_operator(raw.get("operator", "EQ"))
    value = _parse_int(raw.get("value", 0), "value")
    if "mask" in raw:
        mask = _parse_int(raw["mask"], "mask")
    elif operator is Operator.MASKED_EQ:
        mask = value
        value = _parse_int(raw.get("masked_value", 0), "masked_value")
    else:
        mask = UINT64_MAX
    return Condition(index=index, operator=operator, value=value, mask=mask)


def _parse_rule(raw, index: int) -> Rule:
    if not isinstance(raw, dict):
        raise ValueError(f"规则 #{index} 必须是对象: {raw!r}")
    action = _parse_action(raw.get("action"))
    syscalls_raw = raw.get("syscalls", ())
    if isinstance(syscalls_raw, str):
        syscalls = (syscalls_raw,)
    else:
        syscalls = tuple(syscalls_raw)
    if not syscalls:
        raise ValueError(f"规则 #{index} 的 syscall 列表为空")
    conditions = tuple(
        _parse_condition(item) for item in raw.get("conditions", ())
    )
    return Rule(
        action=action,
        syscalls=syscalls,
        conditions=conditions,
        index=index,
    )


def load_policy(raw: dict) -> Policy:
    """把类 JSON 字典解析为 :class:`Policy`，并给规则补上稳定索引。"""

    if not isinstance(raw, dict):
        raise ValueError("策略必须是对象")
    arches_raw = raw.get("architectures", raw.get("arch", ()))
    if isinstance(arches_raw, str):
        arches = (normalize_arch(arches_raw),)
    else:
        arches = tuple(normalize_arch(name) for name in arches_raw)
    rules = tuple(
        _parse_rule(item, index)
        for index, item in enumerate(raw.get("rules", ()))
    )
    default_raw = raw.get("default_action")
    default_action = _parse_action(default_raw) if default_raw is not None else None
    return Policy(
        architectures=arches,
        rules=rules,
        default_action=default_action,
    )

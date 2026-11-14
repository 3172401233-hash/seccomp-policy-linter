# seccomp-policy-linter

Python seccomp 策略**静态**检查库：只解析规则并做集合/位级推理，
**不执行任何系统调用，也不加载 seccomp BPF**。输入包含架构、默认动作、
syscall 名、参数索引、比较运算与掩码，输出冲突定位、重叠分类和具体见证值。

## 能力范围

- 未知 syscall：在策略列出的全部架构编号表中都查不到的名称。
- 恒假比较：零掩码相等、value 含掩码外置位、掩码内越界的严格比较等。
- 不可满足规则：条件合取不存在任何 64 位参数见证，附最小矛盾条件子集。
- 重复规则：动作、syscall 集合与条件序列完全一致。
- 完全重叠：一条规则的参数匹配集合是另一条的子集（含相等集合）。
- 部分重叠：两个匹配集合有交集但互不包含，返回交集内的具体见证值。
- 互斥动作：`ALLOW` / `DENY` / `KILL` 在同一 syscall 上命中同一参数。
- 不可达规则：规则匹配集合被更早规则的**并集**完全覆盖（首条匹配永不发生），
  这正是“一条过宽 allow 盖住后面所有 deny”的场景。

所有结论按 `(规则索引, 类别)` 稳定排序，见证值是可直接代入条件复核的
`{参数索引: uint64 值}`。

## 条件语义

每个条件统一表示为：

```
(args[index] & mask) operator value
```

支持 `EQ`、`NE`、`LT`、`LE`、`GT`、`GE`、`MASKED_EQ`，
以及仅供内部取反使用的 `MASKED_NE`。掩码默认为全 1（`2^64-1`）。
`MASKED_EQ` 同时接受 libseccomp 风格的 `value`/`masked_value` 短格式。

## 快速上手

```python
from seccomp_linter import load_policy, analyze

policy = load_policy({
    "architectures": ["x86_64"],
    "default_action": "SCMP_ACT_ERRNO",
    "rules": [
        {"action": "SCMP_ACT_ALLOW", "syscalls": ["socket"]},
        {
            "action": "SCMP_ACT_KILL",
            "syscalls": ["socket"],
            "conditions": [
                {"index": 0, "operator": "SCMP_CMP_EQ", "value": 1},
            ],
        },
    ],
})

for finding in analyze(policy):
    print(finding.kind, finding)
```

上例会报告第二条 `KILL` 规则不可达：无条件的 `ALLOW` 已经匹配
`socket` 的全部参数组合。

也可以直接使用数据类构建：

```python
from seccomp_linter import Action, Condition, Operator, Policy, Rule, analyze

policy = Policy(
    architectures=("x86_64",),
    default_action=Action.DENY,
    rules=(
        Rule(0, Action.ALLOW, ("read",), (
            Condition(0, Operator.GT, 100),
        )),
        Rule(1, Action.KILL, ("read",), (
            Condition(0, Operator.LT, 200),
        )),
    ),
)
```

## 架构差异

内置 `x86_64`、`i386`、`arm64`、`arm` 的常见 syscall 编号表，
32/64 位编号差异（如 `read` 在 x86_64 为 0、i386 为 3，以及 i386 的
`socketcall` 复用入口）会被识别。未收录的名称按“未知 syscall”报告，
而不是被静默忽略。

## 运行测试

```bash
python -m unittest
```

测试覆盖多重掩码、开放参数范围、32/64 位差异、重复规则、空默认策略、
冲突定位、见证值复核与稳定排序，并包含与小值域暴力枚举对拍的随机属性测试。

## 这不是内核模拟

本工具是**静态推理器**，结论不等同于真实内核对 seccomp 过滤器的执行结果：

- 不加载 BPF、不发起系统调用，不反映运行时寄存器、内存或返回值。
- 只按规则文本的一阶参数条件推理，不模拟 BPF 跳转、动作优先级、
  `RET` 语义、`SECCOMP_RET_USER_NOTIF` 等内核机制。
- syscall 编号表是静态内置子集，内核版本、架构变体或自定义编号可能不同；
  未知名称只代表“表中未收录”，不代表内核一定拒绝。
- 不评估过滤器的实际性能、缓存行为或与 namespaces / capabilities /
  ptrace 等其他安全机制的交互。
- 见证值只证明“存在一组参数满足/区分这些文本条件”，不保证该参数组合
  在真实程序中可达或有意义。

上线前仍需在目标内核上做集成验证；本工具用于在评审阶段提前暴露
规则文本层面的冲突与死规则。

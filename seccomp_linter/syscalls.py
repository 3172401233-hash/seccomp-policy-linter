"""各架构的 syscall 编号表（静态内置，不查询内核）。"""

from __future__ import annotations

# 只收录测试与常见策略会用到的编号；未知 syscall 是检查器的一等公民，
# 未收录名称会被标记而不是被静默忽略。

X86_64 = {
    "read": 0,
    "write": 1,
    "open": 2,
    "close": 3,
    "stat": 4,
    "fstat": 5,
    "lstat": 6,
    "poll": 7,
    "lseek": 8,
    "mmap": 9,
    "mprotect": 10,
    "munmap": 11,
    "rt_sigaction": 13,
    "ioctl": 16,
    "pread64": 17,
    "pwrite64": 18,
    "socket": 41,
    "connect": 42,
    "accept": 43,
    "clone": 56,
    "fork": 57,
    "vfork": 58,
    "exit": 60,
    "wait4": 61,
    "kill": 62,
    "uname": 63,
    "fcntl": 72,
    "truncate": 76,
    "ftruncate": 77,
    "getcwd": 79,
    "chdir": 80,
    "rename": 82,
    "mkdir": 83,
    "rmdir": 84,
    "creat": 85,
    "link": 86,
    "unlink": 87,
    "symlink": 88,
    "readlink": 89,
    "chmod": 90,
    "chown": 92,
    "dup2": 33,
    "socketpair": 53,
    "setsockopt": 54,
    "getsockopt": 55,
    "execve": 59,
    "exit_group": 231,
    "openat": 257,
    "mkdirat": 258,
    "unlinkat": 263,
    "renameat": 264,
    "linkat": 265,
    "readlinkat": 267,
    "fchmodat": 268,
    "fchownat": 260,
    "clone3": 435,
    "seccomp": 317,
}

I386 = {
    "exit": 1,
    "fork": 2,
    "read": 3,
    "write": 4,
    "open": 5,
    "close": 6,
    "waitpid": 7,
    "creat": 8,
    "link": 9,
    "unlink": 10,
    "execve": 11,
    "chdir": 12,
    "mknod": 14,
    "chmod": 15,
    "lseek": 19,
    "getpid": 20,
    "mount": 21,
    "setuid": 23,
    "getuid": 24,
    "ptrace": 26,
    "kill": 37,
    "mkdir": 39,
    "rmdir": 40,
    "dup": 41,
    "pipe": 42,
    "brk": 45,
    "getcwd": 183,
    "mmap2": 192,
    "stat64": 195,
    "lstat64": 196,
    "fstat64": 197,
    "openat": 295,
    "mkdirat": 296,
    "exit_group": 252,
    # i386 用 socketcall 复用整族网络系统调用，x86_64 没有该入口。
    "socketcall": 102,
}

ARM64 = {
    "getcwd": 17,
    "dup2": 23,
    "dup3": 24,
    "fcntl": 25,
    "ioctl": 29,
    "mkdirat": 34,
    "unlinkat": 35,
    "renameat": 38,
    "linkat": 39,
    "readlinkat": 78,
    "chdir": 49,
    "openat": 56,
    "close": 57,
    "read": 63,
    "write": 64,
    "readlink": 78,
    "execve": 221,
    "exit": 93,
    "exit_group": 94,
    "kill": 129,
    "mmap": 222,
    "mprotect": 226,
    "seccomp": 277,
    "clone": 220,
    "clone3": 435,
}

ARM = {
    "exit": 1,
    "read": 3,
    "write": 4,
    "open": 5,
    "close": 6,
    "execve": 11,
    "kill": 37,
    "ioctl": 54,
    "fcntl": 55,
    "mmap2": 192,
    "socketcall": 102,
    "openat": 322,
    "exit_group": 248,
    "seccomp": 383,
}

TABLES: dict[str, dict[str, int]] = {
    "x86_64": X86_64,
    "i386": I386,
    "arm64": ARM64,
    "arm": ARM,
}

# 常见别名归一化。
ARCH_ALIASES = {
    "amd64": "x86_64",
    "x86": "i386",
    "x32": "x86_64",
    "aarch64": "arm64",
    "armhf": "arm",
    "SCMP_ARCH_X86_64": "x86_64",
    "SCMP_ARCH_X86": "i386",
    "SCMP_ARCH_AARCH64": "arm64",
    "SCMP_ARCH_ARM": "arm",
}


def normalize_arch(name: str) -> str:
    return ARCH_ALIASES.get(name, name)


def is_known_syscall(architecture: str, syscall: str) -> bool:
    table = TABLES.get(normalize_arch(architecture))
    if table is None:
        raise ValueError(f"不支持的架构: {architecture}")
    return syscall in table


def syscall_number(architecture: str, syscall: str) -> int | None:
    table = TABLES.get(normalize_arch(architecture))
    if table is None:
        raise ValueError(f"不支持的架构: {architecture}")
    return table.get(syscall)


def unknown_syscalls(architectures, syscalls: tuple[str, ...]) -> tuple[str, ...]:
    """在所有列出架构中都查不到的 syscall 才判定为未知。"""

    result = []
    for syscall in syscalls:
        if all(not is_known_syscall(arch, syscall) for arch in architectures):
            result.append(syscall)
    return tuple(result)

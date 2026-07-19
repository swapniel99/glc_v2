"""Kernel-enforced filesystem and syscall restrictions for adapter workers.

Modal runs adapters in separate Sandboxes. These guards further restrict that
Sandbox process: Landlock permits writes only below its ephemeral runtime home,
and seccomp denies process execution plus namespace/kernel administration.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
from pathlib import Path
from typing import Any


class RuntimeIsolationError(RuntimeError):
    pass


_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446
_SYS_SECCOMP = 317

_LANDLOCK_CREATE_RULESET_VERSION = 1
_MINIMUM_LANDLOCK_ABI = 3
_LANDLOCK_RULE_PATH_BENEATH = 1
_LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
_LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
_LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
_LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
_LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
_LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
_LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
_LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
_LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
_LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
_LANDLOCK_ACCESS_FS_REFER = 1 << 13
_LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14

_PR_SET_NO_NEW_PRIVS = 38
_SECCOMP_SET_MODE_FILTER = 1
_SECCOMP_FILTER_FLAG_TSYNC = 1
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000

_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JSET_K = 0x45
_BPF_RET_K = 0x06
_SECCOMP_DATA_NR_OFFSET = 0
_SECCOMP_DATA_ARCH_OFFSET = 4
_SECCOMP_DATA_ARGS_OFFSET = 16
_AUDIT_ARCH_X86_64 = 0xC000003E
_CLONE_THREAD = 0x00010000

_SYS_CLONE = 56
_SYS_CLONE3 = 435
_DENIED_SYSCALLS = (
    57,  # fork
    58,  # vfork
    59,  # execve
    101,  # ptrace
    155,  # pivot_root
    165,  # mount
    166,  # umount2
    167,  # swapon
    168,  # swapoff
    169,  # reboot
    175,  # init_module
    176,  # delete_module
    246,  # kexec_load
    248,  # add_key
    249,  # request_key
    250,  # keyctl
    272,  # unshare
    298,  # perf_event_open
    304,  # open_by_handle_at
    308,  # setns
    310,  # process_vm_readv
    311,  # process_vm_writev
    313,  # finit_module
    320,  # kexec_file_load
    321,  # bpf
    322,  # execveat
    323,  # userfaultfd
    425,  # io_uring_setup
    426,  # io_uring_enter
    427,  # io_uring_register
    428,  # open_tree
    429,  # move_mount
    430,  # fsopen
    431,  # fsconfig
    432,  # fsmount
    433,  # fspick
    442,  # mount_setattr
)


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(_SockFilter))]


_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.syscall.restype = ctypes.c_long
_PRCTL = getattr(_LIBC, "prctl", None)
_O_PATH = getattr(os, "O_PATH", 0)
if _PRCTL is not None:
    _PRCTL.restype = ctypes.c_int


def _require_linux_amd64() -> None:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise RuntimeIsolationError("kernel isolation requires Linux amd64")


def _syscall(number: int, *args: Any) -> int:
    result = int(_LIBC.syscall(ctypes.c_long(number), *args))
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def _set_no_new_privileges() -> None:
    if _PRCTL is None:
        raise RuntimeIsolationError("prctl is unavailable")
    if _PRCTL(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _landlock_write_access(abi: int) -> int:
    access = (
        _LANDLOCK_ACCESS_FS_WRITE_FILE
        | _LANDLOCK_ACCESS_FS_REMOVE_DIR
        | _LANDLOCK_ACCESS_FS_REMOVE_FILE
        | _LANDLOCK_ACCESS_FS_MAKE_CHAR
        | _LANDLOCK_ACCESS_FS_MAKE_DIR
        | _LANDLOCK_ACCESS_FS_MAKE_REG
        | _LANDLOCK_ACCESS_FS_MAKE_SOCK
        | _LANDLOCK_ACCESS_FS_MAKE_FIFO
        | _LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | _LANDLOCK_ACCESS_FS_MAKE_SYM
    )
    if abi >= 2:
        access |= _LANDLOCK_ACCESS_FS_REFER
    if abi >= 3:
        access |= _LANDLOCK_ACCESS_FS_TRUNCATE
    return access


def install_filesystem_guard(writable_root: Path) -> None:
    """Make all filesystem writes except ``writable_root`` fail in kernel."""

    _require_linux_amd64()
    try:
        abi = _syscall(
            _SYS_LANDLOCK_CREATE_RULESET,
            ctypes.c_void_p(),
            ctypes.c_size_t(0),
            ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION),
        )
        if abi < _MINIMUM_LANDLOCK_ABI:
            raise RuntimeIsolationError("Landlock ABI 3 or newer is required")
        access = _landlock_write_access(abi)
        ruleset = _LandlockRulesetAttr(access)
        ruleset_fd = _syscall(
            _SYS_LANDLOCK_CREATE_RULESET,
            ctypes.byref(ruleset),
            ctypes.sizeof(ruleset),
            0,
        )
    except OSError as exc:
        raise RuntimeIsolationError("Landlock filesystem isolation is unavailable") from exc

    path_fd = -1
    try:
        if not _O_PATH:
            raise RuntimeIsolationError("O_PATH is unavailable")
        path_fd = os.open(writable_root, _O_PATH | os.O_CLOEXEC)
        path_rule = _LandlockPathBeneathAttr(access, path_fd)
        _syscall(
            _SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            _LANDLOCK_RULE_PATH_BENEATH,
            ctypes.byref(path_rule),
            0,
        )
        _set_no_new_privileges()
        _syscall(_SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
    except OSError as exc:
        raise RuntimeIsolationError("failed to install Landlock filesystem isolation") from exc
    finally:
        if path_fd >= 0:
            os.close(path_fd)
        os.close(ruleset_fd)


def _statement(code: int, k: int) -> _SockFilter:
    return _SockFilter(code, 0, 0, k)


def _jump(code: int, k: int, true_offset: int, false_offset: int) -> _SockFilter:
    return _SockFilter(code, true_offset, false_offset, k)


def _build_seccomp_filter() -> list[_SockFilter]:
    filters = [
        _statement(_BPF_LD_W_ABS, _SECCOMP_DATA_ARCH_OFFSET),
        _jump(_BPF_JMP_JEQ_K, _AUDIT_ARCH_X86_64, 1, 0),
        _statement(_BPF_RET_K, _SECCOMP_RET_KILL_PROCESS),
        _statement(_BPF_LD_W_ABS, _SECCOMP_DATA_NR_OFFSET),
    ]
    denied = _SECCOMP_RET_ERRNO | errno.EPERM
    for syscall_number in _DENIED_SYSCALLS:
        filters.extend(
            (
                _jump(_BPF_JMP_JEQ_K, syscall_number, 0, 1),
                _statement(_BPF_RET_K, denied),
            )
        )

    # Make clone3 look unsupported so libc can fall back to clone. Permit only
    # clone calls carrying CLONE_THREAD; fork-like clones receive EPERM.
    filters.extend(
        (
            _jump(_BPF_JMP_JEQ_K, _SYS_CLONE3, 0, 1),
            _statement(_BPF_RET_K, _SECCOMP_RET_ERRNO | errno.ENOSYS),
            _jump(_BPF_JMP_JEQ_K, _SYS_CLONE, 0, 3),
            _statement(_BPF_LD_W_ABS, _SECCOMP_DATA_ARGS_OFFSET),
            _jump(_BPF_JMP_JSET_K, _CLONE_THREAD, 1, 0),
            _statement(_BPF_RET_K, denied),
            _statement(_BPF_RET_K, _SECCOMP_RET_ALLOW),
        )
    )
    return filters


def install_seccomp_guard() -> None:
    """Install syscall filter for process and kernel escape primitives."""

    _require_linux_amd64()
    filters = _build_seccomp_filter()
    filter_array = (_SockFilter * len(filters))(*filters)
    program = _SockFprog(len(filters), filter_array)
    try:
        _set_no_new_privileges()
        _syscall(
            _SYS_SECCOMP,
            _SECCOMP_SET_MODE_FILTER,
            _SECCOMP_FILTER_FLAG_TSYNC,
            ctypes.byref(program),
        )
    except OSError as exc:
        raise RuntimeIsolationError("failed to install seccomp syscall isolation") from exc


def install_kernel_isolation(writable_root: Path) -> None:
    install_filesystem_guard(writable_root)
    install_seccomp_guard()

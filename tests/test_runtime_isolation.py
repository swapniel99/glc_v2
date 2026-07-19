from __future__ import annotations

import platform
import subprocess
import sys

import pytest

from glc.security import runtime_isolation


def _seccomp_result(syscall_number: int, *, clone_flags: int = 0) -> int:
    accumulator = 0
    program = runtime_isolation._build_seccomp_filter()
    counter = 0
    while counter < len(program):
        instruction = program[counter]
        if instruction.code == runtime_isolation._BPF_LD_W_ABS:
            accumulator = {
                runtime_isolation._SECCOMP_DATA_ARCH_OFFSET: runtime_isolation._AUDIT_ARCH_X86_64,
                runtime_isolation._SECCOMP_DATA_NR_OFFSET: syscall_number,
                runtime_isolation._SECCOMP_DATA_ARGS_OFFSET: clone_flags,
            }[instruction.k]
            counter += 1
        elif instruction.code == runtime_isolation._BPF_JMP_JEQ_K:
            counter += (instruction.jt if accumulator == instruction.k else instruction.jf) + 1
        elif instruction.code == runtime_isolation._BPF_JMP_JSET_K:
            counter += (instruction.jt if accumulator & instruction.k else instruction.jf) + 1
        elif instruction.code == runtime_isolation._BPF_RET_K:
            return int(instruction.k)
        else:  # pragma: no cover - test helper rejects unknown BPF instructions
            raise AssertionError(f"unsupported BPF instruction {instruction.code}")
    raise AssertionError("seccomp program returned no action")


def test_seccomp_filter_denies_exec_fork_and_kernel_escape_syscalls():
    filters = runtime_isolation._build_seccomp_filter()
    comparisons = {item.k for item in filters if item.code == runtime_isolation._BPF_JMP_JEQ_K}

    assert 59 in comparisons  # execve
    assert 57 in comparisons  # fork
    assert 101 in comparisons  # ptrace
    assert 165 in comparisons  # mount
    assert 272 in comparisons  # unshare
    assert runtime_isolation._SYS_CLONE in comparisons
    assert runtime_isolation._SYS_CLONE3 in comparisons
    assert _seccomp_result(59) == runtime_isolation._SECCOMP_RET_ERRNO | 1
    assert _seccomp_result(runtime_isolation._SYS_CLONE) == runtime_isolation._SECCOMP_RET_ERRNO | 1
    assert (
        _seccomp_result(runtime_isolation._SYS_CLONE, clone_flags=runtime_isolation._CLONE_THREAD)
        == runtime_isolation._SECCOMP_RET_ALLOW
    )
    assert _seccomp_result(0) == runtime_isolation._SECCOMP_RET_ALLOW


def test_landlock_access_includes_write_mutation_and_modern_migration_rights():
    access = runtime_isolation._landlock_write_access(3)

    assert access & runtime_isolation._LANDLOCK_ACCESS_FS_WRITE_FILE
    assert access & runtime_isolation._LANDLOCK_ACCESS_FS_REMOVE_FILE
    assert access & runtime_isolation._LANDLOCK_ACCESS_FS_MAKE_REG
    assert access & runtime_isolation._LANDLOCK_ACCESS_FS_REFER
    assert access & runtime_isolation._LANDLOCK_ACCESS_FS_TRUNCATE


def test_kernel_isolation_rejects_unsupported_platform(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime_isolation.platform, "system", lambda: "Darwin")

    with pytest.raises(runtime_isolation.RuntimeIsolationError, match="Linux amd64"):
        runtime_isolation.install_kernel_isolation(tmp_path)


def test_filesystem_guard_requires_landlock_abi_three(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime_isolation.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runtime_isolation.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(runtime_isolation, "_syscall", lambda *args: 2)

    with pytest.raises(runtime_isolation.RuntimeIsolationError, match="ABI 3"):
        runtime_isolation.install_filesystem_guard(tmp_path)


@pytest.mark.skipif(
    platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"},
    reason="Landlock/seccomp integration requires Linux amd64",
)
def test_kernel_guards_enforce_write_allowlist_and_exec_denial(tmp_path):
    writable = tmp_path / "runtime"
    outside = tmp_path / "outside"
    writable.mkdir()
    code = """
from pathlib import Path
import subprocess
import sys

from glc.security.runtime_isolation import install_kernel_isolation

writable = Path(sys.argv[1])
outside = Path(sys.argv[2])
install_kernel_isolation(writable)
(writable / "allowed").write_text("ok")
try:
    outside.write_text("blocked")
except PermissionError:
    pass
else:
    raise SystemExit("write outside allowlist succeeded")
try:
    subprocess.run(["true"], check=False)
except OSError:
    pass
else:
    raise SystemExit("process execution succeeded")
"""

    result = subprocess.run(
        [sys.executable, "-c", code, str(writable), str(outside)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (writable / "allowed").read_text() == "ok"
    assert not outside.exists()

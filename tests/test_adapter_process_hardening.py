from __future__ import annotations

import subprocess
import sys


def test_process_guard_blocks_standard_process_apis():
    code = """
import asyncio
import os
import subprocess

from glc.security.process_guard import ProcessExecutionDenied, install_process_guard

install_process_guard()
blocked = [
    lambda: subprocess.run([\"true\"]),
    lambda: os.system(\"true\"),
    lambda: asyncio.run(asyncio.create_subprocess_exec(\"true\")),
]
for attempt in blocked:
    try:
        attempt()
    except ProcessExecutionDenied:
        continue
    raise SystemExit(1)
"""

    result = subprocess.run([sys.executable, "-c", code], check=False)

    assert result.returncode == 0


def test_worker_drops_root_to_unprivileged_numeric_user(monkeypatch):
    from glc.channels import sandbox_runner

    effective_uids = iter([0, sandbox_runner._RUNTIME_UID])
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(sandbox_runner.os, "geteuid", lambda: next(effective_uids))
    monkeypatch.setattr(
        sandbox_runner.os,
        "setgroups",
        lambda groups: calls.append(("setgroups", groups)),
    )
    monkeypatch.setattr(
        sandbox_runner.os,
        "setgid",
        lambda gid: calls.append(("setgid", gid)),
    )
    monkeypatch.setattr(
        sandbox_runner.os,
        "setuid",
        lambda uid: calls.append(("setuid", uid)),
    )

    sandbox_runner._drop_privileges()

    assert calls == [
        ("setgroups", []),
        ("setgid", sandbox_runner._RUNTIME_GID),
        ("setuid", sandbox_runner._RUNTIME_UID),
    ]


def test_worker_leaves_only_private_runtime_directory_writable(monkeypatch, tmp_path):
    from glc.channels import sandbox_runner

    shared = tmp_path / "shared"
    runtime = shared / "adapter"
    shared.mkdir(mode=0o777)
    shared.chmod(0o777)
    ownership: list[tuple[object, int, int]] = []
    monkeypatch.setattr(sandbox_runner, "_RUNTIME_HOME", runtime)
    monkeypatch.setattr(sandbox_runner, "_SHARED_WRITABLE_DIRS", (shared,))
    monkeypatch.setattr(sandbox_runner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        sandbox_runner.os,
        "chown",
        lambda path, uid, gid: ownership.append((path, uid, gid)),
    )

    assert sandbox_runner._prepare_runtime_filesystem()

    assert shared.stat().st_mode & 0o777 == 0o755
    assert runtime.stat().st_mode & 0o777 == 0o700
    assert (runtime / "config").stat().st_mode & 0o777 == 0o700
    assert (runtime / "tmp").stat().st_mode & 0o777 == 0o700
    assert ownership == [
        (runtime, sandbox_runner._RUNTIME_UID, sandbox_runner._RUNTIME_GID),
        (runtime / "config", sandbox_runner._RUNTIME_UID, sandbox_runner._RUNTIME_GID),
        (runtime / "tmp", sandbox_runner._RUNTIME_UID, sandbox_runner._RUNTIME_GID),
    ]


def test_worker_hardens_before_loading_adapter(monkeypatch):
    from glc.channels import sandbox_runner

    events: list[str] = []
    monkeypatch.setattr(sys, "argv", ["sandbox_runner", "telegram"])
    monkeypatch.setattr(sandbox_runner, "_harden_runtime", lambda: events.append("harden"))

    async def run(name: str) -> None:
        events.append(f"run:{name}")

    monkeypatch.setattr(sandbox_runner, "_run", run)

    sandbox_runner.main()

    assert events == ["harden", "run:telegram"]


def test_worker_installs_kernel_guard_before_python_guard(monkeypatch, tmp_path):
    from glc.channels import sandbox_runner
    from glc.security import process_guard, runtime_isolation

    events: list[str] = []
    monkeypatch.setattr(sandbox_runner, "_RUNTIME_HOME", tmp_path / "runtime")
    monkeypatch.setattr(sandbox_runner, "_drop_privileges", lambda: events.append("drop"))
    monkeypatch.setattr(
        runtime_isolation,
        "install_kernel_isolation",
        lambda path, **kwargs: events.append(
            f"kernel:{path.name}:{kwargs['allow_missing_landlock']}"
        ),
    )
    monkeypatch.setattr(process_guard, "install_process_guard", lambda: events.append("python"))

    sandbox_runner._harden_runtime()

    assert events == ["drop", "kernel:runtime:False", "python"]

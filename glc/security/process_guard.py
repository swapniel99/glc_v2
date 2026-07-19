"""Defense-in-depth guard against adapter child-process execution.

Modal's gVisor Sandbox remains the kernel security boundary. This guard
removes normal Python paths to shells and subprocesses before untrusted
adapter modules are imported.
"""

from __future__ import annotations

import asyncio
import multiprocessing.process
import os
import subprocess
from typing import Any, NoReturn


class ProcessExecutionDenied(PermissionError):
    pass


def _deny_process_execution(*args: Any, **kwargs: Any) -> NoReturn:
    raise ProcessExecutionDenied("adapter subprocess execution is disabled")


def install_process_guard() -> None:
    """Disable standard-library process creation APIs for this worker."""

    for name in (
        "Popen",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
        "run",
    ):
        setattr(subprocess, name, _deny_process_execution)

    for name in (
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "fork",
        "forkpty",
        "popen",
        "posix_spawn",
        "posix_spawnp",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "system",
    ):
        if hasattr(os, name):
            setattr(os, name, _deny_process_execution)

    asyncio.create_subprocess_exec = _deny_process_execution
    asyncio.create_subprocess_shell = _deny_process_execution
    multiprocessing.process.BaseProcess.start = _deny_process_execution

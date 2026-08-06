from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

Command = Callable[..., subprocess.CompletedProcess[str]]


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def command(repo_root: Path) -> Command:
    def execute(
        args: Sequence[str | Path],
        *,
        check: bool = True,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [str(arg) for arg in args],
            cwd=repo_root,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )
        if check and result.returncode != 0:
            raise AssertionError(
                f"command failed ({result.returncode}): {args}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    return execute


@pytest.fixture
def run_script(command: Command, repo_root: Path) -> Command:
    def execute(
        script: str,
        *args: str | Path,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return command(
            ["bash", repo_root / script, *args],
            check=check,
        )

    return execute


@pytest.fixture
def fixture_json(repo_root: Path) -> Callable[[str], dict[str, Any]]:
    def load(relative_path: str) -> dict[str, Any]:
        return json.loads((repo_root / relative_path).read_text(encoding="utf-8"))

    return load


@pytest.fixture
def write_json() -> Callable[[Path, Any], Path]:
    def write(path: Path, value: Any) -> Path:
        path.write_text(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    return write


@pytest.fixture
def canonical_copy(command: Command) -> Callable[[Path, Path], Path]:
    def copy(source: Path, target: Path) -> Path:
        result = command(["jq", "-e", "-cS", ".", source])
        target.write_text(result.stdout, encoding="utf-8")
        return target

    return copy


@pytest.fixture
def json_digest(command: Command) -> Callable[[Path], str]:
    def digest(path: Path) -> str:
        canonical = command(["jq", "-e", "-cS", ".", path]).stdout
        return hashlib.sha256(canonical.rstrip("\n").encode("utf-8")).hexdigest()

    return digest


@pytest.fixture
def file_digest() -> Callable[[Path], str]:
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    return digest


@pytest.fixture
def assert_failed() -> Callable[[subprocess.CompletedProcess[str]], None]:
    def check(result: subprocess.CompletedProcess[str]) -> None:
        assert result.returncode != 0, (
            "expected command to fail, but it succeeded:\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    return check

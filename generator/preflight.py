"""AST preflight scan — primary safety barrier (LLD-01 §4.3).

Scans each .py file as INERT TEXT via ast.parse(bytes, filename, mode="exec").
Never imports, never exec's, never compiles for execution. Returns a list of
Violation records (not fail-fast) so reviewers see the full surface.
"""

from __future__ import annotations

import ast
import multiprocessing
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Iterable

from .exceptions import (
    MultiProcessError,
    NonDeterministicEnvironmentError,
)


@dataclass(frozen=True, slots=True)
class Violation:
    """Single preflight rule violation (LLD-01 §4.8)."""

    file: str
    line: int
    column: int
    rule: str
    snippet: str


# Ordered rule names (defense-in-depth-ordered). Length 19.
PREFLIGHT_RULES: Final[tuple[str, ...]] = (
    "forbid_subprocess_import",       # 1
    "forbid_subprocess_dynamic",      # 2
    "forbid_commands_legacy",         # 3
    "forbid_os_system",               # 4
    "forbid_os_popen",                # 5
    "forbid_os_exec_family",          # 6
    "forbid_os_dynamic_attr",         # 7
    "forbid_socket",                  # 8
    "forbid_urllib",                  # 9
    "forbid_http_client",             # 10
    "forbid_dev_tcp_open",            # 11
    "forbid_eval_exec_compile",       # 12
    "forbid_tty_access",              # 13
    "forbid_module_level_random",     # 14
    "forbid_os_environ",              # 15
    "forbid_time_sources",            # 16
    "forbid_datetime_now",            # 17
    "forbid_uuid_random",             # 18
    "forbid_getlogin_getpass",        # 19
)

assert len(PREFLIGHT_RULES) == 19, "PREFLIGHT_RULES must have exactly 19 rules"

_OS_EXEC_SPAWN_ATTRS = frozenset({
    "execv", "execve", "execl", "execle", "execlp", "execlpe",
    "execvp", "execvpe",
    "spawnv", "spawnve", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnvp", "spawnvpe",
})

_RANDOM_MODULE_METHODS = frozenset({
    "random", "randint", "choice", "choices",
    "shuffle", "sample", "uniform", "seed", "getrandbits",
})

_TIME_NONDETERMINISTIC_ATTRS = frozenset({
    "time", "monotonic", "perf_counter", "process_time",
})

_DATETIME_NOW_ATTRS = frozenset({"now", "utcnow", "today"})
_UUID_NONDETERMINISTIC = frozenset({"uuid1", "uuid4"})
_TTY_MODULES = frozenset({"pty", "fcntl", "termios"})


def _module_starts_with(name: str | None, prefix: str) -> bool:
    if not name:
        return False
    return name == prefix or name.startswith(prefix + ".")


def _source_line(source_bytes: bytes, lineno: int) -> str:
    """Return a trimmed snippet of the given 1-based line (≤120 chars)."""
    if lineno <= 0:
        return ""
    try:
        text = source_bytes.decode("utf-8", errors="replace")
    except Exception:
        return ""
    lines = text.splitlines()
    if lineno > len(lines):
        return ""
    return lines[lineno - 1].strip()[:120]


def _is_attr_call(node: ast.AST, obj_name: str, attrs: Iterable[str]) -> bool:
    """Match ast.Call(func=Attribute(value=Name(obj_name), attr in attrs))."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in set(attrs):
        return False
    val = func.value
    return isinstance(val, ast.Name) and val.id == obj_name


def _is_name_call(node: ast.AST, name: str) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return isinstance(node.func, ast.Name) and node.func.id == name


def _is_string_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _contains_subprocess_literal(value: str) -> bool:
    return "subprocess" in value


def _is_string_binop_or_joined(node: ast.AST) -> bool:
    """Detect a runtime-assembled string: concatenation or f-string / JoinedStr."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    return False


def _top_level_calls_of_module(
    tree: ast.Module, module_name: str, attrs: Iterable[str]
) -> list[ast.Call]:
    """Yield Call nodes in module body and class bodies (NOT function bodies).

    Used for rule #14 forbid_module_level_random: only flag module/class scope.
    """
    out: list[ast.Call] = []
    attr_set = set(attrs)

    def _walk_non_function(body: list[ast.stmt]) -> None:
        for stmt in body:
            # Recurse into class bodies, but NOT into function/async-function bodies.
            if isinstance(stmt, ast.ClassDef):
                _walk_non_function(stmt.body)
                continue
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Walk everything else (expressions, ifs, fors, withs at module/class scope).
            for sub in ast.walk(stmt):
                # Don't descend into nested function/class bodies either.
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if isinstance(sub, ast.Call):
                    f = sub.func
                    if (
                        isinstance(f, ast.Attribute)
                        and isinstance(f.value, ast.Name)
                        and f.value.id == module_name
                        and f.attr in attr_set
                    ):
                        out.append(sub)

    _walk_non_function(tree.body)
    return out


def _scan_tree(
    tree: ast.Module,
    source_bytes: bytes,
    file_path: str,
    filename_only: str,
) -> list[Violation]:
    """Apply all 19 rules to a parsed module. Returns violations list."""
    violations: list[Violation] = []

    def _vio(node: ast.AST, rule: str) -> None:
        line = getattr(node, "lineno", 0) or 0
        col = (getattr(node, "col_offset", 0) or 0) + 1
        violations.append(
            Violation(
                file=file_path,
                line=line,
                column=col,
                rule=rule,
                snippet=_source_line(source_bytes, line),
            )
        )

    # Walk once for most rules that apply to ANY scope.
    for node in ast.walk(tree):
        # Rule 1: forbid_subprocess_import
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess" or alias.name.startswith("subprocess."):
                    _vio(node, "forbid_subprocess_import")
                if alias.name == "commands":
                    _vio(node, "forbid_commands_legacy")
                if alias.name == "socket" or alias.name.startswith("socket."):
                    _vio(node, "forbid_socket")
                if alias.name.startswith("urllib"):
                    _vio(node, "forbid_urllib")
                if alias.name == "http" or alias.name.startswith("http."):
                    _vio(node, "forbid_http_client")
                if alias.name in _TTY_MODULES:
                    _vio(node, "forbid_tty_access")
                if alias.name == "getpass":
                    _vio(node, "forbid_getlogin_getpass")

        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if _module_starts_with(mod, "subprocess"):
                _vio(node, "forbid_subprocess_import")
            if _module_starts_with(mod, "socket"):
                _vio(node, "forbid_socket")
            if mod.startswith("urllib"):
                _vio(node, "forbid_urllib")
            if mod == "http" or mod.startswith("http."):
                _vio(node, "forbid_http_client")
            if mod in _TTY_MODULES:
                _vio(node, "forbid_tty_access")
            if mod == "getpass":
                _vio(node, "forbid_getlogin_getpass")

        # Rule 2: forbid_subprocess_dynamic — __import__("sub" + "process") or similar
        if _is_name_call(node, "__import__"):
            assert isinstance(node, ast.Call)
            if node.args:
                arg0 = node.args[0]
                if _is_string_const(arg0):
                    if _contains_subprocess_literal(arg0.value):  # type: ignore[attr-defined]
                        _vio(node, "forbid_subprocess_dynamic")
                elif _is_string_binop_or_joined(arg0):
                    _vio(node, "forbid_subprocess_dynamic")

        # Rule 4: forbid_os_system / Rule 5: forbid_os_popen / Rule 6: exec family /
        # Rule 19: os.getlogin
        if _is_attr_call(node, "os", {"system"}):
            _vio(node, "forbid_os_system")
        if _is_attr_call(node, "os", {"popen"}):
            _vio(node, "forbid_os_popen")
        if _is_attr_call(node, "os", _OS_EXEC_SPAWN_ATTRS):
            _vio(node, "forbid_os_exec_family")
        if _is_attr_call(node, "os", {"getlogin"}):
            _vio(node, "forbid_getlogin_getpass")

        # Rule 7: forbid_os_dynamic_attr — getattr(os, <non-literal>)
        if _is_name_call(node, "getattr"):
            assert isinstance(node, ast.Call)
            if len(node.args) >= 2:
                target, attr = node.args[0], node.args[1]
                if isinstance(target, ast.Name) and target.id == "os":
                    if _is_string_const(attr):
                        pass  # literal attr is handled by the specific rules 4-6
                    else:
                        _vio(node, "forbid_os_dynamic_attr")

        # Rule 11: forbid_dev_tcp_open — open("/dev/tcp/...") or "/dev/udp/..."
        if _is_name_call(node, "open"):
            assert isinstance(node, ast.Call)
            if node.args:
                arg0 = node.args[0]
                if _is_string_const(arg0):
                    v = arg0.value  # type: ignore[attr-defined]
                    if isinstance(v, str) and (
                        v.startswith("/dev/tcp/") or v.startswith("/dev/udp/")
                    ):
                        _vio(node, "forbid_dev_tcp_open")

        # Rule 12: forbid_eval_exec_compile
        if _is_name_call(node, "eval"):
            _vio(node, "forbid_eval_exec_compile")
        if _is_name_call(node, "exec"):
            _vio(node, "forbid_eval_exec_compile")
        if _is_name_call(node, "compile"):
            assert isinstance(node, ast.Call)
            if any(
                _is_string_const(a)
                and isinstance(a.value, str)  # type: ignore[attr-defined]
                and a.value == "exec"  # type: ignore[attr-defined]
                for a in node.args
            ):
                _vio(node, "forbid_eval_exec_compile")

        # Rule 15: forbid_os_environ — EXCEPTION for __main__.py (handled at caller).
        if filename_only != "__main__.py":
            if isinstance(node, ast.Subscript):
                val = node.value
                if (
                    isinstance(val, ast.Attribute)
                    and val.attr == "environ"
                    and isinstance(val.value, ast.Name)
                    and val.value.id == "os"
                ):
                    _vio(node, "forbid_os_environ")
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr in {"get", "setdefault"}:
                    inner = func.value
                    if (
                        isinstance(inner, ast.Attribute)
                        and inner.attr == "environ"
                        and isinstance(inner.value, ast.Name)
                        and inner.value.id == "os"
                    ):
                        _vio(node, "forbid_os_environ")

        # Rule 16: forbid_time_sources
        if _is_attr_call(node, "time", _TIME_NONDETERMINISTIC_ATTRS):
            _vio(node, "forbid_time_sources")

        # Rule 17: forbid_datetime_now
        if _is_attr_call(node, "datetime", _DATETIME_NOW_ATTRS):
            _vio(node, "forbid_datetime_now")

        # Rule 18: forbid_uuid_random
        if _is_attr_call(node, "uuid", _UUID_NONDETERMINISTIC):
            _vio(node, "forbid_uuid_random")

    # Rule 14: module-level random.* — special scope handling
    module_level_random_calls = _top_level_calls_of_module(
        tree, "random", _RANDOM_MODULE_METHODS
    )
    for call in module_level_random_calls:
        line = getattr(call, "lineno", 0) or 0
        col = (getattr(call, "col_offset", 0) or 0) + 1
        violations.append(
            Violation(
                file=file_path,
                line=line,
                column=col,
                rule="forbid_module_level_random",
                snippet=_source_line(source_bytes, line),
            )
        )

    return violations


def ast_scan_package(package_root: Path) -> list[Violation]:
    """Scan all .py files under package_root (recursive). Return full list.

    Per §4.3.3. Fixture scope: tests pass a user-supplied package root; runtime
    scope uses the generator's own benchmarks/generator/ tree. EXCLUDE
    __main__.py from rule #15 (os.environ).
    """
    if not isinstance(package_root, Path):
        package_root = Path(package_root)
    violations: list[Violation] = []
    for py_file in sorted(package_root.rglob("*.py")):
        filename_only = py_file.name
        try:
            source_bytes = py_file.read_bytes()
        except OSError as exc:
            violations.append(
                Violation(
                    file=str(py_file),
                    line=0,
                    column=0,
                    rule="read_error",
                    snippet=str(exc),
                )
            )
            continue
        try:
            tree = ast.parse(source_bytes, filename=str(py_file), mode="exec")
        except SyntaxError as exc:
            violations.append(
                Violation(
                    file=str(py_file),
                    line=getattr(exc, "lineno", 0) or 0,
                    column=getattr(exc, "offset", 0) or 0,
                    rule="parse_error",
                    snippet=str(exc),
                )
            )
            continue
        violations.extend(
            _scan_tree(tree, source_bytes, str(py_file), filename_only)
        )
    return violations


def assert_single_process() -> None:
    """Raise MultiProcessError if multi-thread / multi-process detected (§4.3.5)."""
    n_threads = threading.active_count()
    parent = multiprocessing.parent_process()
    if n_threads > 1 or parent is not None:
        raise MultiProcessError(
            f"generator v1.0 is single-thread / single-process only; "
            f"detected active_count={n_threads}, parent_process={parent!r}"
        )


def assert_pythonhashseed_zero_equiv(observed: str) -> None:
    """Raise NonDeterministicEnvironmentError if observed != '0' (§4.3.4).

    The CLI (__main__.py) is the sole permitted os.environ reader; it forwards
    the observed value to this function via the BenchmarkGenerator constructor.
    """
    if observed != "0":
        raise NonDeterministicEnvironmentError(
            f'PYTHONHASHSEED must be "0" for deterministic generation, got {observed!r}'
        )

"""CI wrappers that run uv, pnpm or pytest re-exec through with-tmp-layout (repository-helpers#832).

The helper is never copied here: each wrapper finds it through REPOSITORY_HELPERS_DIR (exported by the
setup-tmp-layout action in CI) or the local clone, fails in GitHub Actions when it is missing, and runs
unchanged on a host that has no clone. A fake helper stands in for the real one.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CI_DIR = REPO / ".github" / "ci"
WORKFLOWS = REPO / ".github" / "workflows"
ACTION = "the-hcma/repository-helpers/actions/setup-tmp-layout@bfee0e1f2d682e83c6207a0d6a0f7feefa576fd8"

# wrapper -> tools whose temp layout it must request, outermost first
WRAPPERS = {
    "catalog-render-validate": ["uv"],
    "dns-catalog-validate": ["uv"],
    "nginx-security-lint": ["uv"],
    "pdns-reload-gate-test": ["uv"],
    "pytest": ["uv", "pytest"],
    "python-static": ["uv"],
    "web-build": ["pnpm"],
}


def _env(tmp_path: Path, helpers: Path, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in {"CI_TMP_LAYOUT", "GITHUB_ACTIONS"}}
    env.update({"HOME": str(tmp_path), "REPOSITORY_HELPERS_DIR": str(helpers), "TMPDIR": str(tmp_path)})
    env.update(extra)
    return env


def _fake_helpers(tmp_path: Path) -> Path:
    helpers = tmp_path / "helpers"
    (helpers / "scripts" / "dev").mkdir(parents=True)
    fake = helpers / "scripts" / "dev" / "with-tmp-layout"
    # Like the real helper: take `<tool> -- <command...>`, refuse a missing separator, and run the command. The
    # innermost command is the wrapper re-entering itself; record the recursion guard it would see instead of
    # running the real work.
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'printf \'%s\\n\' "tool=$1" >> "$TMPDIR/layout-calls"\n'
        '[[ "$2" == -- ]] || { echo "missing -- separator" >&2; exit 64; }\n'
        "shift 2\n"
        'if [[ "$1" == bash ]]; then\n'
        '  printf \'%s\\n\' "guard=${CI_TMP_LAYOUT:-}" >> "$TMPDIR/layout-calls"\n'
        "  exit 0\n"
        "fi\n"
        'exec "$@"\n'
    )
    fake.chmod(0o755)
    return helpers


@pytest.mark.parametrize("wrapper", sorted(WRAPPERS))
def test_ci_without_the_layout_helper_fails_with_a_pointer_to_the_action(tmp_path: Path, wrapper: str) -> None:
    empty = tmp_path / "none"
    empty.mkdir()
    result = subprocess.run(
        ["bash", str(CI_DIR / wrapper)],
        cwd=REPO,
        env=_env(tmp_path, empty, GITHUB_ACTIONS="true"),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 1
    assert "setup-tmp-layout" in result.stderr


@pytest.mark.parametrize("wrapper", sorted(WRAPPERS))
def test_the_wrapper_runs_itself_again_through_each_tool_layout_with_the_guard_set(
    tmp_path: Path, wrapper: str
) -> None:
    helpers = _fake_helpers(tmp_path)
    result = subprocess.run(
        ["bash", str(CI_DIR / wrapper)],
        cwd=REPO,
        env=_env(tmp_path, helpers),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    calls = (tmp_path / "layout-calls").read_text().split()
    assert calls == [f"tool={tool}" for tool in WRAPPERS[wrapper]] + ["guard=1"]


@pytest.mark.parametrize("wrapper", sorted(WRAPPERS))
def test_a_wrapper_already_inside_the_layout_does_not_enter_it_again(tmp_path: Path, wrapper: str) -> None:
    helpers = _fake_helpers(tmp_path)
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for tool in ("bash", "uv", "pnpm"):
        (stubs / tool).write_text("#!/bin/sh\nexit 0\n")
        (stubs / tool).chmod(0o755)
    env = _env(tmp_path, helpers, CI_TMP_LAYOUT="1", PATH=f"{stubs}:{os.environ['PATH']}")
    subprocess.run(
        [shutil.which("bash") or "/bin/bash", str(CI_DIR / wrapper)],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert not (tmp_path / "layout-calls").exists()


@pytest.mark.parametrize("wrapper", sorted(WRAPPERS))
def test_the_wrapper_reexec_line_names_its_tool_layouts(wrapper: str) -> None:
    text = (CI_DIR / wrapper).read_text()
    match = re.search(r'exec "\$layout_bin" (.+) -- bash "\$0"', text)
    assert match is not None
    tools = [word for word in match.group(1).replace('"$layout_bin"', "").replace("--", "").split()]
    assert tools == WRAPPERS[wrapper]


def test_every_workflow_job_that_runs_a_wrapper_or_uv_sets_up_the_layout_first() -> None:
    triggers = re.compile(r"\b(?:uv (?:run|sync)|pnpm |bash \.github/ci/(?:" + "|".join(WRAPPERS) + r"))\b")
    checked = 0
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        jobs = re.split(r"^  (?=[a-z][\w-]*:\n)", workflow.read_text(), flags=re.MULTILINE)
        for job in jobs[1:]:
            lines = job.splitlines()
            first = next((i for i, line in enumerate(lines) if triggers.search(line) and "# " not in line[:12]), None)
            if first is None:
                continue
            checked += 1
            setup = next((i for i, line in enumerate(lines) if ACTION in line), None)
            assert setup is not None and setup < first, (
                f"{workflow.name}: {lines[0]} runs a layout tool without {ACTION}"
            )
    assert checked >= 8

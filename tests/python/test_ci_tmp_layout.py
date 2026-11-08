"""CI wrappers that run uv, pnpm or pytest re-exec through with-tmp-layout (repository-helpers#832).

The helper is never copied here: each wrapper finds it through REPOSITORY_HELPERS_DIR (exported by the
setup-tmp-layout action in CI) or the local clone, fails in GitHub Actions when it is missing, and runs
unchanged on a host that has no clone. A fake helper stands in for the real one.
"""

import os
import re
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
    # Record the tool, then run the rest of the command with CI_TMP_LAYOUT already set, as the real helper does.
    fake.write_text('#!/usr/bin/env bash\nprintf \'%s\\n\' "$1" >> "$TMPDIR/layout-tools"\nshift 2\nexit 0\n')
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
def test_the_wrapper_hands_its_run_to_the_layout_helper_for_its_outer_tool(tmp_path: Path, wrapper: str) -> None:
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
    assert result.returncode == 0
    assert (tmp_path / "layout-tools").read_text().split()[:1] == [WRAPPERS[wrapper][0]]


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

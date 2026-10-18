"""The manual workflow keeps its security boundaries and valid shell programs."""

import re
import shutil
import subprocess
from pathlib import Path

import yaml


def test_manual_ci_boundaries_and_shell_syntax():
    workflow = yaml.load(
        (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["quality"]["strategy"]["matrix"]["python-version"] == [
        "3.11", "3.12",
    ]
    bash = shutil.which("bash")
    assert bash
    installed_validation = False
    for job in workflow["jobs"].values():
        assert int(job["timeout-minutes"]) <= 15
        assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"])
                if step["uses"].startswith("actions/checkout@"):
                    assert step["with"]["persist-credentials"] == "false"
            if "run" in step:
                syntax = subprocess.run(
                    [bash, "-n"], input=step["run"], text=True,
                    capture_output=True, timeout=5, check=False,
                )
                assert syntax.returncode == 0, syntax.stderr
                if "scripts/validate_install.py" in step["run"]:
                    installed_validation = True
                    assert "dist/*.whl" in step["run"]
                    assert "dist/*.tar.gz" in step["run"]
    assert installed_validation

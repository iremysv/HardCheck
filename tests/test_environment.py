"""Environment detection uses fake roots and treats absence as unknown."""

from hardcheck.environment import detect_environment


def test_linux_markers(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID="debian"\n')
    (tmp_path / "run/systemd/system").mkdir(parents=True)
    (tmp_path / ".dockerenv").touch()
    env = detect_environment(tmp_path, "Linux")
    assert env.distribution == "debian"
    assert env.service_manager == "systemd"
    assert env.container is True


def test_unknown_does_not_mean_host(tmp_path):
    env = detect_environment(tmp_path, "Linux")
    assert env.distribution == "unknown"
    assert env.container is None
    assert detect_environment(tmp_path, "Darwin").system == "Darwin"


def test_cgroup_and_openrc(tmp_path):
    (tmp_path / "proc/1").mkdir(parents=True)
    (tmp_path / "proc/1/cgroup").write_text("0::/kubepods/fixture")
    (tmp_path / "run/openrc").mkdir(parents=True)
    env = detect_environment(tmp_path, "Linux")
    assert env.container is True
    assert env.service_manager == "openrc"

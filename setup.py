"""Include the canonical buildless panel in installed wheels."""

from pathlib import Path
from shutil import copy2

from setuptools import setup
from setuptools.command.build_py import build_py


class PanelBuild(build_py):
    """Bundle only the explicit static asset allowlist."""

    def run(self):
        super().run()
        target = Path(self.build_lib) / "hardcheck" / "web"
        target.mkdir(parents=True, exist_ok=True)
        for name in ("index.html", "app.js", "local.js", "style.css", "demo.json"):
            copy2(Path(__file__).parent / "web" / "dist" / name, target / name)


setup(cmdclass={"build_py": PanelBuild})

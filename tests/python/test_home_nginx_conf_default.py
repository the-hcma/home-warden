"""The default nginx.conf path follows thehcma/home's directory name (nginx/conf) and still reads the former one (nginx/server)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ["scripts/setup-service", "scripts/bootstrap", "scripts/on-deploy", "scripts/nginx-test-and-reload", "scripts/cutover-assess"]


def test_each_script_prefers_the_new_directory_and_falls_back_to_the_old_one() -> None:
    for name in SCRIPTS:
        text = (ROOT / name).read_text()
        assert "home/nginx/conf/nginx.conf" in text, name
        assert "home/nginx/server/nginx.conf" in text, name
        assert text.index("home/nginx/conf/nginx.conf") < text.index("home/nginx/server/nginx.conf"), name


def test_the_documentation_names_the_new_directory_only() -> None:
    for name in ["README.md", "docs/host-prerequisites.md", "docs/architecture-socket-activation.md"]:
        assert "nginx/server" not in (ROOT / name).read_text(), name

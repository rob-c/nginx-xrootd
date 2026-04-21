import os
import socket
import subprocess
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

THIS_DIR = Path(__file__).resolve().parent
MANAGE_SCRIPT = str(THIS_DIR / "manage_test_servers.sh")
CONFIGS_DIR = THIS_DIR / "configs"


def _read_config_text(conf_file: str) -> str:
    path = Path(conf_file)
    if not path.is_absolute():
        path = CONFIGS_DIR / path
    return path.read_text(encoding="utf-8")


def _render_config(conf_text: str, placeholders: dict[str, str]) -> str:
    text = conf_text
    for k, v in placeholders.items():
        text = text.replace(f"{{{k}}}", str(v))
    return text


def render_config_file(conf_file: str, template_kwargs: dict | None = None) -> str:
    if template_kwargs is None:
        template_kwargs = {}
    return _render_config(_read_config_text(conf_file), template_kwargs)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except Exception:
            time.sleep(0.1)
    return False


def start_nginx_instance(
    port: int | None = None,
    nginx_bin: str | None = None,
    conf_file: str | None = None,
    conf_text: str | None = None,
    template_kwargs: dict | None = None,
) -> dict:
    """Start an nginx instance managed via `tests/manage_test_servers.sh`.

    Provide *either* ``conf_file`` (path to a config file in ``tests/configs/``
    with ``{KEY}`` placeholders) or ``conf_text`` (inline config string).
    Placeholders are resolved via safe string replacement — nginx ``{ }``
    braces are not affected.

    Returns a dictionary with keys: `prefix`, `conf_path`, `port`, `url_base`,
    `data_dir`, and `stop()` callable.
    """
    if template_kwargs is None:
        template_kwargs = {}

    if port is None:
        port = _free_port()

    # External override: if TEST_NGINX_URL or EXTERNAL_NGINX_URL is set,
    # treat that as an existing server and return a synthetic info dict
    # (no local nginx will be started). This lets tests target an external
    # nginx+plugin instance provided by CI or operator.
    ext_url = os.environ.get("TEST_NGINX_URL") or os.environ.get("EXTERNAL_NGINX_URL")
    if ext_url:
        parsed = urlparse(ext_url)
        if not parsed.scheme:
            # assume HTTPS if scheme omitted
            ext_url = f"https://{ext_url}"
            parsed = urlparse(ext_url)
        port = parsed.port or (443 if parsed.scheme in ("https", "davs") else 80)
        prefix = Path("/tmp/xrd-test/external") / f"nginx-{uuid.uuid4().hex}"
        data_dir = Path(template_kwargs.get("DATA_DIR", str(prefix / "data")))

        for subdir in ("conf", "logs", "tmp"):
            (prefix / subdir).mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)

        def stop():
            # no-op for external server
            return None

        return {
            "prefix": str(prefix),
            "conf_path": None,
            "port": port,
            "url_base": ext_url,
            "data_dir": str(data_dir),
            "stop": stop,
        }

    prefix = Path("/tmp/xrd-test/instances") / f"nginx-{uuid.uuid4().hex}"
    conf_dir = prefix / "conf"
    log_dir = prefix / "logs"
    tmp_dir = prefix / "tmp"
    data_dir = Path(template_kwargs.get("DATA_DIR", str(prefix / "data")))

    for d in (conf_dir, log_dir, tmp_dir, data_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Build placeholder dict: runtime defaults + caller overrides
    placeholders = {
        "LOG_DIR": str(log_dir),
        "TMP_DIR": str(tmp_dir),
        "PORT": str(port),
        "DATA_DIR": str(data_dir),
        "SERVER_CERT": "/tmp/xrd-test/pki/server/hostcert.pem",
        "SERVER_KEY": "/tmp/xrd-test/pki/server/hostkey.pem",
        "CA_CERT": "/tmp/xrd-test/pki/ca/ca.pem",
    }
    for k, v in template_kwargs.items():
        placeholders[k] = str(v)

    # Load config text from file or use inline string
    if conf_text is None and conf_file is not None:
        conf_text = _read_config_text(conf_file)
    elif conf_text is None:
        raise ValueError("Either conf_file or conf_text must be provided")

    # Replace {KEY} placeholders (safe — nginx braces are not affected)
    text = _render_config(conf_text, placeholders)

    conf_path = conf_dir / "nginx.conf"
    conf_path.write_text(text, encoding="utf-8")

    env = os.environ.copy()
    env["NGINX_PREFIX"] = str(prefix)
    env["NGINX_CONF_REL"] = "conf/nginx.conf"
    env["NGINX_PORT"] = str(port)
    if nginx_bin:
        env["NGINX_BIN"] = nginx_bin
    env["SKIP_XRDFS_CHECK"] = "1"

    subprocess.run([MANAGE_SCRIPT, "start", "nginx"], env=env, check=True)

    if not _wait_for_port("127.0.0.1", port, timeout=15):
        # try stop for cleanup
        subprocess.run([MANAGE_SCRIPT, "stop", "nginx"], env=env, check=False)
        raise RuntimeError(f"nginx did not start on port {port}")

    def stop():
        subprocess.run([MANAGE_SCRIPT, "stop", "nginx"], env=env, check=False)

    return {
        "prefix": str(prefix),
        "conf_path": str(conf_path),
        "port": port,
        "url_base": f"https://127.0.0.1:{port}",
        "data_dir": str(data_dir),
        "stop": stop,
    }


def start_xrootd_instance(
    port: int | None = None,
    ref_bin: str | None = None,
    ref_dir: str | None = None,
    data_dir: str | None = None,
    conf_file: str = "xrootd_ref.conf",
    template_kwargs: dict | None = None,
) -> dict:
    """Start an xrootd reference instance managed via `tests/manage_test_servers.sh`.

    Returns dict with `ref_dir`, `port`, `url`, and `stop()`.
    """
    if template_kwargs is None:
        template_kwargs = {}

    if port is None:
        port = _free_port()

    if ref_dir is None:
        ref_dir = str(Path("/tmp/xrd-test/instances") / f"xrootd-{uuid.uuid4().hex}")

    if data_dir is None:
        data_dir = "/tmp/xrd-test/data"

    # External override: if TEST_REF_URL or EXTERNAL_REF_URL is set, treat
    # that as an existing xrootd reference server and return info without
    # starting a local xrootd. Useful for running the test suite against a
    # preconfigured official xrootd instance.
    ext_ref_url = os.environ.get("TEST_REF_URL") or os.environ.get("EXTERNAL_REF_URL")
    if ext_ref_url:
        parsed = urlparse(ext_ref_url)
        if not parsed.scheme:
            ext_ref_url = f"root://{ext_ref_url}"
            parsed = urlparse(ext_ref_url)
        port = parsed.port or port

        def stop():
            return None

        return {"ref_dir": ref_dir, "port": port, "url": ext_ref_url, "stop": stop}

    ref_root = Path(ref_dir)
    admin_dir = ref_root / "admin-conf"
    run_dir = ref_root / "run-conf"
    admin_dir.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)

    placeholders = {
        "PORT": str(port),
        "DATA_DIR": str(data_dir),
        "ADMIN_DIR": str(admin_dir),
        "RUN_DIR": str(run_dir),
    }
    for k, v in template_kwargs.items():
        placeholders[k] = str(v)

    cfg_path = ref_root / "conformance.cfg"
    cfg_text = _read_config_text(conf_file)
    cfg_path.write_text(_render_config(cfg_text, placeholders), encoding="utf-8")

    env = os.environ.copy()
    env["REF_DIR"] = ref_dir
    env["REF_CFG"] = str(cfg_path)
    env["REF_CFG_PREGENERATED"] = "1"
    env["REF_PORT"] = str(port)
    env["DATA_DIR"] = data_dir
    if ref_bin:
        env["REF_BIN"] = ref_bin

    subprocess.run([MANAGE_SCRIPT, "start", "ref"], env=env, check=True)

    if not _wait_for_port("127.0.0.1", port, timeout=15):
        subprocess.run([MANAGE_SCRIPT, "stop", "ref"], env=env, check=False)
        raise RuntimeError(f"xrootd did not start on port {port}")

    def stop():
        subprocess.run([MANAGE_SCRIPT, "stop", "ref"], env=env, check=False)

    return {"ref_dir": ref_dir, "port": port, "url": f"root://localhost:{port}", "stop": stop}

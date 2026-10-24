"""Known lab handles for the analyst demo: copies of the demo target running on this guest's loopback.

A handle is the app's own address, `127.0.0.1:<port>`, plus (when the copy is held by a container)
the container that holds it. A request is one exec of the fixed client at that URL -- inside the
container when there is one, else right here -- so the client and the destination use the same
string and nothing has to be translated.

A handle is accepted as `verify`d only when ALL of these hold, checked before any exec:
  - the port answers a loopback connect (that is the whole reachability question);
  - with the copy held by a container: it runs, its name starts with `tirith-analyst-lab`, it is on
    the internal lab network, it publishes no host port, it carries `tirith.lab=1`,
    `tirith.analystlab.target=analyst-lab` and `tirith.analystlab.variant=<vulnerable|patched>`, its
    image tag starts with `tirith-lab/analyst-lab-`, and `/health` answers with the expected app.
  - a native copy (no docker on the box) carries the same identity in its boot environment
    (`TIRITH_ANALYST_LAB_VARIANT`), and `/health` is the binding check: the port answering is only
    half of it, the app that answers must be the demo target and the expected variant. Otherwise any
    unrelated local service on that port would pass for a lab.

A handle NAME (the only thing the model supplies) maps to exactly one of {vulnerable, patched}; the
port and container are resolved here from the boot record and Docker labels, never from model output.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import config
from ..remediation import lab as lab_mod
from ..remediation.sh import docker
from ..scanners.docker import docker_available
from ..store import get_store
from ..scope import enforce
from . import copies

# The target tree is deployment data, not backend code: it lives outside the backend image (deploy/README:
# "targets/ is not synced"). Override with TIRITH_ANALYST_LAB_DIR; the default works for a local checkout.
DEMO_TARGET_DIR = Path(os.environ.get(
    "TIRITH_ANALYST_LAB_DIR", str(config.BACKEND_DIR.parent / "targets" / "analyst-lab"))).resolve()
NAME_PREFIX = "tirith-analyst-lab"
IMAGE_PREFIX = "tirith-lab/analyst-lab-"
LABEL_TARGET = "tirith.analystlab.target"
LABEL_TARGET_VALUE = "analyst-lab"
LABEL_VARIANT = "tirith.analystlab.variant"
LABEL_PORT = "tirith.analystlab.port"
ENV_VARIANT = "TIRITH_ANALYST_LAB_VARIANT"
VARIANTS = ("vulnerable", "patched")
HANDLES = {"docker-lab": "vulnerable", "docker-lab-patched": "patched"}
APP_PORT = 8080  # the port the target binds under `--network host` / natively
HEALTH_PATH = "/health"
KV_PORT = "analystlab:port:%s"  # variant -> loopback port of the owned copy


class HandleError(RuntimeError):
    """Unknown, unavailable or unsafe lab handle. Raised before any exec."""


@dataclass
class LabRef:
    handle: str
    variant: str
    port: int = APP_PORT
    host: str = "127.0.0.1"
    container: str = ""  # the copy's own container; blank = native process on this guest
    image: str = ""
    network: str = ""
    asset_id: str | None = None
    verified_at: str = ""
    checks: list[str] = field(default_factory=list)

    @property
    def live(self) -> bool:
        return self.variant == "live"

    @property
    def app_url(self) -> str:
        """Destination. Loopback is loopback for client and app alike; this never gets rewritten."""
        return f"http://{self.host or '127.0.0.1'}:{self.port}"

    @property
    def local(self) -> bool:
        """No container holds the copy: the client runs right here."""
        return not self.container

    def to_dict(self) -> dict:
        return {"handle": self.handle, "variant": self.variant, "port": self.port, "container": self.container,
                "image": self.image, "network": self.network, "asset_id": self.asset_id, "app_url": self.app_url,
                "client": "docker exec" if self.container else "local process",
                "verified_at": self.verified_at, "checks": self.checks}


def known_handles() -> list[str]:
    return list(HANDLES)


def variant_of(name: str) -> str:
    name = (name or "").strip().lower()
    if name not in HANDLES:
        raise HandleError(f"unknown lab handle {name!r}; known: {', '.join(HANDLES)}")
    return HANDLES[name]


# ----------------------------------------------------------------------------- container inspection
def _inspect(container: str) -> dict:
    r = docker(["inspect", container], timeout=20)
    if r.rc != 0:
        raise HandleError(f"container {container!r} not found")
    try:
        data = json.loads(r.out)
    except ValueError as e:
        raise HandleError(f"container {container!r}: unreadable inspect output") from e
    if not isinstance(data, list) or not data:
        raise HandleError(f"container {container!r} not found")
    return data[0]


def _labels(container: str) -> dict[str, str]:
    r = docker(["inspect", container, "--format", "{{json .Config.Labels}}"], timeout=15)
    try:
        return json.loads(r.out) if r.ok and r.out.strip() else {}
    except ValueError:
        return {}


def labels_for_variant(variant: str) -> list[str]:
    r = docker(["ps", "-q", "--filter", f"label={LABEL_TARGET}={LABEL_TARGET_VALUE}",
                "--filter", "label=tirith.lab=1", "--filter", f"label={LABEL_VARIANT}={variant}"], timeout=20)
    return [c for c in (r.out or "").split() if c] if r.ok else []


def network_internal(network: str) -> bool:
    r = docker(["network", "inspect", network, "--format", "{{.Internal}}"], timeout=15)
    return r.ok and r.out.strip() == "true"


def _port_of(container: str, labels: dict[str, str] | None = None) -> int:
    """The copy's host-network port: its label, else the image's one EXPOSE."""
    raw = (labels or _labels(container)).get(LABEL_PORT) or ""
    if raw.isdigit():
        return int(raw)
    cfg = (_inspect(container).get("Config") or {}).get("Image") or ""
    return _image_port(cfg)[1] if cfg else APP_PORT


def _health(ref: LabRef, timeout: int = 4) -> dict | None:
    """`/health` of the copy, read with the same local client everything else uses (inside the copy's
    container when there is one). None when it does not answer or answers nonsense."""
    code = ("import json,sys,urllib.request\n"
            "try:\n"
            f"    r=urllib.request.urlopen({(ref.app_url + HEALTH_PATH)!r},timeout={timeout})\n"
            "    d=json.loads(r.read(400).decode('utf-8','replace'))\n"
            "    print(json.dumps(d) if isinstance(d,dict) else '{}')\n"
            "except Exception as e:\n"
            "    print(json.dumps({'error':type(e).__name__}))\n")
    if ref.container:
        r = docker(["exec", ref.container, "python", "-c", code], timeout=timeout + 10)
    else:
        from ..scanners.docker import run_local

        r = run_local(["python", "-c", code], timeout=timeout + 10)
    if not r.ok:
        return None
    try:
        return json.loads(r.out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None


def _check_health(ref: LabRef, tries: int = 3) -> str:
    health = None
    for _ in range(max(1, tries)):
        health = _health(ref)
        if health and health.get("app") == "analyst-lab":
            break
        time.sleep(0.3)
    if health is None:
        raise HandleError(f"{ref.app_url} does not answer {HEALTH_PATH}")
    if health.get("error"):
        raise HandleError(f"{ref.app_url} answered {HEALTH_PATH} with {health['error']}")
    if health.get("app") != "analyst-lab":
        raise HandleError(f"{ref.app_url} is not the demo target (health said {health.get('app')!r})")
    if health.get("variant") != ref.variant:
        raise HandleError(f"{ref.app_url} is variant {health.get('variant')!r}, expected {ref.variant!r}")
    return "health"


def verify(container: str, variant: str) -> LabRef:
    """All handle preconditions for a copy. Raises HandleError with the first failed check.

    `container` is the copy's container, or "" for a native copy (port from the boot record)."""
    if variant == "live":  # any service the owner runs; its reachability is checked by `live`
        d = _inspect(container)
        name = (d.get("Name") or "").lstrip("/")
        if not (d.get("State") or {}).get("Running"):
            raise HandleError(f"live container {name!r} is not running")
        return LabRef(handle="", variant="live", container=name, port=APP_PORT, image=d.get("Image") or "")
    if variant not in VARIANTS:
        raise HandleError(f"unknown variant {variant!r}")
    ref = LabRef(handle=HANDLES_INV[variant], variant=variant)
    if not container:
        port = _kv_port(variant)
        if not port:
            raise HandleError(f"no {variant} demo lab is running as a local process")
        ref.port, ref.network = port, "host"
        ref.checks = ["recorded-port"]
        if not copies.waits(ref.host, ref.port, 0.5):
            raise HandleError(f"{ref.app_url} does not answer (local {variant} copy)")
        ref.checks += ["port-answers", _check_health(ref)]
        return ref
    d = _inspect(container)
    name = (d.get("Name") or "").lstrip("/")
    if not name.startswith(NAME_PREFIX):
        raise HandleError(f"container {name!r} is not a demo lab container (name must start with {NAME_PREFIX})")
    if not (d.get("State") or {}).get("Running"):
        raise HandleError(f"container {name!r} is not running")
    if (d.get("HostConfig") or {}).get("NetworkMode") != "host":
        raise HandleError(f"container {name!r} is not on host networking")
    cfg = d.get("Config") or {}
    labels = cfg.get("Labels") or {}
    if labels.get("tirith.lab") != "1":
        raise HandleError(f"container {name!r} lacks the tirith.lab=1 label")
    if labels.get(LABEL_TARGET) != LABEL_TARGET_VALUE:
        raise HandleError(f"container {name!r} is not labelled {LABEL_TARGET}={LABEL_TARGET_VALUE}")
    if labels.get(LABEL_VARIANT) != variant:
        raise HandleError(f"container {name!r} is variant {labels.get(LABEL_VARIANT)!r}, expected {variant!r}")
    nets = list(((d.get("NetworkSettings") or {}).get("Networks") or {}).keys())
    expected = lab_mod.lab_network()
    if nets != [expected]:
        raise HandleError(f"container {name!r} is on networks {nets}, expected only {expected!r}")
    if not network_internal(expected):
        raise HandleError(f"network {expected!r} is not internal; refusing to use it as a lab")
    image = cfg.get("Image") or ""
    if not image.startswith(IMAGE_PREFIX):
        raise HandleError(f"container {name!r} runs image {image!r}, not a Tirith analyst-lab build")
    ref = LabRef(handle=ref.handle, variant=variant, container=name, image=image, network=expected,
                 port=_port_of(name, labels), asset_id=labels.get("tirith.analystlab.asset_id"),
                 checks=["name", "running", "host-network", "labels", "internal-network", "tirith-image"])
    ref.checks += ["port-answers", _check_health(ref)]
    return ref


# ----------------------------------------------------------------------------- native copy record
def _kv_port(variant: str) -> int:
    """The recorded loopback port of a native copy (0 when none was ever started)."""
    raw = get_store().get_kv(KV_PORT % variant) or ""
    return int(raw) if raw.isdigit() else 0


def _image_exists(tag: str) -> bool:
    return docker(["image", "inspect", tag, "--format", "{{.Id}}"], timeout=20).ok


def _image_port(tag: str) -> tuple[str, int]:
    """The port the image actually serves on (Dockerfile EXPOSE), refusing anything but one 8080."""
    import json as _json

    r = docker(["image", "inspect", tag, "--format", "{{json .Config.ExposedPorts}}"], timeout=20)
    try:
        ports = sorted(int(p.split("/")[0]) for p in (_json.loads(r.out) or {}))
    except (ValueError, TypeError):
        ports = []
    if ports != [APP_PORT]:
        raise HandleError(f"demo image {tag} exposes {ports or 'no ports'}, expected exactly {APP_PORT}")
    return "127.0.0.1", APP_PORT


def free_port() -> int:
    """A loopback port nobody listens on. The copy binds APP_PORT inside its own namespace when a
    container holds it, so a free host port is exactly what is needed for the native fallback."""
    return copies.free_port()


# ----------------------------------------------------------------------------- boot
def boot(variant: str, *, asset_id: str | None = None, wait: int = 60) -> LabRef:
    """Build (no network) and start the demo target variant on the guest loopback.

    Shape, podman and docker either way:
      - with a container runtime: `docker run -d --network host` on the internal lab network, so the
        app binds the guest loopback itself; the URL is the same string the client uses.
      - without one: a native process with a free loopback port (`PORT`), in its own session, owned by
        this process and killed at teardown. The source directory is the process `cwd`.
    """
    if variant not in VARIANTS:
        raise HandleError(f"unknown variant {variant!r}")
    src = DEMO_TARGET_DIR / variant
    enforce("analystlab.boot", "local_path", str(src))
    if not docker_available():
        return boot_native(variant, asset_id=asset_id, wait=wait)
    if not (src / "Dockerfile").is_file():
        raise HandleError(f"demo target {variant} has no Dockerfile at {src} "
                          f"(TIRITH_ANALYST_LAB_DIR={DEMO_TARGET_DIR})")
    network, _ = lab_mod.ensure_network()  # creates it --internal or refuses a non-internal network
    # Both variants are equally untrusted (deliberately vulnerable), so both build with --network none:
    # the image is stdlib-only, and any dependency install would need a network the build must not get.
    try:
        tag, _br = lab_mod.build(src, f"analyst-lab-{variant}", network=False)
    except lab_mod.LabUnavailable as e:
        if not _image_exists(lab_mod.image_tag(src, f"analyst-lab-{variant}")):
            raise HandleError(
                f"{variant} demo image needs a network-less build but the base image is missing locally "
                f"({e}). Pre-pull python:3.12.15-slim-bookworm on the Docker host, or build it once offline.") from e
        tag = lab_mod.image_tag(src, f"analyst-lab-{variant}")
    _image_port(tag)  # refuses an image that does not expose exactly APP_PORT
    name = f"{NAME_PREFIX}-{variant}-{secrets.token_hex(3)}"
    labels = {"tirith.lab": "1", LABEL_TARGET: LABEL_TARGET_VALUE, LABEL_VARIANT: variant,
              LABEL_PORT: str(APP_PORT), "tirith.analystlab.asset_id": asset_id or ""}
    r = copies.run_container(tag, name=name, ports=[APP_PORT], labels=labels, env={"TIRITH_LAB": "1"})
    if not r.ok:
        raise HandleError(f"could not start the {variant} demo target: {r.tail(300)}")
    try:
        ref = verify(name, variant)
    except HandleError:
        copies.remove_container(name)
        raise
    if asset_id:
        ref.asset_id = asset_id
    try:
        if not copies.wait_http("127.0.0.1", ref.port, wait):
            raise HandleError(f"{ref.app_url} did not answer within {wait}s")
        _check_health(ref)
    except HandleError:
        copies.remove_container(name)
        raise
    from ..models import now_iso

    ref.verified_at = now_iso()
    return ref


def boot_native(variant: str, *, asset_id: str | None = None, wait: int = 60) -> LabRef:
    """Start the demo target as a plain local process (no container runtime on the box)."""
    if variant not in VARIANTS:
        raise HandleError(f"unknown variant {variant!r}")
    src = DEMO_TARGET_DIR / variant
    enforce("analystlab.boot", "local_path", str(src))
    if not (src / "app.py").is_file():
        raise HandleError(f"demo target {variant} has no app.py at {src} (TIRITH_ANALYST_LAB_DIR={DEMO_TARGET_DIR})")
    port = free_port()
    env = {ENV_VARIANT: variant, **({'TIRITH_ANALYSTLAB_ASSET_ID': asset_id} if asset_id else {}),
           "PORT": str(port), "PYTHONUNBUFFERED": "1"}
    app = copies.NativeApp([os.environ.get("TIRITH_LAB_PYTHON") or "python3", "app.py"], src, {**os.environ, **env}).start()
    _spawned[variant] = app
    try:
        ref = LabRef(handle=HANDLES_INV[variant], variant=variant, port=port, asset_id=asset_id)
        if not copies.wait_http("127.0.0.1", port, wait):
            raise HandleError(f"{ref.app_url} did not answer within {wait}s:\n{app.logs(800)}")
        ref.checks = ["port-answers", _check_health(ref)]
    except HandleError:
        app.stop()
        _spawned.pop(variant, None)
        raise
    from ..models import now_iso

    ref.verified_at = now_iso()
    return ref


HANDLES_INV = {v: h for h, v in HANDLES.items()}
_spawned: dict[str, copies.NativeApp] = {}


def _wait_ready(ref: LabRef, timeout: int = 60) -> dict:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        health = _health(ref)
        if health and health.get("app") == "analyst-lab" and health.get("variant") == ref.variant:
            return health
        last = json.dumps(health) if health else "no answer"
        time.sleep(2)
    raise HandleError(f"{ref.app_url}{HEALTH_PATH} did not answer: {last}")


def resolve(name: str) -> LabRef:
    """Handle name -> copy. The only place a model-supplied name becomes a destination.

    The container proves its own identity (labels, network, image, health); a native copy proves the
    port answers and carries its identity as a constant (`verify` also pins it to the health answer)."""
    variant = variant_of(name)
    ids = labels_for_variant(variant)
    if len(ids) > 1:
        raise HandleError(f"{len(ids)} containers claim variant {variant}; stopping the extras is required")
    if ids:
        return verify(ids[0], variant)
    if _kv_port(variant):
        return verify("", variant)
    raise HandleError(f"no running {variant} demo lab (labelled {LABEL_TARGET}={LABEL_TARGET_VALUE}); "
                      f"start it with POST /api/analystlab/reset or the demo script")


def for_asset(asset_id: str | None, variant: str = "vulnerable") -> LabRef | None:
    """Handle recorded as belonging to an asset (set at boot), re-verified before reuse."""
    if not asset_id:
        return None
    for c in labels_for_variant(variant):
        if _labels(c).get("tirith.analystlab.asset_id") == asset_id:
            return verify(c, variant)
    return None


def handle_for_asset(asset, *, boot_if_missing: bool = False) -> LabRef | None:
    """Only the analyst demo target has lab handles; every other asset returns None (-> refusal)."""
    from .regression import ensure_demo_asset, is_demo_target

    if asset is None or asset.kind != "local_path" or not is_demo_target(Path(asset.ref)):
        return None
    a = ensure_demo_asset()
    ref = for_asset(a.id)
    if ref is None and boot_if_missing:
        ref = boot_or_native("vulnerable", asset_id=a.id)
    return ref


def boot_or_native(variant: str, **kw) -> LabRef:
    """`boot` when a container runtime exists, else the native start (same handle shape)."""
    if copies.available():
        return boot(variant, **kw)
    ref = boot_native(variant, **kw)
    if ref.port:
        get_store().set_kv(KV_PORT % variant, str(ref.port))
        ref.verified_at = ref.verified_at or "native"
    return ref


def asset_handle(asset_id: str | None) -> LabRef | None:
    if not asset_id:
        return None
    return for_asset(asset_id)


def reset_all() -> list[str]:
    """Stop every demo lab copy (both variants). Returns names of what was removed."""
    removed = []
    for variant in VARIANTS:
        for c in labels_for_variant(variant):
            copies.remove_container(c)
            removed.append(c)
        app = _spawned.pop(variant, None)
        if app is not None:
            pid = app.proc.pid if app.proc else "?"
            app.stop()
            removed.append(f"{HANDLES_INV[variant]} (pid {pid})")
        port = _kv_port(variant)
        if port:
            get_store().set_kv(KV_PORT % variant, "")
            removed.append(f"{HANDLES_INV[variant]} (port {port})")
    return removed


def status() -> dict:
    st = get_store()
    out: dict = {"handles": {}, "network": lab_mod.lab_network(),
                 "network_internal": network_internal(lab_mod.lab_network()),
                 "runtime": copies.available() or "none (native processes)"}
    for name, variant in HANDLES.items():
        try:
            out["handles"][name] = resolve(name).to_dict()
        except HandleError as e:
            out["handles"][name] = {"error": str(e)}
    try:
        out["latest_run"] = st.get_kv("analystlab:last_run")
    except Exception:  # noqa: BLE001 - kv table is optional for this view
        out["latest_run"] = None
    return out


__all__ = ["HANDLES", "HandleError", "LabRef", "VARIANTS", "asset_handle", "boot", "boot_native", "for_asset",
           "handle_for_asset", "known_handles", "reset_all", "resolve", "status", "variant_of", "verify"]


def known_handles_for(url: str) -> list[LabRef]:
    """Running verified lab copies for an asset URL (base or deeper), patched variant last.

    The analyst uses this to turn the URL a finding names into the copy it must talk to: the copy is
    still resolved from the boot record, never from the string the model wrote."""
    want = (url or "").rstrip("/")
    out: list[LabRef] = []
    for name in HANDLES:
        try:
            ref = resolve(name)
        except HandleError:
            continue
        asset_id = ref.asset_id
        if not asset_id or not want:
            continue
        from ..store import get_store

        asset = get_store().get_asset(asset_id)
        if asset is None:
            continue
        base = (asset.ref or "").rstrip("/")
        if want == base or want.startswith(base + "/"):
            out.append(ref)
    return out
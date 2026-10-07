"""U2-B privileged execution. Root-managed inputs; no arbitrary CLI targets."""
import datetime as dt
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time
import urllib.request
import uuid

from tiraz_updater import (Commands, CheckError, GIT_EXECUTABLE, DOCKER_EXECUTABLE,
                           SHA, MAX_BYTES, atomic_write, initial_status, identity,
                           latest_release, previous_metadata, semver, stamp, validate_config)

SERVICES = ("app", "web", "queue", "scheduler", "backup_queue")
WORKERS = ("queue", "scheduler", "backup_queue")
ACTIVITIES = {"backup", "fetch_release", "prepare_release", "build_app", "build_web",
              "migration", "deploy", "health_check", "finalize"}
ACTIVITY_COMMANDS = {"backup": "backup", "fetch": "fetch_release", "archive": "prepare_release",
                     "build_app": "build_app", "build_web": "build_web", "migration": "migration",
                     "deploy": "deploy"}
FAILURES = {
    "preflight": ("preflight_failed", "تعذر إتمام التحقق الآمن قبل التحديث."),
    "backup": ("backup_failed", "تعذر إنشاء نسخة احتياطية موثقة."),
    "prepare_release": ("release_fetch_failed", "تعذر تجهيز الإصدار أو التحقق من توافقه؛ راجع مسؤول الخادم."),
    "build": ("build_failed", "تعذر بناء الإصدار."),
    "build_app": ("build_app_failed", "تعذر بناء تطبيق الإصدار."),
    "build_web": ("build_web_failed", "تعذر بناء واجهة الإصدار."),
    "migration": ("migration_failed", "تعذر إتمام تحديث قاعدة البيانات."),
    "deploy": ("deploy_failed", "تعذر تشغيل الإصدار الجديد."),
    "health_check": ("health_check_failed", "لم يجتز الإصدار فحص سلامة النظام."),
    "finalize": ("finalize_failed", "تعذر إتمام التحقق النهائي من التحديث."),
}


class ComposeCompatibilityError(CheckError):
    pass


def require_compose_compatibility(approved, candidate):
    """Compare privately; never include values or differing keys in diagnostics."""
    def normalize(model):
        if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
            raise ComposeCompatibilityError("Target Compose requires operator review.")
        if not set(SERVICES) <= set(model["services"]) or "database" not in model["services"]:
            raise ComposeCompatibilityError("Target Compose requires operator review.")
        result = json.loads(json.dumps(model))
        for name in SERVICES:
            service = result["services"][name]
            if not isinstance(service, dict):
                raise ComposeCompatibilityError("Target Compose requires operator review.")
            service.pop("build", None)
            environment = service.get("environment", {})
            if not isinstance(environment, dict):
                raise ComposeCompatibilityError("Target Compose requires operator review.")
            for key in ("APP_VERSION", "APP_REVISION"):
                environment.pop(key, None)
            if not environment:
                service.pop("environment", None)
        return result
    if normalize(approved) != normalize(candidate):
        raise ComposeCompatibilityError("Target Compose requires operator review.")


class HostLock:
    def __init__(self, path):
        self.path = path
        self.fd = None

    def __enter__(self):
        try:
            import fcntl
            self.fd = os.open(self.path, os.O_RDWR | os.O_NOFOLLOW)
            if not stat.S_ISREG(os.fstat(self.fd).st_mode):
                raise OSError()
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self
        except (ImportError, AttributeError, OSError):
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            raise CheckError("Update lock is unavailable or already held.") from None

    def __exit__(self, *args):
        os.close(self.fd)


def read_json(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValueError()
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError()
        return json.loads(raw)
    except (OSError, ValueError, TypeError):
        raise CheckError("Invalid local request or operation file.") from None


def validate_request(data, channel, now=None):
    keys = {"schema_version", "request_id", "action", "requested_at", "channel",
            "current", "target", "requested_by"}
    if not isinstance(data, dict) or set(data) != keys or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise CheckError("Invalid update request schema.")
    try:
        uid = uuid.UUID(data["request_id"])
        date = dt.datetime.fromisoformat(data["requested_at"].replace("Z", "+00:00"))
        age = ((now or dt.datetime.now(dt.timezone.utc)) - date).total_seconds()
        if uid.version != 4 or str(uid) != data["request_id"] or date.utcoffset() != dt.timedelta(0) or not 0 <= age <= 300:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise CheckError("Invalid or expired update request identity.") from None
    if data["action"] != "install_release" or data["channel"] != channel or channel not in ("stable", "beta"):
        raise CheckError("Invalid update request action or channel.")
    for key in ("current", "target"):
        value = data[key]
        if (not isinstance(value, dict) or set(value) != {"version", "commit"}
                or not semver(value["version"]) or not isinstance(value["commit"], str)
                or not SHA.fullmatch(value["commit"])):
            raise CheckError("Invalid release identity in request.")
    if (not isinstance(data["requested_by"], dict) or set(data["requested_by"]) != {"user_id"}
            or type(data["requested_by"]["user_id"]) is not int or data["requested_by"]["user_id"] <= 0):
        raise CheckError("Invalid requester identifier.")
    if data["current"]["commit"] == data["target"]["commit"] or semver(data["target"]["version"]) <= semver(data["current"]["version"]):
        raise CheckError("Requested release is not newer.")
    return data


def safe_extract(archive, destination):
    try:
        with tarfile.open(archive, "r:") as source:
            members = source.getmembers()
            if len(members) > 100000 or sum(m.size for m in members) > 512 * 1024 * 1024:
                raise ValueError()
            for member in members:
                path = PurePosixPath(member.name)
                if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                        or any(ord(c) < 32 for c in member.name)
                        or not (member.isfile() or member.isdir())):
                    raise ValueError()
                target = Path(destination).joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with source.extractfile(member) as read, open(target, "xb") as write:
                        import shutil
                        shutil.copyfileobj(read, write)
                    os.chmod(target, 0o644 | (member.mode & 0o111))

        # The updater service runs under UMask=0077. Normalize extracted
        # source directories so Docker COPY does not bake unreadable 0700
        # directories into runtime images used by www-data.
        for root, directories, _ in os.walk(destination):
            os.chmod(root, 0o755)
            for directory in directories:
                os.chmod(Path(root) / directory, 0o755)

    except (OSError, ValueError, tarfile.TarError):
        raise CheckError("Release archive failed safe extraction.") from None


def validate_release_contract(path, migration_delta):
    """Require explicit database migration intent for every release."""
    try:
        data = read_json(path)
    except CheckError:
        raise CheckError("Invalid release contract.") from None

    if (not isinstance(data, dict)
            or set(data) != {"schema_version", "database"}
            or type(data["schema_version"]) is not int
            or data["schema_version"] != 1
            or not isinstance(data["database"], dict)
            or set(data["database"]) != {"migration_policy"}
            or data["database"]["migration_policy"] != "run_if_changed"
            or not isinstance(migration_delta, str)):
        raise CheckError("Invalid release contract.")

    return {
        "contract": data,
        "migrations_required": any(
            line.strip() for line in migration_delta.splitlines()
        ),
    }


class ApplyCommands(Commands):
    def __init__(self, config, request, workspace):
        super().__init__(config)
        self.request, self.workspace = request, Path(workspace)

    def previous_image(self, container_id):
        if not isinstance(container_id, str) or not re.fullmatch(r"[a-f0-9]{12,64}", container_id):
            raise CheckError("Invalid previous container identity.")
        return self._execute([DOCKER_EXECUTABLE, "inspect", "--format", "{{.Image}}", container_id], "previous_image", 30)

    def run(self, operation):
        if operation in ("head", "dirty", "remote", "tags", "identity"):
            return super().run(operation)
        target = self.request["target"]
        commit, tag = target["commit"], target["version"]
        git = [GIT_EXECUTABLE, "-c", "core.fsmonitor=false", "-c", "credential.helper=",
               "-c", "core.askPass=", "-c", "core.hooksPath=/dev/null",
               "-c", "protocol.ext.allow=never", "-C", self.config["repository_path"]]
        docker = [DOCKER_EXECUTABLE]
        compose = docker + ["compose", "--project-name", self.config["compose_project"],
                            "-f", str(self.workspace / "target-compose.json")]
        workers = list(WORKERS)
        images = [f"tiraz-app:{commit}", f"tiraz-web:{commit}"]
        refs = "refs/tiraz-updater/" + self.request["request_id"]
        approved_compose = docker + ["compose", "--project-name", self.config["compose_project"],
                                     "--project-directory", self.config["repository_path"]]
        commands = {
            "snapshot": approved_compose + ["-f", str(Path(self.config["repository_path"]) / "compose.yaml"), "config", "--format", "json"],
            "topology_snapshot": approved_compose + ["-f", str(Path(self.config["repository_path"]) / "compose.yaml"), "config", "--no-env-resolution", "--format", "json"],
            "release_snapshot": approved_compose + ["-f", str(self.workspace / "source/compose.yaml"), "config", "--format", "json"],
            "release_topology": approved_compose + ["-f", str(self.workspace / "source/compose.yaml"), "config", "--no-env-resolution", "--format", "json"],
            "containers": docker + ["compose", "--project-name", self.config["compose_project"],
                                     "-f", str(Path(self.config["repository_path"]) / "compose.yaml"), "ps", "--format", "json"],
            "backup": docker + ["exec", self.config["docker_app_container"], "php", "artisan", "tiraz:update-backup", "--no-interaction", "--no-ansi"],
            "fetch": git + ["fetch", "--no-tags", self.config["remote"], f"refs/tags/{tag}:{refs}"],
            "resolve": git + ["rev-parse", refs + "^{commit}"],
            "ancestor": git + ["merge-base", "--is-ancestor", "HEAD", commit],
            "archive": git + ["archive", "--format=tar", commit],
            "migration_delta": git + ["diff", "--name-only", "HEAD", commit, "--", "database/migrations"],
            "build_app": docker + ["build", "--target", "app", "--build-arg", "APP_VERSION=" + tag,
                                    "--build-arg", "APP_REVISION=" + commit, "-t", images[0], str(self.workspace / "source")],
            "build_web": docker + ["build", "--target", "web", "--build-arg", "APP_VERSION=" + tag,
                                    "--build-arg", "APP_REVISION=" + commit, "-t", images[1], str(self.workspace / "source")],
            "promote_app": docker + ["image", "tag", images[0], "decor-office-app:local"],
            "promote_web": docker + ["image", "tag", images[1], "decor-office-web:local"],
            "forward": git + ["merge", "--ff-only", "--no-edit", commit],
            "maintenance": docker + ["exec", self.config["docker_app_container"], "php", "artisan", "down", "--retry=60"],
            "stop_workers": compose + ["stop", "--timeout", "120"] + workers,
            "migration": compose + ["run", "--rm", "--no-deps", "--pull", "never", "app", "php", "artisan", "migrate", "--force", "--no-interaction"],
            "deploy": compose + ["up", "-d", "--no-deps", "--no-build", "--pull", "never", "--force-recreate"] + list(SERVICES),
            "clear": docker + ["exec", self.config["docker_app_container"], "php", "artisan", "optimize:clear"],
            "up": docker + ["exec", self.config["docker_app_container"], "php", "artisan", "up"],
            "boot": docker + ["exec", self.config["docker_app_container"], "php", "artisan", "about", "--only=environment", "--no-ansi"],
            "restore_workers": docker + ["compose", "--project-name", self.config["compose_project"],
                                        "-f", str(self.workspace / "previous-compose.json"), "up", "-d", "--no-deps", "--no-build"] + workers,
        }
        if operation not in commands:
            raise CheckError("Unsupported execution operation.")
        timeout = {"backup": 2100, "build_app": 3600, "build_web": 3600, "migration": 1800,
                   "deploy": 300, "stop_workers": 150, "fetch": 120}.get(operation, self.config["command_timeout_seconds"])
        return self._execute(commands[operation], operation, timeout,
                             self.workspace / "release.tar" if operation == "archive" else None)


def private_json(path, data):
    atomic_write(path, data)
    os.chmod(path, 0o600)


def archive_private_json(source, destination, data):
    """Archive validated JSON across filesystems without losing the protected source."""
    private_json(destination, data)
    try:
        os.unlink(source)
    except OSError:
        raise CheckError("Cannot archive processed update request.") from None


def health(url, heartbeat=None):
    # No proxy environment, external redirect or arbitrary URL permitted.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for _ in range(12):
        if heartbeat:
            heartbeat("health_check")
        try:
            with opener.open(url, timeout=5) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        if heartbeat:
            heartbeat("health_check")
        time.sleep(5)
    raise CheckError("Local application health verification failed.")


def process_request(config, factory=ApplyCommands, health_check=health):
    """Caller MUST hold HostLock. Processing/recovery files are outside writable request mount."""
    config = validate_config(config)
    if "request_path" not in config:
        raise CheckError("Execution configuration is required.")
    status = initial_status(config)
    previous_metadata(config["status_path"], status)
    processing = Path(config["status_path"]).parent / "processing.json"
    if processing.exists() or status.get("operation", {}).get("state") in ("running", "failed"):
        if Path(config["request_path"]).exists():
            try:
                os.rename(config["request_path"], processing.parent / ("rejected-" + str(uuid.uuid4()) + ".json"))
            except OSError:
                raise CheckError("Cannot quarantine blocked request.") from None
        raise CheckError("Previous operation requires manual review.")
    if not Path(config["request_path"]).exists():
        return status
    status.pop("operation", None)
    try:
        os.rename(config["request_path"], processing)
    except OSError:
        raise CheckError("Cannot atomically consume update request.") from None
    mutation = False
    advanced = False
    maintenance = False
    commands = None
    workspace = None
    try:
        request = validate_request(read_json(processing), config["channel"])
        workspace = Path(config["release_temp_root"]) / request["request_id"]
        workspace.mkdir(mode=0o700)  # Existing UUID is a durable replay/crash barrier.
        operation = {"id": request["request_id"], "state": "running", "phase": "preflight",
                     "target_version": request["target"]["version"], "target_commit": request["target"]["commit"],
                     "previous_version": request["current"]["version"], "started_at": stamp(),
                     "updated_at": stamp(), "message": None, "manual_intervention_required": False,
                     "heartbeat_supported": True}
        status["operation"] = operation
        commands = factory(config, request, workspace)
        def heartbeat(command=None):
            activity = ACTIVITY_COMMANDS.get(command, operation["phase"])
            if activity in ACTIVITIES:
                operation["activity"] = activity
            operation["updated_at"] = stamp()
            status["checked_at"] = stamp()
            atomic_write(config["status_path"], status)
        commands.heartbeat = heartbeat
        def phase(name):
            operation.pop("activity", None)
            operation.update(phase=name, updated_at=stamp())
            status.update(checked_at=stamp(), last_error=None)
            atomic_write(config["status_path"], status)
            private_json(workspace / "result.json", status)
        phase("preflight")
        head = commands.run("head")
        if not SHA.fullmatch(head) or commands.run("dirty"):
            raise CheckError("Repository identity or tracked state is unsafe.")
        # Reuse the exact remote validation in the check engine before contacting tags.
        remote = commands.run("remote")
        if not (re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9_./-]+", remote)
                or re.fullmatch(r"[A-Za-z0-9_-]+@[A-Za-z0-9.-]+:[A-Za-z0-9_./-]+", remote)
                or re.fullmatch(r"ssh://[A-Za-z0-9_-]+@[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9_./-]+", remote)):
            raise CheckError("Remote transport is unsafe.")
        current = identity(commands.run("identity"))
        release = latest_release(commands.run("tags"), config["channel"])
        if current != request["current"] or {k: release[k] for k in ("version", "commit")} != request["target"]:
            raise CheckError("Requested release no longer matches authoritative identities.")
        status.update(current=current, available=release, update_available=True)
        snapshot = json.loads(commands.run("snapshot"))
        topology = json.loads(commands.run("topology_snapshot"))
        if snapshot.get("name") != config["compose_project"] or not set(SERVICES) <= set(snapshot.get("services", {})):
            raise CheckError("Unexpected Compose project/service configuration.")
        if any(snapshot['services'][s].get('image') != ('decor-office-web:local' if s == 'web' else 'decor-office-app:local') for s in SERVICES):
            raise CheckError("Unexpected production image aliases; operator review required.")
        # Retain exact existing volumes/networks/environment; only app/web images change.
        previous = json.loads(json.dumps(snapshot))
        for service in SERVICES:
            previous["services"][service].pop("build", None)
        containers = commands.run("containers")
        try:
            records = json.loads(containers)
            if isinstance(records, dict):
                records = [records]
        except ValueError:
            records = [json.loads(line) for line in containers.splitlines() if line.strip()]
        by_service = {r["Service"]: r for r in records}
        if any(s not in by_service or by_service[s].get("State") != "running" for s in SERVICES):
            raise CheckError("Expected application services are not running.")
        if by_service["app"].get("Name") != config["docker_app_container"]:
            raise CheckError("App container does not belong to the configured project.")
        # docker compose ps Image may be a mutable tag: inspect each immutable image ID.
        for service in SERVICES:
            record = by_service[service]
            if not re.fullmatch(r"[a-f0-9]{12,64}", record["ID"]):
                raise CheckError("Invalid container identity.")
            image = commands.previous_image(record["ID"])
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
                raise CheckError("Invalid previous image identity.")
            previous["services"][service]["image"] = image
        private_json(workspace / "previous-compose.json", previous)
        phase("backup")
        backup = json.loads(commands.run("backup"))
        if backup.get("verified") is not True or type(backup.get("backup_id")) is not int or backup["backup_id"] <= 0:
            raise CheckError("Mandatory verified backup failed.")
        operation["backup_reference"] = backup["backup_id"]
        phase("prepare_release")
        commands.run("fetch")
        if commands.run("resolve").lower() != request["target"]["commit"].lower():
            raise CheckError("Fetched release commit differs from requested commit.")
        commands.run("ancestor")
        commands.run("archive")
        source = workspace / "source"
        source.mkdir()
        safe_extract(workspace / "release.tar", source)

        release_policy = validate_release_contract(
            source / "deploy/release-contract.json",
            commands.run("migration_delta"),
        )
        private_json(
            workspace / "release-contract.json",
            release_policy["contract"],
        )
        migrations_required = release_policy["migrations_required"]

        # Resolve against approved production paths/environment, not staging paths.
        # env_file structure is separately retained rather than flattened away.
        try:
            release_snapshot = json.loads(commands.run("release_snapshot"))
            release_topology = json.loads(commands.run("release_topology"))
        except (CheckError, ValueError, TypeError):
            raise ComposeCompatibilityError("Target Compose requires operator review.") from None
        private_json(workspace / "release-compose.json", release_snapshot)
        private_json(workspace / "release-topology.json", release_topology)
        require_compose_compatibility(snapshot, release_snapshot)
        require_compose_compatibility(topology, release_topology)
        phase("build")
        commands.run("build_app")
        commands.run("build_web")
        target = json.loads(json.dumps(previous))
        for service in SERVICES:
            target["services"][service]["image"] = "tiraz-" + ("web" if service == "web" else "app") + ":" + request["target"]["commit"]
            if service != "web":
                target["services"][service].setdefault("environment", {})["APP_VERSION"] = request["target"]["version"]
        private_json(workspace / "target-compose.json", target)
        if commands.run("head") != head or commands.run("dirty"):
            raise CheckError("Repository changed during release preparation.")
        commands.run("ancestor")
        commands.run("forward")
        advanced = True
        maintenance = True
        commands.run("maintenance")
        commands.run("stop_workers")

        if migrations_required:
            phase("migration")
            mutation = True  # Even partial/failed migrations forbid automatic rollback.
            commands.run("migration")

        phase("deploy")
        commands.run("promote_app")
        commands.run("promote_web")
        commands.run("deploy")
        commands.run("clear")
        commands.run("up")
        phase("health_check")
        for _ in range(12):
            heartbeat("health_check")
            health_records = commands.run("containers")
            try:
                values = json.loads(health_records)
                if isinstance(values, dict):
                    values = [values]
            except ValueError:
                values = [json.loads(line) for line in health_records.splitlines() if line.strip()]
            running = {r["Service"] for r in values if r.get("State") == "running"}
            if set(SERVICES) <= running:
                break
            time.sleep(5)
        else:
            raise CheckError("Application services did not become healthy.")
        if identity(commands.run("identity")) != request["target"]:
            raise CheckError("Deployed OCI identity did not match the release.")
        commands.run("boot")
        if health_check is health:
            health_check(config["health_url"], heartbeat=heartbeat)
        else:
            heartbeat("health_check")
            health_check(config["health_url"])
        if commands.run("head") != request["target"]["commit"]:
            raise CheckError("Repository did not advance to deployed release.")
        phase("finalize")
        status.update(current=request["target"], update_available=False, last_error=None)
        status["agent"]["state"] = "idle"
        operation.update(state="completed", completed_at=stamp(), updated_at=stamp())
    except (CheckError, OSError, ValueError, KeyError, TypeError) as error:
        # Never surface raw command output, config URLs, paths or exception strings.
        status["agent"]["state"] = "error"
        status["last_error"] = ("Target Compose requires operator review." if isinstance(error, ComposeCompatibilityError)
                                else "Update failed; operator review required.")
        if status.get("operation"):
            failed = status["operation"]
            diagnostic = failed.get("activity") if failed.get("activity") in ("build_app", "build_web") else failed["phase"]
            error_code, safe_message = FAILURES[diagnostic]
            manual_intervention = mutation or advanced
            status["operation"].update(
                state="failed",
                updated_at=stamp(),
                message=safe_message,
                error_code=error_code,
                manual_intervention_required=manual_intervention,
            )
        if maintenance and not mutation and commands is not None:
            commands.heartbeat = None
            try:
                commands.run("up")
                commands.run("restore_workers")
            except CheckError:
                status["operation"]["manual_intervention_required"] = True
    status["checked_at"] = stamp()
    atomic_write(config["status_path"], status)
    if workspace is not None and workspace.is_dir():
        private_json(workspace / "result.json", status)
        archive_private_json(processing, workspace / "request.json", request)
    # Invalid requests remain in the protected processing location for manual review.
    return status

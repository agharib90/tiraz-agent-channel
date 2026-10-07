"""TIRAZ host agent: isolated release checks and validated request processing."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

VERSION = "0.2.0"
MAX_BYTES = 65536
MAX_OUTPUT = 4 * 1024 * 1024
GIT_EXECUTABLE = "/usr/bin/git"
DOCKER_EXECUTABLE = "/usr/bin/docker"
SEMVER = re.compile(
    r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z"
)
SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class CheckError(Exception):
    """Only constant, non-sensitive messages may cross the status boundary."""


def semver(value):
    if not isinstance(value, str) or len(value) > 200:
        return None
    match = SEMVER.fullmatch(value)
    if not match:
        return None
    pre = match[4].split(".") if match[4] else []
    if any(x.isdigit() and len(x) > 1 and x.startswith("0") for x in pre):
        return None
    # Numeric identifiers precede nonnumeric; release precedes no prerelease.
    return (tuple(int(match[i]) for i in (1, 2, 3)), not pre,
            tuple((0, int(x)) if x.isdigit() else (1, x) for x in pre))


def validate_config(data):
    required = {"schema_version", "repository_path", "remote", "channel",
                "status_path", "agent_version", "docker_app_container",
                "command_timeout_seconds"}
    execution = {"request_path", "lock_path", "release_temp_root", "health_url", "compose_project"}
    if not isinstance(data, dict) or (set(data) != required and set(data) != required | execution):
        raise CheckError("Invalid configuration fields.")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise CheckError("Unsupported configuration schema.")
    for key in ("repository_path", "status_path"):
        value = data[key]
        if (not isinstance(value, str) or len(value) > 4096
                or any(ord(c) < 32 for c in value) or not Path(value).is_absolute()
                or ".." in Path(value).parts):
            raise CheckError("Configuration paths must be absolute and normalized.")
    if Path(data["status_path"]).name != "status.json":
        raise CheckError("Status filename must be status.json.")
    if data["channel"] not in ("stable", "beta"):
        raise CheckError("Unsupported release channel.")
    for key in ("remote", "docker_app_container"):
        if not isinstance(data[key], str) or not IDENTIFIER.fullmatch(data[key]):
            raise CheckError("Invalid command identifier.")
    if not semver(data["agent_version"]):
        raise CheckError("Invalid agent version.")
    timeout = data["command_timeout_seconds"]
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise CheckError("Command timeout must be between 1 and 120 seconds.")
    if execution <= set(data):
        for key in ("request_path", "lock_path", "release_temp_root"):
            value = data[key]
            if (not isinstance(value, str) or not Path(value).is_absolute()
                    or ".." in Path(value).parts or any(ord(c) < 32 for c in value)):
                raise CheckError("Invalid execution path.")
        request_directory = Path(data["request_path"]).parent
        if (Path(data["request_path"]).name != "request.json"
                or not isinstance(data["compose_project"], str) or not IDENTIFIER.fullmatch(data["compose_project"])
                or request_directory == Path(data["status_path"]).parent
                or request_directory in Path(data["status_path"]).parents
                or request_directory in Path(data["lock_path"]).parents
                or request_directory in Path(data["release_temp_root"]).parents):
            raise CheckError("Invalid execution configuration.")
        if not isinstance(data["health_url"], str) or not re.fullmatch(r"http://127\.0\.0\.1(?::[1-9][0-9]{0,4})?/login", data["health_url"]):
            raise CheckError("Health URL must be local HTTP /login.")
        from urllib.parse import urlsplit
        try:
            urlsplit(data["health_url"]).port
        except ValueError:
            raise CheckError("Invalid local health port.") from None
    return dict(data)


def load_config(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError()
        return validate_config(json.loads(raw))
    except (OSError, ValueError, TypeError):
        raise CheckError("Cannot read valid configuration.") from None


class Commands:
    """Fixed operations only. Config cannot supply executable names or arguments."""
    def __init__(self, config):
        self.config = config
        self.heartbeat = None

    def run(self, operation):
        repo, remote = self.config["repository_path"], self.config["remote"]
        git = [GIT_EXECUTABLE, "-c", "core.fsmonitor=false",
               "-c", "credential.helper=", "-c", "core.askPass=",
               "-c", "core.hooksPath=/dev/null",
               "-c", "protocol.ext.allow=never", "-C", repo]
        commands = {
            "head": git + ["rev-parse", "HEAD"],
            "dirty": git + ["status", "--porcelain", "--untracked-files=no"],
            "remote": git + ["remote", "get-url", remote],
            "tags": git + ["ls-remote", "--tags", remote],
            "identity": [DOCKER_EXECUTABLE, "inspect", "--type", "container", "--format",
                         "{{json .Config.Labels}}", self.config["docker_app_container"]],
        }
        if operation not in commands:
            raise CheckError("Unsupported check operation.")
        return self._execute(commands[operation], operation, self.config["command_timeout_seconds"])

    def _execute(self, argv, operation, timeout, output_path=None):
        environment = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
        # Keep process output off the Python heap; only bounded stdout is read.
        # stderr is deliberately discarded, never copied into status or logs.
        try:
            with tempfile.TemporaryFile() as output:
                if self.heartbeat is None:
                    result = subprocess.run(argv, shell=False, stdin=subprocess.DEVNULL,
                                            stdout=output, stderr=subprocess.DEVNULL,
                                            env=environment, timeout=timeout, check=False)
                else:
                    self.heartbeat(operation)
                    child = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL,
                                             stdout=output, stderr=subprocess.DEVNULL, env=environment)
                    deadline = time.monotonic() + timeout
                    limit = 512 * 1024 * 1024 if output_path is not None else MAX_OUTPUT
                    try:
                        while child.poll() is None:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise subprocess.TimeoutExpired(operation, timeout)
                            try:
                                child.wait(timeout=min(5, remaining))
                            except subprocess.TimeoutExpired:
                                if os.fstat(output.fileno()).st_size > limit:
                                    raise CheckError("Check output exceeded safety limit.")
                                if time.monotonic() >= deadline:
                                    raise subprocess.TimeoutExpired(operation, timeout)
                                self.heartbeat(operation)
                        result = child
                    finally:
                        if child.poll() is None:
                            child.terminate()
                            try:
                                child.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                child.kill()
                                child.wait()
                if result.returncode:
                    raise CheckError("Check command failed: " + operation + ".")
                output.seek(0)
                if output_path is not None:
                    import shutil
                    if output.seek(0, 2) > 512 * 1024 * 1024:
                        raise CheckError("Release archive exceeded safety limit.")
                    output.seek(0)
                    with open(output_path, "xb") as destination:
                        shutil.copyfileobj(output, destination)
                    return ""
                raw = output.read(MAX_OUTPUT + 1)
                if len(raw) > MAX_OUTPUT:
                    raise CheckError("Check output exceeded safety limit.")
                return raw.decode("utf-8", errors="strict").strip()
        except subprocess.TimeoutExpired:
            raise CheckError("Check command timed out: " + operation + ".") from None
        except (OSError, UnicodeError):
            raise CheckError("Check command unavailable: " + operation + ".") from None


def latest_release(output, channel):
    refs = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 2 or not SHA.fullmatch(parts[0]):
            continue
        if parts[1].startswith("refs/tags/"):
            refs[parts[1][10:]] = parts[0].lower()
    releases = []
    for tag, commit in refs.items():
        version = semver(tag)
        if version is None or (channel == "stable" and not version[1]):
            continue
        releases.append((version, tag, refs.get(tag + "^{}", commit)))
    if not releases:
        raise CheckError("No valid releases found for the configured channel.")
    _, tag, commit = max(releases)
    return {"version": tag, "commit": commit, "published_at": None}


def identity(output):
    try:
        labels = json.loads(output)
        version = labels.get("org.opencontainers.image.version")
        revision = labels.get("org.opencontainers.image.revision")
        if not semver(version) or not isinstance(revision, str) or not SHA.fullmatch(revision):
            raise ValueError()
        return {"version": version, "commit": revision.lower()}
    except (ValueError, AttributeError, TypeError):
        raise CheckError("Running container release identity is missing or invalid.") from None


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def initial_status(config):
    return {"schema_version": 1, "checked_at": stamp(), "channel": config["channel"],
            "current": {"version": "unknown", "commit": "unknown"}, "available": None,
            "update_available": None, "release_notes": [],
            "agent": {"state": "checking", "version": VERSION},
            "last_error": "Release check has not completed."}


def previous_metadata(path, status):
    """Retain only validated release identifiers, not arbitrary old notes/errors."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return
        old = json.loads(raw)
        if old.get("schema_version") != 1 or old.get("channel") != status["channel"]:
            return
        if isinstance(old.get("operation"), dict):
            status["operation"] = old["operation"]
            if old["operation"].get("state") in ("queued", "running"):
                status["checked_at"] = old["checked_at"]
        current = old.get("current", {})
        if semver(current.get("version")) and SHA.fullmatch(str(current.get("commit", ""))):
            status["current"] = {"version": current["version"], "commit": current["commit"]}
        available = old.get("available", {}) or {}
        if semver(available.get("version")) and SHA.fullmatch(str(available.get("commit", ""))):
            status["available"] = {"version": available["version"],
                                   "commit": available["commit"], "published_at": None}
            status["update_available"] = old.get("update_available") is True
    except (OSError, ValueError, AttributeError, TypeError):
        pass


def atomic_write(path, status):
    data = (json.dumps(status, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_BYTES:
        raise CheckError("Status exceeded safety limit.")
    destination = Path(path)
    temporary = None
    try:
        # Directory must be provisioned by an administrator, not guessed/created.
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".status-",
                                         suffix=".tmp", delete=False) as handle:
            temporary = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    except OSError:
        raise CheckError("Cannot publish status atomically.") from None
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def check(config, commands=None):
    config = validate_config(config)
    commands = commands or Commands(config)
    status = initial_status(config)
    previous_metadata(config["status_path"], status)
    if (Path(config["status_path"]).parent / "processing.json").exists():
        return status
    if status.get("operation", {}).get("state") in ("queued", "running"):
        return status  # Do not refresh a crashed operation: U1.1 must make it stale.
    # Checking cannot claim an up-to-date result; retain useful metadata only.
    status["last_error"] = None
    atomic_write(config["status_path"], status)
    try:
        head = commands.run("head")
        if not SHA.fullmatch(head):
            raise CheckError("Invalid repository HEAD identity.")
        if commands.run("dirty"):
            raise CheckError("Tracked repository modifications require operator review.")
        remote = commands.run("remote")
        # Only SSH/scp-style or HTTPS remotes. Do not execute URL helper transports
        # or accept embedded HTTPS credentials; no remote URL crosses the boundary.
        if not (re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9_./-]+", remote)
                or re.fullmatch(r"[A-Za-z0-9_-]+@[A-Za-z0-9.-]+:[A-Za-z0-9_./-]+", remote)
                or re.fullmatch(r"ssh://[A-Za-z0-9_-]+@[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9_./-]+", remote)):
            raise CheckError("Remote must use credential-free HTTPS or operator-managed SSH.")
        # Never substitute repository HEAD for deployed-image identity.
        status["current"] = identity(commands.run("identity"))
        release = latest_release(commands.run("tags"), config["channel"])
        status["available"] = release
        status["update_available"] = release["commit"] != status["current"]["commit"]
        if status["update_available"] and semver(release["version"]) <= semver(status["current"]["version"]):
            raise CheckError("Release identity divergence requires operator review; no downgrade offered.")
        status["agent"]["state"] = "idle"
        status["last_error"] = None
        if status.get("operation", {}).get("state") == "failed":
            raise CheckError("Previous update failed; operator review required.")
    except CheckError as error:
        status["agent"]["state"] = "error"
        status["last_error"] = str(error)
    status["checked_at"] = stamp()
    atomic_write(config["status_path"], status)
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(description="TIRAZ host update agent")
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "validate-config", "process-request"):
        sub.add_parser(name).add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "validate-config":
            print("TIRAZ updater configuration valid.")
            return 0
        if "lock_path" in config:
            from tiraz_apply import HostLock, process_request
            with HostLock(config["lock_path"]):
                if args.command == "process-request":
                    with HostLock(str(Path(config["request_path"]).parent / ".request.lock")):
                        status = process_request(config)
                else:
                    status = check(config)
        elif args.command == "process-request":
            raise CheckError("Execution configuration is required.")
        else:
            status = check(config)
        print("TIRAZ release check: " + status["agent"]["state"])
        return 1 if status["last_error"] else 0
    except CheckError as error:
        print(str(error))
        return 1


if __name__ == "__main__":
    import sys
    # The execution module must share this exact CheckError/Commands definition.
    sys.modules["tiraz_updater"] = sys.modules[__name__]
    raise SystemExit(main())

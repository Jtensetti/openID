"""Strict local one-request IPC. Never transports key material or logs payloads."""
import json
import os
from pathlib import Path
import socket
import socketserver
import stat

MAX_MESSAGE = 131072


def _unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate IPC field")
        result[key] = value
    return result


def request(path, payload):
    message = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    if len(message) > MAX_MESSAGE:
        raise ValueError("IPC request size")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(12)
        connection.connect(str(path))
        connection.sendall(message)
        with connection.makefile("rb") as reader:
            response = reader.readline(MAX_MESSAGE + 1)
    if not response.endswith(b"\n") or len(response) > MAX_MESSAGE:
        raise ValueError("IPC response size")
    value = json.loads(response, object_pairs_hook=_unique)
    if not isinstance(value, dict) or value.get("ok") is not True or set(value) != {"ok", "result"}:
        raise ValueError("IPC request failed")
    return value["result"]


def _verify_parent(path, group):
    directory = Path(path).parent
    if directory.is_symlink():
        raise ValueError("IPC directory must not be a symlink")
    info = directory.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_gid != group or (info.st_mode & 0o777) != 0o710
            or not (info.st_mode & stat.S_ISGID)):
        raise ValueError("IPC directory must be owner-controlled mode 2710")


def _remove_stale(path):
    target = Path(path)
    try:
        st = target.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.getuid():
        raise ValueError("unexpected IPC endpoint")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        try:
            probe.connect(str(target))
        except ConnectionRefusedError:
            target.unlink()
        else:
            raise ValueError("IPC endpoint already active")


class LocalService(socketserver.UnixStreamServer):
    """One bounded JSON request per connection; socket group is explicit."""

    def __init__(self, path, group, dispatch):
        _verify_parent(path, group)
        _remove_stale(path)
        self.dispatch = dispatch
        self.path = str(path)
        owner = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(12)
                try:
                    raw = self.rfile.readline(MAX_MESSAGE + 1)
                    if not raw.endswith(b"\n") or len(raw) > MAX_MESSAGE:
                        raise ValueError("IPC input size")
                    payload = json.loads(raw, object_pairs_hook=_unique)
                    if not isinstance(payload, dict):
                        raise ValueError("IPC object required")
                    result = owner.dispatch(payload)
                    encoded = json.dumps({"ok": True, "result": result}, separators=(",", ":")).encode() + b"\n"
                    if len(encoded) > MAX_MESSAGE:
                        raise ValueError("IPC output size")
                    self.wfile.write(encoded)
                except Exception:
                    try:
                        self.wfile.write(b'{"ok":false}\n')
                    except OSError:
                        pass

        super().__init__(str(path), Handler)
        os.chmod(path, 0o660)
        st = Path(path).stat()
        if st.st_gid != group or st.st_uid != os.getuid():
            self.server_close()
            Path(path).unlink(missing_ok=True)
            raise ValueError("IPC socket ownership")

    def close(self):
        self.shutdown()
        self.server_close()
        Path(self.path).unlink(missing_ok=True)

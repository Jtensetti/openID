"""Fail-closed deployment attestation for the beta-112 isolated server.

Only reads Compose JSON or Docker metadata. Never reads wallets or keys.
"""
import argparse
import json
import re
import subprocess
import sys

SERVICE_MOUNTS = {
    "vault": {"keys": True, "vault-ipc": False},
    "verifier": {"runtime.json": True, "secrets": True, "data": False,
                 "vault-ipc": True, "continuity.json": True},
    "bridge": {"data": False, "origins.json": True, "continuity.json": True,
               "federation-ipc": False, "notice-ipc": False, "vault-ipc": True},
    "idp": {"federation": False, "federation-ipc": True, "origins.json": True},
    "sp": {"federation": True, "federation-ipc": True, "origins.json": True},
    "notice-exporter": {"notice-ipc": True},
}
USERS = {"vault": "10005:20002", "verifier": "10001:20002",
         "bridge": "10001:20001", "idp": "10002:20001",
         "sp": "10003:20001", "notice-exporter": "10004:20003"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def mounts_for(name):
    return {"/srv/openid/" + key: ro for key, ro in SERVICE_MOUNTS[name].items()}


def validate_service(name, image, user, groups, readonly_root, mounts, tmpfs, image_id):
    require(image == image_id, "unverified service image")
    require(user == USERS[name], "unexpected service user")
    expected_groups = ["20002", "20003"] if name == "bridge" else []
    require([str(x) for x in groups or []] == expected_groups, "unexpected supplementary groups")
    require(readonly_root is True, "service filesystem must be read-only")
    require(len(mounts) == len(mounts_for(name)) and dict(mounts) == mounts_for(name),
            "unexpected bind mount or wallet exposure")
    require(set(tmpfs) <= {"/tmp"}, "unexpected tmpfs")


def validate_compose(config, image_id):
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", image_id), "pinned image ID required")
    services = config.get("services", {})
    require(set(services) == set(SERVICE_MOUNTS), "wrong service set")
    for name, entry in services.items():
        require("build" not in entry and not any(entry.get(k) for k in ("configs","secrets","volumes_from")),
                "unapproved runtime overlay")
        volumes = entry.get("volumes", [])
        require(all(v.get("type") == "bind" for v in volumes), "only bind mounts allowed")
        validate_service(name, entry.get("image"), entry.get("user"), entry.get("group_add", []),
                         entry.get("read_only"),
                         [(v.get("target"), v.get("read_only", False)) for v in volumes],
                         [v.split(":",1)[0] for v in entry.get("tmpfs", [])], image_id)
    return True


def validate_running(containers, image_id):
    require(len(containers) == len(SERVICE_MOUNTS), "wrong number of beta containers")
    names = [c.get("Config",{}).get("Labels",{}).get("com.docker.compose.service") for c in containers]
    require(set(names) == set(SERVICE_MOUNTS), "missing or extra beta container")
    for c,name in zip(containers, names):
        require(c["State"].get("Running") and c["Image"] == image_id
                and c["Config"].get("Image") == image_id, "missing or drifting beta image")
        host = c.get("HostConfig",{})
        volumes = c.get("Mounts",[])
        require(all(v.get("Type") == "bind" for v in volumes), "unapproved Docker volume")
        validate_service(name, c["Image"], c["Config"].get("User"), host.get("GroupAdd", []),
                         host.get("ReadonlyRootfs"),
                         [(v.get("Destination"),not v.get("RW")) for v in volumes],
                         host.get("Tmpfs",{}).keys(), image_id)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["compose","running"])
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    if args.mode == "compose":
        validate_compose(json.load(sys.stdin), args.image_id)
    else:
        ids = subprocess.check_output(["docker","ps","--all","--filter",
              "label=com.docker.compose.project=openid-beta","--format","{{.ID}}"], text=True).splitlines()
        require(ids, "beta project not present")
        containers = json.loads(subprocess.check_output(["docker","inspect",*ids], text=True))
        validate_running(containers, args.image_id)
    print("Beta-112 isolation and image boundaries verified; no data accessed")


if __name__ == "__main__":
    main()

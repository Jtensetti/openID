"""No-personal-data regression checks for the beta-112 release boundary."""
from copy import deepcopy
import unittest

import check_beta112 as guard

IMAGE = "sha256:" + "a"*64


def compose():
    services = {}
    for name in guard.SERVICE_MOUNTS:
        services[name] = {
            "image": IMAGE,
            "user": guard.USERS[name],
            "group_add": ["20002", "20003"] if name == "bridge" else [],
            "read_only": True,
            "tmpfs": ["/tmp:size=32m"],
            "volumes": [
                {"type":"bind", "source":"/isolated/" + target, "target":"/srv/openid/" + target,
                 "read_only": readonly}
                for target,readonly in guard.SERVICE_MOUNTS[name].items()
            ]
        }
    return {"services": services}


class Beta112SecurityBoundary(unittest.TestCase):
    def test_correct_compose(self):
        self.assertTrue(guard.validate_compose(compose(), IMAGE))

    def test_no_identity_access_for_idp_sp_notice(self):
        for service in ("idp", "sp", "notice-exporter"):
            for forbidden in ("data", "keys"):
                with self.subTest(service=service, forbidden=forbidden):
                    c = compose()
                    c["services"][service]["volumes"].append(
                        {"type":"bind", "source":"/some/private",
                         "target":"/srv/openid/" + forbidden, "read_only":True})
                    with self.assertRaises(ValueError):
                        guard.validate_compose(c, IMAGE)

    def test_lateral_movement_fails_closed(self):
        for service in ("verifier", "bridge", "idp", "sp", "notice-exporter", "vault"):
            with self.subTest(service=service):
                c = compose()
                c["services"][service]["user"] = "10001:10001"
                if guard.USERS[service] == "10001:10001":
                    continue
                with self.assertRaises(ValueError):
                    guard.validate_compose(c, IMAGE)

    def test_unverified_image_and_code_overlays_fail(self):
        c = compose()
        c["services"]["bridge"]["volumes"].append(
            {"type":"bind","source":"/tmp/evil.py",
             "target":"/app/verification/federation.py","read_only":True})
        with self.assertRaises(ValueError):
            guard.validate_compose(c, IMAGE)
        c = compose()
        c["services"]["bridge"]["image"] = "openid-pilot:beta"
        with self.assertRaises(ValueError):
            guard.validate_compose(c, IMAGE)

    def test_runtime_mount_drift_is_rejected(self):
        c=compose()
        running=[]
        for name,item in c["services"].items():
            running.append({
                "Config":{"Labels":{"com.docker.compose.service":name},
                          "Image":IMAGE,"User":item["user"]},
                "Image":IMAGE,"State":{"Running":True},
                "HostConfig":{"ReadonlyRootfs":True, "Tmpfs":{"/tmp":"size=32m"},
                              "GroupAdd":item["group_add"]},
                "Mounts":[{"Type":"bind","Destination":v["target"],
                           "RW":not v["read_only"]} for v in item["volumes"]]})
        self.assertTrue(guard.validate_running(running, IMAGE))
        modified=deepcopy(running)
        modified[3]["Mounts"].append({"Type":"bind","Destination":"/srv/openid/data","RW":False})
        with self.assertRaises(ValueError):
            guard.validate_running(modified, IMAGE)


if __name__ == "__main__":
    unittest.main()

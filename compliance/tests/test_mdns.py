# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import configparser
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "script/lib"))

import build_assets  # noqa: E402


class MdnsPackagingTests(unittest.TestCase):
    def test_guest_has_supervised_usb_only_address_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owners: dict[str, str] = {}
            services = root / "etc/avahi/services"
            services.mkdir(parents=True)
            sample = services / "ssh.service"
            sample.write_text("stock SSH advertisement")
            owners["etc/avahi/services/ssh.service"] = "avahi"
            build_assets.install_project_files(root, owners)

            script = root / "usr/local/sbin/init-mdns"
            self.assertEqual(script.read_bytes(), (ROOT / "script/initramfs/init-mdns").read_bytes())
            self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o755)
            self.assertEqual(owners["usr/local/sbin/init-mdns"], "project")
            inittab = (root / "etc/inittab").read_text().splitlines()
            self.assertEqual(inittab.count("::respawn:/usr/local/sbin/init-mdns"), 1)
            self.assertLess(inittab.index("::wait:/usr/local/sbin/init-network"),
                            inittab.index("::respawn:/usr/local/sbin/init-mdns"))
            self.assertIn("::wait:/usr/local/sbin/init-rndis", inittab)
            self.assertIn("::respawn:/usr/local/sbin/usb0-watcher", inittab)

            config = configparser.ConfigParser()
            config.read(root / "etc/avahi/avahi-daemon.conf")
            self.assertEqual(config["server"]["host-name"], "thrurndis")
            self.assertEqual(config["server"]["domain-name"], "local")
            self.assertEqual(config["server"]["allow-interfaces"], "usb0")
            self.assertTrue(config.getboolean("server", "use-ipv4"))
            self.assertTrue(config.getboolean("server", "use-iff-running"))
            self.assertFalse(config.getboolean("server", "use-ipv6"))
            self.assertFalse(config.getboolean("server", "enable-dbus"))
            self.assertFalse(config.getboolean("wide-area", "enable-wide-area"))
            self.assertFalse(config.getboolean("reflector", "enable-reflector"))
            self.assertTrue(config.getboolean("publish", "publish-addresses"))
            for key in ("publish-aaaa-on-ipv4", "publish-resolv-conf-dns-servers",
                        "publish-workstation", "publish-hinfo", "publish-domain"):
                self.assertFalse(config.getboolean("publish", key))
            self.assertEqual(list(services.iterdir()), [])
            self.assertNotIn("etc/avahi/services/ssh.service", owners)
            self.assertEqual((root / "etc/avahi/hosts").read_bytes(), b"")
            self.assertEqual((root / "etc/resolv.conf").read_bytes(), b"")
            self.assertEqual((root / "var/run").readlink(), Path("/run"))

            # The APK pre-install is never run. The normal daemon privilege
            # drop must still work and its system account must remain locked.
            accounts = {line.split(":")[0]: line.split(":") for line in
                        (root / "etc/passwd").read_text().splitlines()}
            self.assertEqual(accounts["avahi"][2:4], ["86", "86"])
            self.assertEqual(accounts["avahi"][-1], "/sbin/nologin")
            self.assertIn("avahi:x:86:", (root / "etc/group").read_text())
            self.assertIn("avahi:!:", (root / "etc/shadow").read_text())
            self.assertEqual(stat.S_IMODE((root / "etc/shadow").stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()

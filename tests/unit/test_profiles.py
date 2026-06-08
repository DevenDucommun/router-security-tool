"""Tests for device-specific security profiles."""

import pytest
from unittest.mock import MagicMock

from assessment.profiles import detect_profile, OpenWrtProfile, LinksysProfile, CiscoIOSProfile
from assessment.profiles.base import DeviceProfile


class TestProfileDetection:
    def test_detects_openwrt(self):
        device_info = {
            "uname": "Linux router 5.10.0 armv7l GNU/Linux",
            "firmware_version": "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='23.05'",
        }
        result = detect_profile(device_info)
        assert result == OpenWrtProfile

    def test_detects_linksys_by_hostname(self):
        device_info = {
            "uname": "Linux Community00099 5.4.213 armv7l",
            "hostname": "Community00099",
            "firmware_version": "DISTRIB_ID='OpenWrt'",
        }
        result = detect_profile(device_info)
        assert result == LinksysProfile

    def test_detects_cisco(self):
        device_info = {
            "uname": "Cisco IOS Software, Version 15.7",
            "hostname": "cisco-router-01",
        }
        result = detect_profile(device_info)
        assert result == CiscoIOSProfile

    def test_no_match_returns_none(self):
        device_info = {"uname": "FreeBSD generic 13.0", "hostname": "mybox"}
        result = detect_profile(device_info)
        assert result is None

    def test_linksys_takes_priority_over_openwrt(self):
        """Linksys runs OpenWrt but should match Linksys profile (more specific)."""
        device_info = {
            "uname": "Linux Community00099 5.4.213 armv7l",
            "hostname": "Community00099",
            "firmware_version": "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='23.05-SNAPSHOT'",
        }
        result = detect_profile(device_info)
        assert result == LinksysProfile


class TestOpenWrtProfile:
    @pytest.fixture
    def profile(self):
        device_info = {
            "uname": "Linux router 5.10.0 armv7l",
            "firmware_version": "DISTRIB_ID='OpenWrt'",
        }
        cmd = MagicMock(return_value="")
        return OpenWrtProfile(cmd, device_info)

    def test_matches_openwrt(self):
        score = OpenWrtProfile.matches({"firmware_version": "DISTRIB_ID='OpenWrt'"})
        assert score >= 0.9

    def test_no_match_generic_linux(self):
        score = OpenWrtProfile.matches({"uname": "Linux server 5.15.0 x86_64"})
        assert score < 0.5

    def test_check_firewall_zones_missing(self, profile):
        profile._cmd.return_value = ""
        profile._check_firewall_zones()
        ids = [f.check_id for f in profile.findings]
        assert "OWRT-FW-001" in ids

    def test_check_firewall_wan_accept(self, profile):
        profile._cmd.return_value = (
            "firewall.@zone[0].name='lan'\n"
            "firewall.@zone[1].name='wan'\n"
            "firewall.@zone[1].input='ACCEPT'\n"
        )
        profile._check_firewall_zones()
        ids = [f.check_id for f in profile.findings]
        assert "OWRT-FW-002" in ids

    def test_check_luci_all_interfaces(self, profile):
        profile._cmd.return_value = "uhttpd.main.listen_http='0.0.0.0:80'\nuhttpd.main.listen_https='0.0.0.0:443'"
        profile._check_luci_exposure()
        ids = [f.check_id for f in profile.findings]
        assert "OWRT-WEB-001" in ids
        assert "OWRT-WEB-002" in ids

    def test_check_wireless_open_network(self, profile):
        profile._cmd.return_value = "wireless.wifinet0.encryption='none'\n"
        profile._check_wireless_config()
        ids = [f.check_id for f in profile.findings]
        assert "OWRT-WIFI-001" in ids

    def test_check_wireless_weak_encryption(self, profile):
        profile._cmd.return_value = "wireless.wifinet0.encryption='psk'\n"
        profile._check_wireless_config()
        ids = [f.check_id for f in profile.findings]
        assert "OWRT-WIFI-002" in ids

    def test_check_dns_rebinding_disabled(self, profile):
        profile._cmd.return_value = "dhcp.@dnsmasq[0].rebind_protection='0'\n"
        profile._check_dhcp_dns()
        ids = [f.check_id for f in profile.findings]
        assert "OWRT-DNS-001" in ids

    def test_check_packages_telnet(self, profile):
        profile._cmd.return_value = "base-files - 1.0\ntelnetd - 2.0\nbusybox - 1.36"
        profile._check_packages()
        ids = [f.check_id for f in profile.findings]
        assert "OWRT-NET-TEL" in ids

    def test_run_checks_returns_findings(self, profile):
        profile._cmd.return_value = ""
        results = profile.run_checks()
        assert isinstance(results, list)


class TestLinksysProfile:
    @pytest.fixture
    def profile(self):
        device_info = {
            "uname": "Linux Community00099 5.4.213 armv7l",
            "hostname": "Community00099",
            "firmware_version": "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='23.05-SNAPSHOT'",
        }
        cmd = MagicMock(return_value="")
        return LinksysProfile(cmd, device_info)

    def test_matches_community_hostname(self):
        score = LinksysProfile.matches({"hostname": "Community00099", "uname": ""})
        assert score >= 0.8

    def test_matches_linksys_firmware(self):
        score = LinksysProfile.matches({"firmware_version": "Linksys WRT3200ACM"})
        assert score >= 0.9

    def test_check_jnap_noauth(self, profile):
        profile._cmd.side_effect = lambda cmd: {
            "ps | grep -i jnap 2>/dev/null": "1234 root jnapd",
        }.get(cmd, "noauth=true" if "syscfg" in cmd else "")
        profile._check_jnap_api()
        ids = [f.check_id for f in profile.findings]
        assert "LNK-JNAP-002" in ids

    def test_check_firmware_old_build(self, profile):
        profile.device_info["uname"] = "Linux Community00099 5.4.213 #0 SMP PREEMPT Jan 15 10:00:00 2022 armv7l"
        profile._check_firmware_version()
        ids = [f.check_id for f in profile.findings]
        assert "LNK-FW-003" in ids

    def test_check_syscfg_world_readable(self, profile):
        def cmd_handler(cmd):
            if "ls /tmp/syscfg" in cmd:
                return "syscfg.dat\nwifi.dat"
            if "stat" in cmd:
                return "777"
            if "grep" in cmd:
                return "passphrase=mysecret"
            return ""
        profile._cmd.side_effect = cmd_handler
        profile._check_syscfg_exposure()
        ids = [f.check_id for f in profile.findings]
        assert "LNK-CFG-001" in ids
        assert "LNK-CFG-002" in ids

    def test_check_default_ssid(self, profile):
        profile._cmd.return_value = "Linksys_Setup_5G"
        profile._check_default_patterns()
        ids = [f.check_id for f in profile.findings]
        assert "LNK-DEF-001" in ids

    def test_run_checks_returns_findings(self, profile):
        profile._cmd.return_value = ""
        results = profile.run_checks()
        assert isinstance(results, list)


class TestCiscoIOSProfile:
    @pytest.fixture
    def profile(self):
        device_info = {
            "uname": "Cisco IOS Software, Version 15.7(3)M",
            "hostname": "cisco-rtr-01",
        }
        cmd = MagicMock(return_value="")
        return CiscoIOSProfile(cmd, device_info)

    def test_matches_ios(self):
        score = CiscoIOSProfile.matches({"os_release": "Cisco IOS", "uname": ""})
        assert score >= 0.9

    def test_no_match_linux(self):
        score = CiscoIOSProfile.matches({"uname": "Linux server", "os_release": "Ubuntu"})
        assert score < 0.5

    def test_check_enable_password(self, profile):
        profile._cmd.return_value = "!\nenable password cisco123\n!\nhostname rtr"
        profile._check_running_config()
        ids = [f.check_id for f in profile.findings]
        assert "CISCO-AUTH-001" in ids

    def test_check_plaintext_username(self, profile):
        profile._cmd.return_value = "!\nusername admin password 0 cisco\n!"
        profile._check_running_config()
        ids = [f.check_id for f in profile.findings]
        assert "CISCO-AUTH-002" in ids

    def test_check_vty_no_acl(self, profile):
        profile._cmd.return_value = "!\nline vty 0 4\n transport input ssh\n login local\n!"
        profile._check_vty_lines()
        ids = [f.check_id for f in profile.findings]
        assert "CISCO-VTY-001" in ids

    def test_check_vty_telnet(self, profile):
        profile._cmd.return_value = "!\nline vty 0 4\n transport input telnet\n access-class 10 in\n!"
        profile._check_vty_lines()
        ids = [f.check_id for f in profile.findings]
        assert "CISCO-VTY-002" in ids

    def test_check_snmp_default_community(self, profile):
        profile._cmd.return_value = "!\nsnmp-server community public RO\nsnmp-server community private RW\n!"
        profile._check_snmp()
        ids = [f.check_id for f in profile.findings]
        assert "CISCO-SNMP-001" in ids
        assert "CISCO-SNMP-002" in ids

    def test_check_services_http(self, profile):
        profile._cmd.return_value = "!\nip http server\nip source-route\n!"
        profile._check_services()
        ids = [f.check_id for f in profile.findings]
        assert "CISCO-SVC-001" in ids
        assert "CISCO-SVC-005" in ids

    def test_check_no_aaa(self, profile):
        profile._cmd.return_value = "!\nhostname router\n!"
        profile._check_aaa()
        ids = [f.check_id for f in profile.findings]
        assert "CISCO-AAA-001" in ids

    def test_check_no_remote_logging(self, profile):
        profile._cmd.return_value = "!\nlogging buffered 8192\n!"
        profile._check_logging()
        ids = [f.check_id for f in profile.findings]
        assert "CISCO-LOG-001" in ids

    def test_run_checks_returns_findings(self, profile):
        profile._cmd.return_value = ""
        results = profile.run_checks()
        assert isinstance(results, list)


class TestProfileIntegration:
    """Test that profiles integrate correctly with the assessor flow."""

    def test_profile_findings_have_correct_structure(self):
        device_info = {"firmware_version": "DISTRIB_ID='OpenWrt'"}
        cmd = MagicMock(return_value="")
        profile = OpenWrtProfile(cmd, device_info)
        profile.run_checks()

        for finding in profile.findings:
            d = finding.to_dict()
            assert "id" in d
            assert "title" in d
            assert "severity" in d
            assert d["severity"] in ("Critical", "High", "Medium", "Low", "Info")

    def test_progress_callback_receives_profile_prefix(self):
        device_info = {"firmware_version": "DISTRIB_ID='OpenWrt'"}
        cmd = MagicMock(return_value="")
        profile = OpenWrtProfile(cmd, device_info)
        messages = []
        profile.run_checks(progress_callback=messages.append)
        assert any("[openwrt]" in m for m in messages)
